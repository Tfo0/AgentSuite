"""SDK 驱动引擎:drive_with_resume 驱动 loop + 连接中断 resume 续跑 + CLI 子进程树清理。

agent 运行层(BaseRunner._drive)调 drive_with_resume 驱动 ClaudeSDKClient;
连接中断 mid-response 且无结论时用 session_id resume 续跑(不重读流量,只补提交结论);
每轮 async-with 退出前 cleanup_sdk_subprocess 杀整棵 CLI 子进程树防泄漏(Windows 不 reparent)。
"""
from __future__ import annotations

import asyncio
from typing import Any

from claude_agent_sdk import ClaudeSDKClient, ResultMessage

# 总尝试 = 1 + 此值;连接中断通常瞬时 resume 一发即成,连续失败到上限认 inconclusive(不再耗串行锁)。
MAX_RESUME_RETRIES = 2

# resume 续跑不重读流量(转录里有),只补提交结论:dispatch→dispatch_send / verify→verify_report / report→Write。
DEFAULT_RESUME_PROMPT = (
    "刚才 API 连接中断 mid-response,你之前 traffic_get / 原生 Read 的分析"
    "结果都还在会话记忆里,无需重读。现在请直接把刚才没提交完的结论提交掉"
    "(dispatch:继续调 dispatch_send 分发未覆盖的单元;verify:调 verify_report 提交结论;report:继续 Write 撰写未完成的 .md 报告),"
    "基于已分析的流量即可。"
)


# ---- CLI 子进程树清理(防 SDK 子进程泄漏;Windows 不 reparent,根先死→子孙孤儿化)----

def _grab_cli_pid(client: Any) -> int | None:
    """从 SDK client 私有属性掏 CLI 子进程 PID(SDK 升级改名则返 None,退回不杀靠 watchdog 自退)。"""
    try:
        transport = getattr(client, "_transport", None)
        proc = getattr(transport, "_process", None)
        return getattr(proc, "pid", None) if proc else None
    except Exception:
        return None


def kill_process_tree(root_pid: int | None) -> None:
    """递归杀进程树(best-effort,kill 不 wait 不阻塞 loop)。先杀子孙再杀根——Windows 不 reparent,根先死→子孙孤儿化。无 psutil 退回不杀。"""
    if not root_pid:
        return
    try:
        import psutil
    except ImportError:
        return
    try:
        root = psutil.Process(root_pid)
    except Exception:
        return  # CLI 已退,孙进程靠 stdio-EOF/watchdog 自退
    for child in root.children(recursive=True):
        try:
            child.kill()
        except Exception:
            pass
    try:
        root.kill()
    except Exception:
        pass


def cleanup_sdk_subprocess(client: Any) -> None:
    """async-with 块 finally 调:抓 CLI PID + 杀整树。须在 disconnect 之前(CLI 活着、子孙挂树上,psutil 才抓全)。"""
    kill_process_tree(_grab_cli_pid(client))


# ---- SDK 消息提取 + 连接中断判别 ----

def _extract_text(message: Any) -> str:
    content = getattr(message, "content", None)
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    parts = []
    for block in content:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


def render_sdk_message(emit, message) -> None:
    """on_message 占位 seam(有意静默):tool_use/文本/stop_reason 非人读逐条刷屏是噪音,进度由 stage emit 给;中断检测走 _drive_once 累积文本不经这里。"""


def is_connection_abort(result_msg: ResultMessage | None, text: str) -> bool:
    """API 连接中断判别(无结论提前结束)。主信号:文本含 'Connection closed mid-response'(is_error 不置——走 is_error 的已 ProcessError 抛到 runner 到不了这);兜底看 is_error/errors。"""
    t = text or ""
    if "Connection closed mid-response" in t or "API Error: Connection" in t:
        return True
    if result_msg is not None:
        if getattr(result_msg, "is_error", None):
            return True
        errs = getattr(result_msg, "errors", None) or []
        low = " ".join(str(e) for e in errs).lower()
        if "connection" in low or "closed" in low or "mid-response" in low:
            return True
    return False


# ---- 驱动 loop ----

async def _drive_once(options, prompt: str, on_message, *, timeout: int | None,
                      emit, tag: str) -> tuple[str, Any, ResultMessage | None]:
    """单次驱动 SDK,返 (文本, structured, 最后 ResultMessage)。比原版多捕 ResultMessage(给 drive_with_resume 判中断+拿 session_id resume);异常不吞原样抛 runner。"""
    chunks: list[str] = []
    structured: Any = None
    result_msg: ResultMessage | None = None

    async def _run():
        nonlocal structured, result_msg
        async with ClaudeSDKClient(options=options) as client:
            try:
                await client.query(prompt)
                async for message in client.receive_response():
                    if on_message is not None:
                        try:
                            on_message(message)
                        except Exception:
                            pass
                    t = _extract_text(message)
                    if t:
                        chunks.append(t)
                    if isinstance(message, ResultMessage):
                        if message.structured_output is not None:
                            structured = message.structured_output
                        result_msg = message
            finally:
                cleanup_sdk_subprocess(client)  # disconnect 前杀整树,防孙进程泄漏

    if timeout is None:
        await _run()
    else:
        try:
            await asyncio.wait_for(_run(), timeout=timeout)
        except asyncio.TimeoutError:
            emit(f"[超时] {tag} 会话超 {timeout}s 强制结束")
    return "\n".join(chunks), structured, result_msg


async def drive_with_resume(*, build_options_fn, prompt: str, resume_prompt: str,
                            on_message, emit, tag: str,
                            max_retries: int = MAX_RESUME_RETRIES) -> tuple[str, Any, object]:
    """驱动 SDK loop,连接中断+无结论时 resume 重试。返 (文本, structured, state)。

    收工:下了结论(state.findings/dispatched 非空)或非连接中断(干净 stop/超时/异常);只有「中断+无结论」才 resume。
    resume 传上次 session_id 开新 client(MCP state 每 client 内存,转录记旧 tool 结果不丢,续跑只补提交结论)。
    全败→空 state→runner 走 inconclusive。
    """
    text = ""
    structured: Any = None
    state: object = None
    resume_id: str | None = None
    for attempt in range(max_retries + 1):
        options, state, eff_timeout = build_options_fn(resume_id=resume_id)
        cur_prompt = prompt if attempt == 0 else resume_prompt
        cur_text, structured, result_msg = await _drive_once(
            options, cur_prompt, on_message, timeout=eff_timeout, emit=emit, tag=tag,
        )
        text = f"{text}\n{cur_text}" if text else cur_text
        has_report = bool(getattr(state, "findings", None)) or bool(
            getattr(state, "dispatched", None))
        if has_report or not is_connection_abort(result_msg, cur_text):
            break
        resume_id = getattr(result_msg, "session_id", None) if result_msg is not None else None
        if resume_id and attempt < max_retries:
            emit(f"[{tag}] API 连接中断 mid-response,resume {resume_id} 重试 "
                 f"({attempt + 1}/{max_retries})")
            continue
        break  # 没 session_id 或重试耗尽
    return text, structured, state
