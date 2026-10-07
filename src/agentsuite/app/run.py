"""as run:单终端一条龙——起 mitm 录制 → 用户按回车停 → 跑审计(dispatch→verify→
report)→ 出 report/ 下交付报告 .md。无 Ctrl+C、无第二终端、单命令一条龙。

session-based(0→1):无全局 DB。`as run -u <url>` 直接落
project/sessions/<ts>-<host>/ 当 session_dir(仓库内,.gitignore 已 ignore,
不沾用户 C 盘),init 不需要(pipeline/agent/findings.jsonl/
traffic.sqlite 都 CREATE IF NOT EXISTS,按 session_dir 分区)。

流程:
1. 起 mitmproxy 代理(纯被动,浏览器挂 --proxy-server 指向它 + 装 CA 过 HTTPS)
2. 用户在浏览器手动操作录流量;终端实时打 [stage] 进度
3. 用户回终端按回车 → set stop_event → record 收尾 dump + build_clean
4. run_pipeline 接着跑 dispatch→verify→report(同 session_dir,流式)
5. print findings 概览 + report 阶段写 report/ 下交付报告 .md → 退出

按回车停的实现:input() 同步阻塞读 stdin,不能在 asyncio loop 主线程跑(卡 loop)。
daemon 线程跑 input() + threading.Event,asyncio 轮询 flag → set stop_event。daemon
线程进程退出强杀(不归 asyncio executor 管,否则 shutdown_default_executor 死等)。

state 文件(project/active_run.json)记 session/mode;启动查陈旧(上次未完)给
警告,跑完 clear。

用法:
    as run -u https://example.com/login
    as run -f targets.jsonl
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import threading
import ctypes
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from agentsuite.config import settings
from agentsuite.pipeline.runner import DEFAULT_CONFIG, DEFAULT_STAGES


# Windows: 开 ENABLE_VIRTUAL_TERMINAL_PROCESSING 让 ANSI 颜色码生效(MinTTY/非 Win 自动跳过)。
def _enable_vt() -> None:
    if sys.platform != "win32":
        return
    try:
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x4)
    except Exception:
        pass


_enable_vt()

_ANSI = {
    "reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "cyan": "\033[36m", "gray": "\033[90m",
}


def _color_for(msg: str) -> str:
    """按内容挑颜色:verdict 红/黄/灰,启动蓝,进度绿,异常红,默认青。"""
    m = msg.lower()
    if "异常" in msg or "失败" in msg or "error" in m or "failed" in m:
        return _ANSI["red"]
    if "confirmed" in m:
        return _ANSI["bold"] + _ANSI["red"]
    if "rejected" in m:
        return _ANSI["yellow"]
    if "inconclusive" in m:
        return _ANSI["dim"]
    if "agent启动" in msg:
        return _ANSI["blue"]
    if "批 " in msg or "单元 " in msg or "done stop_reason" in m:
        return _ANSI["green"]
    return _ANSI["cyan"]


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "run",
        help="录 mitm 流量 + 跑审计一条龙(按回车停录制 → dispatch→verify→report → 报告)")
    inp = parser.add_argument_group("输入(--url 或 --file 二选一)")
    inp.add_argument("-u", "--url", action="append", default=[], metavar="URL",
                     help="目标 url(可多次给);首个是录制入口页(人手自己开,后端不导航)")
    inp.add_argument("-f", "--file", metavar="JSONL",
                     help="jsonl 文件(每行 {url, note})")
    inp.add_argument("--note", default="", help="给 --url 的备注(整批共用)")
    parser.set_defaults(command_handler=_handler)


def _handler(args: argparse.Namespace) -> int:
    try:
        return asyncio.run(_run_async(args))
    except KeyboardInterrupt:
        # 兜底:异常情况(用户强制 Ctrl+C / 窗口关)。正常流程按回车停,不走此。
        return 0


def _build_input(args: argparse.Namespace) -> str | None:
    if args.file:
        p = Path(args.file)
        if not p.is_file():
            print(f"输入文件不存在:{p}", file=sys.stderr)
            return None
        return p.read_text(encoding="utf-8")
    if not args.url:
        print("须给 --url 或 --file", file=sys.stderr)
        return None
    lines: list[str] = []
    for u in args.url:
        obj: dict = {"url": u.strip()}
        if args.note:
            obj["note"] = args.note
        lines.append(json.dumps(obj, ensure_ascii=False))
    return "\n".join(lines)


def _domain_of(urls: list[str]) -> str:
    for u in urls:
        host = urlsplit(u).hostname
        if host:
            return host
    return ""


def _parse_input(jsonl_text: str) -> tuple[list[dict], str]:
    """校验每行合法 json 对象(给 --file 模式校验)。返 (rows, error)。不落盘——
    record 只用首行 url,直接经 RunContext.url 传,不再写 input.jsonl。"""
    lines = [l.strip() for l in jsonl_text.splitlines() if l.strip()]
    rows: list[dict] = []
    for i, ln in enumerate(lines, 1):
        try:
            obj = json.loads(ln)
            if not isinstance(obj, dict):
                raise ValueError("非 json 对象")
            rows.append(obj)
        except (json.JSONDecodeError, ValueError) as exc:
            return [], f"第 {i} 行不是合法 jsonl:{exc}"
    return rows, ""


def _new_session_dir(host: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_host = host or "target"
    # session 落仓库下 project/sessions/(.gitignore 已 ignore,不沾用户 C 盘)。
    return settings.project_path / "sessions" / f"{ts}-{safe_host}"


def _start_enter_watcher(stop_event: asyncio.Event) -> asyncio.Task:
    """起 daemon 线程等用户按回车,触发 asyncio stop_event。

    input() 同步阻塞读 stdin,不能在 asyncio loop 主线程跑(卡 loop)。daemon 线程
    跑 input() + threading.Event,asyncio 轮询 flag → set stop_event。daemon 线程
    进程退出强杀(若用户没按回车而审计超时完成)。不归 asyncio executor 管(否则
    shutdown_default_executor 会死等阻塞线程)。
    """
    entered = threading.Event()

    def _input_thread() -> None:
        try:
            input("\n[run] 浏览器操作完毕后按回车 → 停录制 + 开跑审计 ...\n")
        except (EOFError, OSError):
            pass
        entered.set()

    threading.Thread(target=_input_thread, daemon=True).start()

    async def _poll() -> None:
        while not entered.is_set():
            await asyncio.sleep(0.3)
        stop_event.set()

    return asyncio.create_task(_poll())


async def _run_async(args: argparse.Namespace) -> int:
    from agentsuite.pipeline.runner import run_pipeline, get_session_findings
    from agentsuite.app._runstate import read_state, write_state, clear_state

    jsonl_text = _build_input(args)
    if jsonl_text is None:
        return 2

    host = _domain_of(args.url)
    session_dir = _new_session_dir(host)
    session_dir.mkdir(parents=True, exist_ok=True)

    rows, err = _parse_input(jsonl_text)
    if err:
        print(f"[run] {err}", file=sys.stderr)
        return 2
    url = str(rows[0].get("url") or "").strip() if rows else ""

    # 一条龙:record 录制(按回车停)→ dispatch → verify → report
    cfg = {**DEFAULT_CONFIG, "record_enabled": True, "dispatch_enabled": True,
           "verify_enabled": True, "report_enabled": True}
    mode = "mitm"  # 本仓唯一录制轨(mitmproxy 纯被动,见 ADR-0002)

    stale = read_state()
    if stale and stale.get("session_dir") != str(session_dir):
        print(f"[run] 上次 run(session {stale.get('session_dir')})未完成,"
              f"覆盖 state(旧 traffic 孤立未审计)")
    write_state(session_dir=str(session_dir), mode=mode)

    traffic_db = session_dir / "pipeline" / "proxy" / "traffic.sqlite"
    print(f"[run] session={session_dir}")
    print(f"[run] 流量落地:{traffic_db}")
    print(f"[run] mitmproxy 纯被动录制 → 浏览器挂代理 "
          f"{settings.mitm_proxy_host}:{settings.mitm_proxy_port} + 装 mitm CA 过 HTTPS")
    print("[run] 浏览器操作完毕回终端按回车 → 停录制 → 审计 → 报告(实时进度见下方 [stage])")

    q: asyncio.Queue = asyncio.Queue()
    stop_event = asyncio.Event()

    def emit(msg: str) -> None:
        try:
            c = _color_for(msg)
            print(f"{_ANSI['dim']}[stage]{_ANSI['reset']} {c}{msg}{_ANSI['reset']}", flush=True)
        except Exception:
            pass
        q.put_nowait(msg)

    async def _run_with_done():
        try:
            return await run_pipeline(str(session_dir), cfg, DEFAULT_STAGES,
                                      emit, stop_event, url)
        finally:
            q.put_nowait(None)

    task = asyncio.create_task(_run_with_done())
    # 按回车停录制(daemon 线程 input + asyncio 轮询 set stop_event)
    enter_task = _start_enter_watcher(stop_event)

    exit_code = 0
    try:
        # 前台 drain:emit 流式打 stage 进度。run_pipeline 完(录+审跑完)→ None 到 → 退出。
        while True:
            msg = await q.get()
            if msg is None:
                break
    except (KeyboardInterrupt, asyncio.CancelledError):
        # 兜底:用户回不到终端按回车的异常情况(被 kill / 窗口关)。set stop_event
        # 等 task 收尾(recorder finally 兜底数据落盘),干净退出。
        print("\n[run] 中断收到,停止录制,flush + 跑审计 ...", flush=True)
        stop_event.set()
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=60)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            pass
    finally:
        enter_task.cancel()

    results = task.result() if task.done() and not task.cancelled() else []
    failed = [r for r in (results or []) if isinstance(r, dict) and r.get("failed")]
    if failed:
        exit_code = 5
        print(f"[run] stage 失败:{failed[-1].get('error', '')}", file=sys.stderr)

    # 审计完:print findings 概览(report 阶段已写 report/ 下交付报告 .md)
    from agentsuite.pipeline.report import print_findings
    findings = get_session_findings(str(session_dir))
    print_findings(findings)
    report_dir = session_dir / "report"
    print(f"[run] 报告目录: {report_dir}")

    clear_state()
    return exit_code
