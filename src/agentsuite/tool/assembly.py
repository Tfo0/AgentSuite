from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Any, Callable

import yaml

from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

from .runner import build_traffic_services
from .server import TRAFFIC_TOOL_NAMES, build_traffic_mcp_server

_MCP_TOOLS = {"traffic": list(TRAFFIC_TOOL_NAMES)}

# skill 在仓内 src/agentsuite/skill/,agent cwd=session_dir 两树分离;prompt 用 {SKILL_DIR} 占位符,下方替换注入。
SKILL_DIR = Path(__file__).resolve().parent.parent / "skill"


def _collect_env() -> dict[str, str]:
    env = {}
    for k in ("AGENTSUITE_PLANNER_API_KEY", "DASHSCOPE_API_KEY",
              "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
              "ANTHROPIC_MODEL", "HTTP_PROXY", "HTTPS_PROXY"):
        v = os.getenv(k, "")
        if v:
            env[k] = v
    return env


def load_tool_manifest(agent_dir: Path | str,
                       disabled_tools: list[str] | None = None
                       ) -> tuple[str, list[str], list[str] | None, int | None, int | None, str | None]:
    """读 ``<agent>/agent.yaml``,返 ``(mcp, allowed, sdk_tools, max_turns, session_timeout_s, model)``。``sdk_tools`` 三态:null→追加 Bash 进 allowed(开 sdk 内置+允许 Bash);[]→禁所有内置;[list]→只给这些内置(无 Bash)。"""
    p = Path(agent_dir) / "agent.yaml"
    if not p.is_file():
        raise FileNotFoundError(f"agent.yaml not found: {p}")
    spec = yaml.safe_load(p.read_text(encoding="utf-8"))
    mcp = spec.get("mcp")
    disabled = set(disabled_tools or [])
    raw = spec.get("allowed_tools", "all")
    if raw == "all":
        full = _MCP_TOOLS.get(mcp, [])
        allowed = [t for t in full if t not in disabled]
    else:
        allowed = [t for t in raw if t not in disabled]
    sdk_tools = spec.get("sdk_tools", [])
    if sdk_tools is None and "Bash" not in allowed:
        allowed.append("Bash")
    max_turns = spec.get("max_turns")
    session_timeout_s = spec.get("session_timeout_s")
    model = spec.get("model")
    return mcp, allowed, sdk_tools, max_turns, session_timeout_s, model


def emit_assembly(emit, *, tag: str, prompt_files: list[str],
                  allowed: list[str], disallowed: list[str],
                  sdk_tools: list[str] | None, max_turns, timeout, model,
                  mcp: str = "traffic") -> None:
    """agent 启动记录装配。明细进 logging.debug;终端发一行启动摘要(node lambda 加 [tag] 前缀,emit 不含防双前缀);emit=None 走 stdout。"""
    log = logging.getLogger("agentsuite.assembly")

    def _short(t: str) -> str:
        return t.replace("mcp__traffic__", "")

    full = _MCP_TOOLS.get(mcp, [])
    allowed_set = set(allowed)
    dis_set = set(disallowed)
    usable = [t for t in allowed if t not in dis_set and t in allowed_set]
    not_listed = [t for t in full if t not in allowed_set and t not in dis_set]
    if sdk_tools is None:
        bash = "null(全默认+Bash)"
    elif sdk_tools == []:
        bash = "[](禁内置)"
    else:
        bash = f"{sdk_tools}(显式内置,无 Bash)"
    log.debug("[%s] 装配 提示词=%s mcp可用=%s 未装配=%s sdk_tools=%s max_turns=%s timeout=%s model=%s",
              tag, prompt_files, [_short(t) for t in usable],
              [_short(t) for t in not_listed], bash, max_turns, timeout, model)
    summary = (f"agent启动: {len(usable)} mcp工具, max_turns={max_turns}, "
               f"timeout={timeout}s, model={model or '(.env全局)'}")
    if emit:
        emit(summary)
    else:
        print(f"[{tag}] {summary}", flush=True)


def read_prompt(agent_dir: Path | str, filename: str = "prompt.md") -> str:
    """读 ``<agent_dir>/<filename>`` 作为 system prompt。共享,替代各 agent.py 的 _load_prompt。"""
    p = Path(agent_dir) / filename
    if not p.is_file():
        raise FileNotFoundError(f"prompt not found: {p}")
    return p.read_text(encoding="utf-8").strip()


def build_traffic_options(
    *,
    session_dir: str,
    tag: str,
    prompt: str,
    prompt_files: list[str],
    hook_factory: Callable[[Any], Any],
    state_setup: Callable[[Any], None] | None = None,
    max_turns: int,
    session_timeout_s: int,
    allow_mutating: bool = True,
    disabled_tools: list[str] | None = None,
    resume: str | None = None,
    emit=None,
    agent_dir: Path | str,
) -> tuple[ClaudeAgentOptions, Any, int | None]:
    """组装 traffic agent options + RunState + 有效超时,返 (options, state, session_timeout_s)。per-agent delta:prompt、prompt_files、hook_factory、state_setup(verify 设 expected_traffic_ids)、tag、agent_dir。yaml max_turns/timeout/model 优先于参数。"""
    query_service, replay_service, report_service, dispatch_service, state = build_traffic_services(
        session_dir, allow_mutating=allow_mutating,
    )
    if state_setup is not None:
        state_setup(state)
    _mcp, allowed, sdk_tools, y_mt, y_to, y_model = load_tool_manifest(agent_dir, disabled_tools)
    eff_max_turns = y_mt if y_mt is not None else max_turns
    eff_timeout = y_to if y_to is not None else session_timeout_s
    env = _collect_env()
    if y_model:
        env["ANTHROPIC_MODEL"] = y_model
    server = build_traffic_mcp_server(
        query_service, replay_service, report_service, dispatch_service, state,
        tool_subset=allowed,
    )
    emit_assembly(emit, tag=tag, prompt_files=prompt_files,
                  allowed=allowed, disallowed=[], sdk_tools=sdk_tools,
                  max_turns=eff_max_turns, timeout=eff_timeout, model=y_model)
    hook = hook_factory(state)
    # prompt 里 {SKILL_DIR} 占位符 → skill 目录绝对路径(防 agent cwd=session_dir 下相对路径解析不到)
    prompt = prompt.replace("{SKILL_DIR}", str(SKILL_DIR))
    options = ClaudeAgentOptions(
        mcp_servers={"traffic": server},
        strict_mcp_config=True,
        tools=sdk_tools,
        allowed_tools=allowed,
        max_turns=eff_max_turns,
        system_prompt=prompt,
        hooks={"Stop": [HookMatcher(hooks=[hook])]},
        permission_mode="bypassPermissions",
        max_buffer_size=64 * 1024 * 1024,  # SDK 默认 1MB:大 tool 结果触发 message reader Fatal;调到 64MB
        setting_sources=[],  # 不读任何 CLAUDE.md(防泄露)
        include_partial_messages=True,
        env=env,
        cwd=session_dir or None,
        resume=resume,  # 连接中断续跑(CLI --resume);setting_sources=[] 不影响 resume
        session_store=None,  # 不镜像会话到磁盘(transcript jsonl 无下游消费,resume 走 SDK 原生 session_id)
    )
    return options, state, eff_timeout
