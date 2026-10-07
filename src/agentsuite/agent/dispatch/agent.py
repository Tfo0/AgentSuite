from __future__ import annotations

from pathlib import Path

from agentsuite.agent.base import NodeManifest
from agentsuite.tool.assembly import build_traffic_options, read_prompt

from .hooks import make_pack_stop_hook

_PROMPT_PATH = Path(__file__).parent / "prompt.md"

# skill/index.md(认-side 路由目录,活文件)。dispatch 直读文件拼 system_prompt(Python 层读文件,非 MCP 工具调用)。
_INDEX_PATH = Path(__file__).parent.parent.parent / "skill" / "index.md"

# 不设 output_format:否则 agent 用 StructuredOutput 提交 verdict 绕过 dispatch_send → 覆盖率门禁失效。

MANIFEST = NodeManifest(
    name="dispatch",
    category="discover",
    requires=["traffic"],
    produces=["candidates"],
    optional_config=["dispatch_max_turns", "dispatch_timeout"],
)


def _load_index_catalog() -> str:
    """读 skill/index.md 拼系统 prompt(直读文件非 MCP)。文件缺失→空(prompt 降级,未命中→skill=[] novel)。"""
    if not _INDEX_PATH.is_file():
        return ""
    return _INDEX_PATH.read_text(encoding="utf-8").strip()


def _build_prompt() -> str:
    base = read_prompt(_PROMPT_PATH.parent)
    catalog = _load_index_catalog()
    return f"{base}\n\n{catalog}" if catalog else base


def _prompt_files() -> list[str]:
    files = [_PROMPT_PATH.name]
    if _INDEX_PATH.is_file():
        files.append(f"{_INDEX_PATH.parent.name}/{_INDEX_PATH.name}")
    return files


def build_options(session_dir: str, *, batch_rids: list[str] | None = None,
                  max_turns: int = 12,
                  session_timeout_s: int = 300,
                  allow_mutating: bool = True,
                  disabled_tools: list[str] | None = None,
                  resume: str | None = None,
                  emit=None,
                  ) -> tuple:
    """组装 options + RunState + 有效超时。batch_rids 是覆盖率门禁依据(每 rid 须 ≥1 次 dispatch_send);max_turns/session_timeout_s 优先 agent.yaml,参数作 fallback。"""
    return build_traffic_options(
        session_dir=session_dir, tag="dispatch",
        prompt=_build_prompt(), prompt_files=_prompt_files(),
        hook_factory=lambda state: make_pack_stop_hook(state, batch_rids),
        max_turns=max_turns, session_timeout_s=session_timeout_s,
        allow_mutating=allow_mutating, disabled_tools=disabled_tools,
        resume=resume, emit=emit, agent_dir=Path(__file__).parent,
    )
