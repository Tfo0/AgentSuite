from __future__ import annotations

from pathlib import Path

from agentsuite.agent.base import NodeManifest
from agentsuite.tool.assembly import build_traffic_options, read_prompt

from .hooks import make_report_stop_hook

_PROMPT_PATH = Path(__file__).parent / "prompt.md"

MANIFEST = NodeManifest(
    name="report",
    category="report",
    requires=["findings"],
    produces=["report"],
    optional_config=["report_max_turns", "report_timeout"],
)


def build_options(session_dir: str, *, max_turns: int = 80,
                  session_timeout_s: int = 3600,
                  disabled_tools: list[str] | None = None,
                  resume: str | None = None,
                  emit=None,
                  ) -> tuple:
    """组装 options + RunState + 有效超时。hook 检查 report/*.md 而非 state.findings(report 不调 verdict,state.findings 恒空)。max_turns/session_timeout_s 优先 agent.yaml。"""
    def _hook_factory(state):
        return make_report_stop_hook(session_dir)

    return build_traffic_options(
        session_dir=session_dir, tag="report",
        prompt=read_prompt(_PROMPT_PATH.parent), prompt_files=[_PROMPT_PATH.name],
        hook_factory=_hook_factory,
        state_setup=lambda state: None,
        max_turns=max_turns, session_timeout_s=session_timeout_s,
        allow_mutating=False,  # report 不重放,不需 mutating
        disabled_tools=disabled_tools,
        resume=resume, emit=emit, agent_dir=Path(__file__).parent,
    )
