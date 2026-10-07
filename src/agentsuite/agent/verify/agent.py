from __future__ import annotations

from pathlib import Path

from agentsuite.agent.base import NodeManifest
from agentsuite.tool.assembly import build_traffic_options, read_prompt
from agentsuite.tool import make_stop_hook

_PROMPT_PATH = Path(__file__).parent / "prompt.md"

# 不设 output_format:否则 agent 用 StructuredOutput 提交 verdict 绕过 verify_report → 门禁失效。

MANIFEST = NodeManifest(
    name="verify",
    category="replay",
    requires=["traffic"],
    produces=["findings"],
    optional_config=["traffic_max_turns", "traffic_allow_mutating"],
)


def build_options(session_dir: str, *, max_turns: int = 30,
                  session_timeout_s: int = 600,
                  allow_mutating: bool = True,
                  disabled_tools: list[str] | None = None,
                  resume: str | None = None,
                  candidate_traffic_ids: list[str] | None = None,
                  candidate_skills: list[str] | None = None,
                  emit=None,
                  ) -> tuple:
    """组装 options + RunState + 有效超时。state_setup 设 expected_traffic_ids(evidence 归属门禁,防跨模块复用同 repeater:N 交差)+ expected_skills(stop 门禁覆盖率,防静默漏 skill;resume 重建也要重设)。max_turns/session_timeout_s 优先 agent.yaml。"""
    expected = set(candidate_traffic_ids) if candidate_traffic_ids else None
    skills = set(candidate_skills) if candidate_skills else None

    def _state_setup(state):
        if expected is not None:
            state.expected_traffic_ids = expected
        if skills is not None:
            state.expected_skills = skills

    return build_traffic_options(
        session_dir=session_dir, tag="verify",
        prompt=read_prompt(_PROMPT_PATH.parent), prompt_files=[_PROMPT_PATH.name],
        hook_factory=make_stop_hook,
        state_setup=_state_setup,
        max_turns=max_turns, session_timeout_s=session_timeout_s,
        allow_mutating=allow_mutating, disabled_tools=disabled_tools,
        resume=resume, emit=emit, agent_dir=Path(__file__).parent,
    )
