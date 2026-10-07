from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

DISPATCH_STATUSES = ("hit", "skip", "inconclusive")

DISPATCH_SEVERITIES = ("high", "medium", "low")


@dataclass
class DispatchResult:
    """单 clean 单元 dispatch 结论(一单元一结论)。不再落盘——模块候选由 dispatch_send 直接写 dispatch_queue,本对象只回传 stage 做统计。"""

    session_dir: str
    traffic_id: str = ""
    stage: str = "dispatch"
    status: str = "inconclusive"
    severity: str | None = None
    skill: str | None = None
    summary: str = ""
    tested: bool = False
    evidence_ids: list[str] = field(default_factory=list)
    raw_result: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
