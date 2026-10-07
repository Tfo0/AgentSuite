from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


TRAFFIC_STATUSES = ("confirmed", "rejected", "inconclusive")


@dataclass
class TrafficReport:
    """验证结论(可含多条 finding)。findings 是主字段;兼容字段取 worst-finding(confirmed>inconclusive>rejected)供旧消费者读单结论。severity 不在 verdict——save_finding 从 summary 标签提,这里兼容字段留空。"""

    session_dir: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    stage: str = "verify"
    status: str = "inconclusive"
    skill: str = ""
    title: str = ""
    summary: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    severity: str = ""
    confidence: float = 0.0
    replays_total: int = 0  # runner 从 state.replays 数(非 LLM 报)
    raw_result: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_dir": self.session_dir,
            "findings": self.findings,
            "stage": self.stage,
            "status": self.status,
            "skill": self.skill,
            "title": self.title,
            "summary": self.summary,
            "evidence_ids": self.evidence_ids,
            "severity": self.severity,
            "confidence": self.confidence,
            "replays_total": self.replays_total,
            "raw_result": self.raw_result,
            "error": self.error,
        }

    def _normalize_worst(self) -> None:
        """从 findings 里取 worst(confirmed 优先)回填到单 finding 兼容字段。severity 留空(findings 不带,save_finding 从 summary 标签提)。"""
        if not self.findings:
            return
        order = {"confirmed": 0, "inconclusive": 1, "rejected": 2}
        worst = min(self.findings, key=lambda f: order.get(str(f.get("status")), 3))
        self.stage = str(worst.get("stage") or self.stage or "verify")
        self.status = str(worst.get("status") or "inconclusive")
        self.skill = str(worst.get("skill") or "")
        self.title = str(worst.get("title") or "")
        self.summary = str(worst.get("summary") or "")
        ids = worst.get("evidence_ids") or []
        self.evidence_ids = [str(i) for i in ids] if isinstance(ids, list) else []
        self.severity = str(worst.get("severity") or "")
        self.confidence = float(worst.get("confidence") or 0.0)
