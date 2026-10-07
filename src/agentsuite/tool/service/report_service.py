"""report_service:提交统一 verdict(精简 schema)+ 证据门禁。

每次调 add_finding 产一条 finding(一个 skill 的结论)。门禁(统一,不分 stage):
- confirmed/inconclusive 须提供非空 evidence_ids(证据锚定防幻觉);rejected 可空。
- evidence_ids 每个 value 须是 traffic.sqlite 真实存在的流量(replay 或 history,evidence_exists)。
diff 不再是门禁条件(降为 summary 里可提的派生信号)——证据=客观存在的流量,不机械要求 diff。

精简 verdict 字段(4 字段全必填,与 findings 表共用):{stage, skill, status,
summary, evidence_ids}。severity 不在 verdict——靠 summary 标签 [严重]/[高]/[中]/[低]/[无]
由 _extract_severity 提取(report_agent 信 verify 不重定级)。tested 删除(status 已隐含)。
proof 不内联——重放工具产 evidence 落 traffic.sqlite evidence 表,verdict 只引用 evidence_ids。
"""
from __future__ import annotations

from typing import Any

from ..data.store import AuditStore
from ..models import RunState


class ReportService:
    """提交统一 verdict finding,校验结论与证据要求(统一门禁,不分 stage)。"""

    def __init__(self, store: AuditStore) -> None:
        self.store = store

    def add_finding(
        self, *, stage: str, skill: str, status: str, summary: str,
        evidence_ids: list[Any] | None = None,
        state: RunState | None = None,
    ) -> dict[str, Any]:
        """提交一个 skill 的结论。返回带 finding_id 的 finding dict;追加到 state.findings。

        统一门禁(不分 stage):
        - stage ∈ {dispatch,verify}(dispatch 走 dispatch_send 不走 report);
          status ∈ {confirmed,rejected,inconclusive}(旧 noise/skip 并入 rejected);summary 非空。
        - confirmed/inconclusive 须非空 evidence_ids;rejected 可空(跳过证据门禁)。
        - evidence_ids 每个 value 须是 DB 真实流量(evidence_exists)。
        """
        stage_n = str(stage or "").strip().casefold()
        if stage_n not in {"dispatch", "verify"}:
            raise ValueError(f"不支持的 stage:{stage}")
        status_n = str(status or "").strip().casefold()
        if status_n not in {"confirmed", "rejected", "inconclusive"}:
            raise ValueError(f"不支持的 status:{status}(仅 confirmed/rejected/inconclusive)")
        skill_s = str(skill or "").strip()
        if not skill_s:
            raise ValueError("skill 不能为空")
        summary_s = str(summary or "").strip()
        if not summary_s:
            raise ValueError("summary 不能为空")

        ev_ids = [str(x).strip() for x in (evidence_ids or []) if str(x).strip()]
        ev_ids = list(dict.fromkeys(ev_ids))  # 去重保序

        need_ev = status_n in {"confirmed", "inconclusive"}
        if need_ev and not ev_ids:
            raise ValueError(f"{status_n} 须提供至少一条 evidence_ids(证据锚定防幻觉)")

        # 证据 id 真实性校验:每个 evidence_id 须在 DB 存在(replay 或 history)
        missing = [t for t in ev_ids if not self.store.evidence_exists(t)]
        if missing:
            raise ValueError(f"证据 id 不在流量库(不存在或未重放):{missing[:5]}")

        # 证据归属校验:引用证据的根 history 须属于当前模块的 traffic_ids。防 agent
        # 跨模块复用同一条 repeater:N(别模块的重放)当本模块证据交差。仅 verify 模块化
        # 模式在 build_options 设了 expected_traffic_ids(全量=None 不校验,向后兼容)。
        allowed = getattr(state, "expected_traffic_ids", None) if state else None
        if allowed:
            wrong = [t for t in ev_ids
                     if not (r := self._evidence_root_history(t)) or r not in allowed]
            if wrong:
                raise ValueError(
                    f"证据不属于本模块流量(疑似跨模块引用,须重放本模块流量产证):{wrong[:5]}")

        seq = (len(state.findings) + 1) if state is not None else 1
        finding = {
            "finding_id": f"{seq:03d}",
            "stage": stage_n,
            "skill": skill_s,
            "status": status_n,
            "summary": summary_s,
            "evidence_ids": ev_ids,
        }
        if state is not None:
            state.findings.append(finding)
        return finding

    def _evidence_root_history(self, traffic_id: str) -> str:
        """evidence id → 根 history:N。history:N 直返;repeater/brute/send 递归读
        source_id 回指直到 history:N(链式 repeater 也解到底)。解不到(链断/环/无前缀
        module_id)返 ''。归属门禁用——比 evidence_exists 多一道:不只查存在,还查根属谁。"""
        visited: set[str] = set()
        cur = str(traffic_id or "").strip()
        while cur and cur not in visited:
            visited.add(cur)
            if cur.startswith("history:"):
                return cur
            data = self.store.get(cur)  # evidence → dict 含 source_id;module_id → None
            if data is None:
                return ""
            nxt = str(data.get("source_id") or "").strip()
            if not nxt or nxt == cur:
                return ""
            cur = nxt
        return ""
