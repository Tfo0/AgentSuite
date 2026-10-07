"""pipeline 的 session 级 findings 存储(jsonl):verify 终审结论。

只存,无业务逻辑。落 session_dir/pipeline/agent/findings.jsonl(单 jsonl,一行一 finding)。
pipeline stages 调它落 verify 终审结论。

findings:最终结论(verify 下 confirmed/rejected/inconclusive)。
dispatch 候选池在 traffic.sqlite 的 dispatch_queue 表(module schema),不在这。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _extract_severity(summary: str) -> str:
    """从 summary 文本提取定级标签 [严重]/[高]/[中]/[低]/[无] → 英文
    critical/high/medium/low/info(对齐前端 SEVERITY_COLOR + agent severity 枚举)。"""
    for tag in ("严重", "高危", "高", "中危", "中", "低危", "低", "无"):
        if f"[{tag}]" in summary:
            if tag == "严重":
                return "critical"
            if tag in ("高危", "高"):
                return "high"
            if tag in ("中危", "中"):
                return "medium"
            if tag in ("低危", "低"):
                return "low"
            return "info"  # 无
    return ""


class FindingsStore:
    """findings 的 CRUD(jsonl)。database_path=None 用内存 list(测试)。

    database_path 指向 findings.jsonl 文件路径。单 session 一文件,session_dir 参数
    保留接口兼容(实际不用于过滤,文件本身已 per-session)。
    """

    def __init__(self, database_path: str | Path | None = None) -> None:
        self._file = Path(database_path) if database_path else None
        if self._file is not None:
            self._file.parent.mkdir(parents=True, exist_ok=True)
        self._memory: list[dict[str, Any]] | None = [] if self._file is None else None

    def _read_all(self) -> list[dict[str, Any]]:
        if self._file is None:
            return list(self._memory or [])
        if not self._file.exists():
            return []
        out: list[dict[str, Any]] = []
        for ln in self._file.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                out.append(json.loads(ln))
            except (json.JSONDecodeError, OSError):
                continue
        return out

    def _write_all(self, items: list[dict[str, Any]]) -> None:
        if self._file is None:
            self._memory = list(items)
            return
        self._file.write_text(
            "\n".join(json.dumps(d, ensure_ascii=False) for d in items) + "\n",
            encoding="utf-8",
        )

    # ---- findings:写(verify 终审结论) ----
    def save_finding(self, *, session_dir: str, finding: dict[str, Any],
                     source_candidate_id: str = "") -> str:
        """verify 确认一条 finding 写进 findings.jsonl(统一 verdict 字段)。返回 finding_id。"""
        fid = str(finding.get("finding_id") or f"{self._next_finding_id():03d}")
        # severity:优先取 finding 字段(agent 填的英文枚举),否则从 summary 提取 [严重]/[高]/...
        severity = str(finding.get("severity") or _extract_severity(finding.get("summary") or ""))
        items = self._read_all()
        items.append({
            "session_dir": session_dir,
            "finding_id": fid,
            "stage": finding.get("stage") or "verify",
            "status": finding.get("status") or "inconclusive",
            "skill": finding.get("skill"),
            "title": finding.get("title"),
            "summary": finding.get("summary"),
            "evidence_ids": finding.get("evidence_ids") or [],
            "confidence": finding.get("confidence") or 0.0,
            "source_candidate_id": source_candidate_id,
            "severity": severity,
        })
        self._write_all(items)
        return fid

    def list_findings(self, session_dir: str) -> list[dict[str, Any]]:
        """列最终 findings(给前端/报告)。按 status 优先级降序(confirmed 的在前)+ finding_id。"""
        items = self._read_all()
        out: list[dict[str, Any]] = []
        for d in items:
            ids = d.get("evidence_ids") or []
            d2 = dict(d)
            # raw:N → send:N:对齐旧 raw 证据(已迁 send)。历史 finding 引用
            # raw:N 读出时规范化,不改文件——下游统一按 send:N 解析。
            d2["evidence_ids"] = [
                "send:" + str(i).split(":", 1)[1] if str(i).startswith("raw:") else str(i)
                for i in ids
            ]
            d2.setdefault("severity", "")
            d2.setdefault("skill", d2.get("family") or "")
            out.append(d2)
        out.sort(key=lambda f: (0 if f.get("status") == "confirmed" else 1,
                                 str(f.get("finding_id") or "")))
        return out

    # ---- 内部 ----
    def _next_finding_id(self) -> int:
        items = self._read_all()
        max_id = 0
        for d in items:
            fid = str(d.get("finding_id") or "")
            if fid.isdigit():
                i = int(fid)
                if i > max_id:
                    max_id = i
        return max_id + 1


__all__ = ["FindingsStore"]
