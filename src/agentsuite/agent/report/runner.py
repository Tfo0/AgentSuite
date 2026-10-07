from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsuite.agent.base import BaseRunner, Emit, RunContext

from .agent import build_options, MANIFEST


# severity 闸:severity ∈ 这些值的 finding 入报告([低]以上)。verify 倾向把 status 全标
# inconclusive(confirmed 硬标准太严→0 confirmed→下游断流),故下游按 severity 而非 status 闸。
# [无]/info/none/空 丢(无实际危害不留底);[低]及以上全到 report,含 confirmed 与存疑 inconclusive。
REPORT_SEVERITIES = ("low", "medium", "high", "critical")


def reportable_findings(findings: list[dict]) -> list[dict]:
    """筛 severity∈REPORT_SEVERITIES 的 finding([低]以上入报告)。单源:stage + runner 共用。"""
    return [f for f in findings if (f.get("severity") or "") in REPORT_SEVERITIES]


class ReportRunner(BaseRunner):
    """报告撰写驱动。无浏览器,读 findings + evidence 写 .md。"""

    async def run_report(self, session_dir: str, findings: list[dict]) -> dict[str, Any]:
        """读 severity≥low findings + evidence 写 report/。findings 是 verify 终审全量(含 rejected/
        inconclusive),本函数按 severity 闸筛 [低]以上(含 confirmed 与存疑 inconclusive)入报告。"""
        to_report = reportable_findings(findings)
        if not to_report:
            self._emit(f"无可报告 finding(severity≥low,共 {len(findings)} 条),跳过报告")
            return {"stage": "report", "reports": [], "skipped": True}

        findings_desc = json.dumps(to_report, ensure_ascii=False, indent=2)
        prompt = (
            f"## 待撰写报告的 findings(severity≥low,verify 终审,共 {len(to_report)} 条)\n"
            f"```\n{findings_desc}\n```\n\n"
            "你是报告 agent。上面是 verify 终审产出、severity≥low 的 findings(含 confirmed "
            "与存疑 inconclusive)。**逐条**为每个 finding 撰写一份可直接交付的漏洞报告(独立 "
            ".md),并写一份总览索引 report/report.md。每条的 status/summary 已标置信度——"
            "confirmed 项作已确认;inconclusive 项如实标存疑(不脑补、不把存疑当已确认)。每条 "
            "evidence_ids 是证据指针——traffic_get(raw=true) 读 raw HTTP 原文贴进复现段(不靠"
            "记忆重抄)。详见 system prompt 的逻辑/工具/注意事项/输出。\n\n"
            "**逐条不漏**:每个 finding 必须写一个独立 .md,漏一个不算完成。"
        )

        try:
            result_text, _structured, _state = await self._drive(
                build_options_fn=lambda resume_id=None: build_options(
                    session_dir, max_turns=self.max_turns,
                    session_timeout_s=self.session_timeout_s,
                    emit=self._emit, resume=resume_id,
                ),
                user_prompt=prompt,
                tag="report",
            )
        except Exception as exc:  # noqa: BLE001
            self._emit(f"报告异常 {type(exc).__name__}: {exc}")
            return {"stage": "report", "reports": [], "error": str(exc), "failed": True}

        # report 产出是 .md 文件,统计 report/ 下 .md(LLM 调 Write 写的)
        report_dir = Path(session_dir) / "report"
        reports = sorted(str(p.name) for p in report_dir.glob("*.md")) if report_dir.is_dir() else []
        self._emit(f"报告产出 {len(reports)} 个 .md: {', '.join(reports)}")
        return {"stage": "report", "reports": reports, "raw_result": result_text}


async def run_report(
    session_dir: str, findings: list[dict], *,
    max_turns: int = 80, session_timeout_s: int = 3600,
    on_event: Any = None,
) -> dict[str, Any]:
    """node 稳定接口:读 confirmed findings + evidence 写 report/。"""
    runner = ReportRunner(
        max_turns=max_turns, session_timeout_s=session_timeout_s, on_event=on_event)
    return await runner.run_report(session_dir, findings)


async def run_from_ctx(ctx: RunContext, emit: Emit,
                       findings: list[dict] | None = None) -> dict[str, Any]:
    """node 稳定接口(ctx→runner 适配):读 confirmed findings + evidence,写交付报告(report/ 下 .md)。"""
    result = await run_report(
        ctx.session_dir,
        findings=findings or [],
        max_turns=ctx.report_max_turns,
        session_timeout_s=ctx.report_timeout,
        on_event=lambda m: emit(f"[report] {m}"),
    )
    return {"stage": "report", "result": result}


class _ReportNode:
    manifest = MANIFEST
    run = staticmethod(run_from_ctx)


NODE = _ReportNode
