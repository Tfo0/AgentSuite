from __future__ import annotations

from pathlib import Path
from typing import Any


def make_report_stop_hook(session_dir: str):
    """report/ 下至少一个 .md 才放行。检查文件系统而非 state.findings——report 不调 verdict,state.findings 恒空,make_stop_hook 会永远挡停。continue_=True=挡停/False=允许停。"""

    report_dir = Path(session_dir) / "report"

    async def stop_hook(hook_input: dict[str, Any],
                        _tool_name: str | None = None,
                        _context: Any = None) -> dict[str, Any]:
        if report_dir.is_dir() and any(report_dir.glob("*.md")):
            return {"continue_": False}
        return {
            "continue_": True,
            "stopReason": (
                "report:尚未写任何报告文件(report/*.md)。"
                "每个 confirmed finding 写一个独立 .md + report.md 总览后再结束。"
            ),
        }

    return stop_hook
