"""session 审计报告生成:读 findings + evidence + history → 拼 report/report.md 写盘。

B 证据深度(用户定):每个 confirmed/inconclusive finding 嵌 baseline raw HTTP +
candidate raw HTTP + response 摘录(并排标关键变化);rejected 一行概览省篇幅。

源数据:pipeline.sqlite findings(runner.get_session_findings 已附 method/host/path)+
traffic.sqlite(AuditStore.get 解 history:N 原始流量 + repeater/brute/send:N 重放证据,
后者 source_id 回指 history)。raw HTTP 渲染复用 to_raw_http(同 traffic_get raw 模式,
不重发明)。app/stop.py 跑完审计调 write_session_report 写 report/report.md,终端 print 概览保留
(快速扫),report/report.md 是可归档/可贴 issue 的人类可读投影。

多 candidate(repeater/brute/send 多条证据):嵌第一个 candidate 的 raw + response 摘录,
其余 evidence_id 列在 finding 头(不重复嵌,防爆篇幅)。无 candidate(只 history:N)→ 只嵌
baseline。无证据 traffic_id → 标"无可用证据"。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from agentsuite.proxy.http import to_raw_http

_RESP_EXCERPT = 800  # response 摘录字符数(够看 code/data 结构)


def print_findings(payload: dict[str, Any]) -> None:
    """终端概览:一行一条 finding `[status] skill/sev title <- METHOD host path`。
    无 finding 标"(无 finding)"。快速扫;report/report.md 是可归档详细投影。"""
    items = payload.get("findings") or []
    confirmed = payload.get("confirmed_count", 0)
    print(f"\n=== findings({len(items)}) confirmed={confirmed} ===")
    for f in items:
        status = f.get("status", "")
        skill = f.get("skill", "") or f.get("family", "")
        title = f.get("title") or f.get("summary") or ""
        sev = f.get("severity", "")
        method = f.get("method", "")
        host = f.get("host", "")
        path = f.get("path", "")
        loc = f"{method} {host}{path}".strip()
        line = f"  [{status}] {skill}/{sev} {title}"
        if loc:
            line += f"  <- {loc}"
        print(line)
    if not items:
        print("  (无 finding)")


def write_session_report(session_dir: str) -> Path:
    """读 session 产物 → 拼 report/report.md → 写 session_dir/report/report.md,返回路径。

    无 findings 也写(标"无 finding"),让用户确认跑过审计不是空跑。
    """
    from agentsuite.pipeline.runner import get_session_findings
    from agentsuite.tool.data.store import AuditStore

    root = Path(session_dir)
    payload = get_session_findings(session_dir)
    findings = payload.get("findings") or []
    traffic_db = root / "pipeline" / "proxy" / "traffic.sqlite"
    traffic = AuditStore(database_path=traffic_db, session_dir=root) if traffic_db.is_file() else None
    md = _render_report(root.name, payload, findings, traffic)
    out = root / "report" / "report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    return out


def _render_report(session_name: str, payload: dict[str, Any],
                   findings: list[dict[str, Any]], traffic: Any) -> str:
    total = len(findings)
    confirmed = int(payload.get("confirmed_count", 0) or
                    sum(1 for f in findings if f.get("status") == "confirmed"))
    inconclusive = sum(1 for f in findings if f.get("status") == "inconclusive")
    rejected = sum(1 for f in findings if f.get("status") == "rejected")
    lines: list[str] = [
        f"# 审计报告 — {session_name}",
        "",
        f"findings {total} · confirmed {confirmed} · "
        f"inconclusive {inconclusive} · rejected {rejected}",
        "",
    ]
    if not findings:
        lines += ["(无 finding)", ""]
        return "\n".join(lines)

    # 概览表:全部 findings 一表(快速扫)
    lines += ["## 概览", "",
              "| # | status | skill | severity | 位置 | 证据 |",
              "|---|---|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        lines.append(
            f"| {i} | {f.get('status', '')} | {f.get('skill', '') or f.get('family', '')} | "
            f"{f.get('severity', '') or '—'} | {_fmt_loc(f)} | {_first_evidence(f)} |")
    lines.append("")

    # confirmed / inconclusive:嵌 baseline + candidate raw + response 摘录
    for status_key in ("confirmed", "inconclusive"):
        group = [f for f in findings if f.get("status") == status_key]
        if not group:
            continue
        lines += [f"## {status_key}", ""]
        for i, f in enumerate(group, 1):
            lines.append(_render_finding_detail(f, traffic, idx=i))

    # rejected:一行概览(不嵌证据,供复盘不蒸发)
    rejected_group = [f for f in findings if f.get("status") == "rejected"]
    if rejected_group:
        lines += ["## rejected(供复盘)", ""]
        for f in rejected_group:
            lines.append(
                f"- [{f.get('skill', '') or f.get('family', '')}/{f.get('severity', '') or '—'}] "
                f"{_title(f)} — {_fmt_loc(f)} ({_first_evidence(f)})")
        lines.append("")
    return "\n".join(lines)


def _render_finding_detail(f: dict[str, Any], traffic: Any, *, idx: int) -> str:
    eids = [str(e) for e in (f.get("evidence_ids") or [])]
    baseline_raw, baseline_resp, cand_raw, cand_resp, cand_ids = _evidence_for_finding(eids, traffic)
    lines = [
        f"### [{idx}] {f.get('skill', '') or f.get('family', '')}/{f.get('severity', '') or '—'} — {_title(f)}",
        f"- 位置: {_fmt_loc(f)}",
    ]
    if eids:
        lines.append(f"- 证据: {', '.join(eids)}")
    summary = str(f.get("summary") or "")
    if summary:
        lines.append(f"- summary: {summary}")
    if baseline_raw:
        lines += ["", "**baseline:**", "", "```http", baseline_raw.rstrip(), "```"]
        if baseline_resp:
            lines += ["", f"baseline response(摘前 {_RESP_EXCERPT} 字符):", "",
                      "```", baseline_resp[:_RESP_EXCERPT], "```"]
    if cand_raw:
        lines += ["", "**candidate:**", "", "```http", cand_raw.rstrip(), "```"]
        if cand_resp:
            lines += ["", f"candidate response(摘前 {_RESP_EXCERPT} 字符,← 对比 baseline 看关键变化):",
                      "", "```", cand_resp[:_RESP_EXCERPT], "```"]
        if len(cand_ids) > 1:
            lines.append(f"(另有 {len(cand_ids) - 1} 条重放证据: {', '.join(cand_ids[1:])})")
    elif not baseline_raw:
        lines.append("(无可用证据 traffic_id)")
    lines.append("")
    return "\n".join(lines)


def _evidence_for_finding(eids: list[str], traffic: Any) -> tuple[str, str, str, str, list[str]]:
    """分 baseline(history:N 或 candidate source_id 回指)+ candidate(repeater/brute/send:N)。

    返回 (baseline_raw, baseline_resp, candidate_raw, candidate_resp, candidate_ids)。
    baseline 优先取 evidence_ids 里的 history:N;没有则从第一个 candidate 的 source_id 回指
    history(repeater 重放时 replay_service 存了 source_id 回指原流量)。
    """
    if traffic is None:
        return "", "", "", "", []
    baseline_id = next((e for e in eids if e.startswith("history:")), "")
    cand_ids = [e for e in eids if ":" in e and not e.startswith("history:")]
    baseline_raw, baseline_resp = "", ""
    if baseline_id:
        baseline_raw, baseline_resp = _load_raw(baseline_id, traffic)
    elif cand_ids:
        data = traffic.get(cand_ids[0])
        sid = str((data or {}).get("source_id") or "")
        if sid.startswith("history:"):
            baseline_raw, baseline_resp = _load_raw(sid, traffic)
    cand_raw, cand_resp = "", ""
    if cand_ids:
        cand_raw, cand_resp = _load_raw(cand_ids[0], traffic)
    return baseline_raw, baseline_resp, cand_raw, cand_resp, cand_ids


def _load_raw(traffic_id: str, traffic: Any) -> tuple[str, str]:
    """traffic.get(id) → (raw_http, response_body_text)。拿不到返 ("", "")。"""
    data = traffic.get(traffic_id)
    if not data:
        return "", ""
    req = data.get("request") or {}
    resp = data.get("response") or {}
    return to_raw_http(req, resp), _resp_text(resp)


def _resp_text(resp: dict[str, Any]) -> str:
    """取 response body 文本(吃 history shape 的 body.text + evidence shape 的 body_text)。"""
    body = resp.get("body")
    if isinstance(body, dict):
        text = body.get("text")
        if isinstance(text, str):
            return text
    return str(resp.get("body_text") or "")


def _fmt_loc(f: dict[str, Any]) -> str:
    method = f.get("method") or ""
    host = f.get("host") or ""
    path = f.get("path") or ""
    loc = f"{method} {host}{path}".strip()
    return loc or "—"


def _first_evidence(f: dict[str, Any]) -> str:
    eids = f.get("evidence_ids") or []
    return str(eids[0]) if eids else "—"


def _title(f: dict[str, Any]) -> str:
    return str(f.get("title") or f.get("summary") or f.get("skill") or f.get("family") or "")
