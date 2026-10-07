"""forced-loop 编排(0→1 session-based)。

session_dir 是唯一坐标:无全局 DB,无项目锁,无内存 RunManager。
对外两个入口:
- run_pipeline(session_dir, cfg, stage_names, emit, stop_event, url):建 ctx → 跑 stages。
- get_session_findings(session_dir):读 pipeline/agent/findings.jsonl findings + 附代表 API。

stage 编排逻辑(record 串→dispatch+verify 流式并发)在 run_stages;
run_pipeline 只是 build_run_context + run_stages 的薄壳。DEFAULT_CONFIG/DEFAULT_STAGES
是原 builtin-record 策略种子的内联化(无全局 DB 后的默认装配)。
"""
from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

from agentsuite.agent.base import RunContext
from agentsuite.pipeline._concurrency import glm_concurrency_size
from agentsuite.pipeline import stages as stages

# 原 builtin-record 策略种子(无全局 DB 后内联到这)
DEFAULT_STAGES = ["record", "dispatch", "verify", "report"]
DEFAULT_CONFIG: dict[str, Any] = {
    "record_timeout": 3600,
    "traffic_max_turns": 80, "traffic_allow_mutating": True, "traffic_timeout": 3600,
    "dispatch_enabled": True, "dispatch_max_turns": 80, "dispatch_timeout": 3600,
    "verify_enabled": True,
    "report_enabled": True, "report_max_turns": 80, "report_timeout": 3600,
}


def build_run_context(session_dir: str, cfg: dict, *, url: str = "",
                      stop_event: Any = None) -> RunContext:
    """从 session_dir + cfg 建 RunContext(session_dir 是唯一坐标,
    pipeline/agent/findings.jsonl 的 findings 都按 session_dir 分区)。"""
    return RunContext(
        project_id="",
        session_dir=session_dir,
        url=url,
        provider=cfg.get("provider", "local"),
        headless=not cfg.get("headed", False),
        record_enabled=cfg.get("record_enabled", True),
        traffic_max_turns=cfg.get("traffic_max_turns", 30),
        traffic_allow_mutating=cfg.get("traffic_allow_mutating", True),
        traffic_timeout=cfg.get("traffic_timeout", 600),
        dispatch_enabled=cfg.get("dispatch_enabled", True),
        verify_enabled=cfg.get("verify_enabled", True),
        report_enabled=cfg.get("report_enabled", True),
        dispatch_max_turns=cfg.get("dispatch_max_turns", 12),
        dispatch_timeout=cfg.get("dispatch_timeout", 300),
        report_max_turns=cfg.get("report_max_turns", 80),
        report_timeout=cfg.get("report_timeout", 3600),
        record_timeout=cfg.get("record_timeout", 3600),
        disabled_tools=cfg.get("disabled_tools", []),
        record_traffic=True,            # forced-loop 录制场景必录流量
        stop_event=stop_event,
    )


async def run_stages(ctx: RunContext, stage_names: list[str],
                     emit) -> list[dict[str, Any]]:
    """跑 forced-loop 链路:record(串)→ dispatch+verify(流式并发)。

    装配式:各段读 ctx.{stage}_enabled flag 跳过。record 必须先串行录流量
    (dispatch/verify 都吃 traffic.sqlite);dispatch 产模块进 dispatch_queue,verify worker
    流式消费,两 stage 在同一 gather 里并发跑(共用 ctx.glm_sem 限 glm 总并发)。

    队列解耦:dispatch 不调 verify,只写 dispatch_queue;verify 不调 dispatch,只 claim
    队列。dispatch_done Event 是唯一时序信号(dispatch 产完→set,verify 排空即止)。
    """
    results: list[dict[str, Any]] = []

    # 契约校验(违反跳过+警告,不崩链;flag 组合须满足 requires/produces 咬合)
    if ctx.verify_enabled and not ctx.dispatch_enabled:
        emit("[pipeline] verify 开但 dispatch 关→无候选来源,verify 将空跑")

    # 1. record 纯录制(串行,mitm 纯被动;用户手动操作浏览器录流量)
    if "record" in stage_names and ctx.record_enabled:
        try:
            r = await stages.run_record_stage(ctx, emit)
            results.append(r)
        except Exception as exc:
            emit(f"[record] 失败:{exc}")
            results.append({"stage": "record", "error": str(exc), "failed": True})

    record_failed = any(x.get("stage") == "record" and x.get("failed") for x in results)

    # 2+3. dispatch + verify 流式并发(dispatch 产模块,verify 边 claim 边消)
    run_dispatch = ("dispatch" in stage_names and ctx.dispatch_enabled and not record_failed)
    run_verify = ("verify" in stage_names and ctx.verify_enabled and not record_failed)
    if run_dispatch or run_verify:
        ctx.glm_sem = asyncio.Semaphore(glm_concurrency_size())
        ctx.dispatch_done = asyncio.Event()

        async def _dispatch_producer():
            try:
                if run_dispatch:
                    return await stages.run_dispatch_stage(ctx, emit)
                return None
            finally:
                ctx.dispatch_done.set()

        async def _verify_consumer():
            if run_verify:
                return await stages.run_verify_stage(ctx, emit)
            # verify 关:等 dispatch 产完(不消费,仅同步 done 信号)
            await ctx.dispatch_done.wait()
            return None

        try:
            d, v = await asyncio.gather(_dispatch_producer(), _verify_consumer())
            if d is not None:
                results.append(d)
            if v is not None:
                results.append(v)
        except Exception as exc:
            emit(f"[dispatch/verify] 失败:{exc}")
            results.append({"stage": "dispatch_verify", "error": str(exc), "failed": True})

    # 4. report:读 verify 终审的 confirmed findings + evidence,写交付报告 .md
    #    (串行,verify 完才跑——report 吃 findings.jsonl 的 confirmed,verify 必须先落完)
    run_report = ("report" in stage_names and getattr(ctx, "report_enabled", True)
                  and not record_failed)
    if run_report:
        try:
            r = await stages.run_report_stage(ctx, emit)
            results.append(r)
        except Exception as exc:
            emit(f"[report] 失败:{exc}")
            results.append({"stage": "report", "error": str(exc), "failed": True})

    return results


async def run_pipeline(session_dir: str, cfg: dict, stage_names: list[str],
                       emit, stop_event: Any = None,
                       url: str = "") -> list[dict[str, Any]]:
    """session-based 编排入口:建 ctx → 跑 stages → 返回结果。

    as run 传 stop_event + page-only cfg(录)+ url(入口页);as stop 传 audit cfg
    (无 stop_event、page off、无 url,复用现有 traffic.sqlite)。无全局 DB,无项目锁
    ——session_dir 是唯一坐标。
    """
    ctx = build_run_context(session_dir, cfg, url=url,
                            stop_event=stop_event)
    return await run_stages(ctx, stage_names, emit)


# ── findings 读 + 附代表 API(从 runner 移植,session_dir 直参,无全局 id 解析)──

def get_session_findings(session_dir: str) -> dict[str, Any]:
    """读 session_dir/pipeline/agent/findings.jsonl 的 findings + 附代表 API(method/host/path)。

    逐条 evidence_id 解到 history 行:history:N 直查;repeater/brute/send:N
    读 traffic.sqlite evidence 表的 source_id 回指 history(链式重放沿链追);
    无前缀 id 跳过。第一个解到的 history 行赢。
    """
    root = Path(session_dir)
    from agentsuite.pipeline.store import FindingsStore
    store = FindingsStore(database_path=root / "pipeline" / "agent" / "findings.jsonl")
    findings = store.list_findings(str(root))
    _enrich_findings_api(findings, root)
    return {
        "findings": findings,
        "findings_count": len(findings),
        "confirmed_count": sum(1 for f in findings if f.get("status") == "confirmed"),
        "ready": bool(findings),
    }


def _enrich_findings_api(findings: list[dict[str, Any]], root: Path) -> None:
    """每条 finding 附 method/host/path(取 evidence_ids 解到 history 再查 traffic.sqlite)。

    evidence 已回 traffic.sqlite 的 evidence 表(与 history 同库),单连接解析:
    history:N 直查;repeater/brute/send:N 读 evidence.source_id 回指(链式重放
    source_id 可能再指 evidence id,沿链追到 history:<id> 为止);send 证据 source_id
    是 "send" 字面量无 history 根 → ''(B1,设计取舍);无前缀 id(module sha1)→ ''。
    第一个解到的 history 行赢,填 method/host/path。"""
    traffic_db = root / "pipeline" / "proxy" / "traffic.sqlite"
    if not traffic_db.is_file():
        return
    src_cache: dict[str, str] = {}
    conn = sqlite3.connect(str(traffic_db))
    try:
        conn.row_factory = sqlite3.Row
        for f in findings:
            for eid in f.get("evidence_ids") or []:
                hid = _to_history_id(str(eid), conn, src_cache)
                if not hid:
                    continue
                row = conn.execute(
                    "SELECT method, host, path FROM history WHERE id=?", (hid,)
                ).fetchone()
                if row:
                    f["method"], f["host"], f["path"] = row[0], row[1], row[2]
                    break
    finally:
        conn.close()


def _to_history_id(eid: str, conn: sqlite3.Connection, cache: dict[str, str]) -> str:
    """evidence id → history 数字 id(沿 source_id 链追到 history:<id>)。

    history:N 直返;<source>:<seq>(repeater/brute/send)从 evidence 表读 source_id
    递归(链式重放 source_id 可能再指 evidence id);无前缀 id(module sha1)/"send"
    字面量/悬空/环 → ''。cache 按 eid 记终值防重算;占位防环(链上回指自己 → 终止)。"""
    if eid.startswith("history:"):
        return eid.split(":", 1)[1]
    if ":" not in eid:
        return ""
    if eid in cache:
        return cache[eid]
    cache[eid] = ""  # 先占位防环(链上回指到自己 → 终止返 "")
    cur = eid
    for _ in range(16):  # 链深度上限(防环/异常长链)
        src, _, raw = cur.partition(":")
        if src not in ("repeater", "brute", "send") or not raw.isdigit():
            break
        row = conn.execute(
            "SELECT source_id FROM evidence WHERE source=? AND source_seq=?",
            (src, int(raw)),
        ).fetchone()
        if row is None:
            break
        nxt = str(row["source_id"] or "")
        if not nxt or nxt == "send":  # send 字面量无根/空 source_id
            break
        if nxt.startswith("history:"):
            cache[eid] = nxt.split(":", 1)[1]
            return cache[eid]
        if nxt in cache:  # 已算过:有值复用(链共享),空值=环/不可解 → 终止
            if cache[nxt]:
                cache[eid] = cache[nxt]
                return cache[nxt]
            break
        cache[nxt] = ""  # 占位防环
        cur = nxt
    return cache[eid]
