from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from agentsuite.agent.base import Emit, RunContext
from agentsuite.agent.registry import get_node
from agentsuite.pipeline._concurrency import glm_concurrency_size
from agentsuite.proxy.clean import build_clean


async def run_record_stage(ctx: RunContext, emit: Emit) -> dict[str, Any]:
    """mitm 纯被动录制(无 LLM,走 proxy.recorder):人手操作浏览器录流量 → traffic.sqlite。结束信号 stop_event / record_timeout 兜底。"""
    url = (ctx.url or "").strip()
    if not url:
        emit("[record] 无目标 url")
        return {"stage": "record", "error": "无目标 url", "failed": True}
    from agentsuite.config import settings
    from agentsuite.proxy import run_record_session_mitm
    from agentsuite.proxy import get_mitm_service, start_mitm_service, stop_mitm_service
    # stage 是 mitm 唯一消费者在此起(幂等);start 失败不抛留 is_running=False,下面门禁兜住。
    start_mitm_service()
    if not (settings.mitm_proxy_enabled and get_mitm_service().is_running):
        emit("[record] mitmproxy 代理未起,无法录制(本仓唯一录制轨)")
        return {"stage": "record", "error": "mitm 代理未起", "failed": True}
    emit("[record] 纯被动模式:浏览器经代理挂 mitmproxy,手动操作后点'停止'")
    timeout = int(getattr(ctx, "record_timeout", 3600) or 3600)
    try:
        result = await run_record_session_mitm(
            url, session_dir=ctx.session_dir,
            timeout=timeout, stop_event=ctx.stop_event, on_event=emit,
        )
        written = int(result.get("traffic_records", 0))
        emit(f"[record] 录制结束,流量落地 {written} 条")
        return {"stage": "record", "result": result}
    except Exception as exc:  # noqa: BLE001
        emit(f"[record] 录制异常:{type(exc).__name__}: {exc}")
        return {"stage": "record", "error": str(exc), "failed": True}
    finally:
        # build_clean record 尾跑(executor 免阻塞 loop);失败不阻塞定稿(dispatch 读不到 clean.jsonl→空单元降级不崩)。
        try:
            _loop = asyncio.get_running_loop()
            _stat = await _loop.run_in_executor(None, lambda: build_clean(ctx.session_dir))
            emit(f"[record] build_clean: raw={_stat['total_raw']} clusters={_stat['clusters']} "
                 f"clean={_stat['clean']} noise_drop={_stat['skipped_noise']} -> pipeline/proxy/clean.jsonl + pipeline/proxy/noise.jsonl")
        except Exception as _exc:  # noqa: BLE001
            emit(f"[record] build_clean 跳过:{type(_exc).__name__}: {_exc}")
        # 停 mitm 代理(record 是 mitm 唯一消费者,录完即停释放端口)。
        try:
            stop_mitm_service()
        except Exception:
            pass


async def run_dispatch_stage(ctx: RunContext, emit: Emit) -> dict[str, Any]:
    """逐批 clean 单元跑 dispatch agent 找漏洞线索。模块候选由 agent 内部 dispatch_send 写 dispatch_queue(1 send=1 模块行),stage 只统计不落盘。前置 clean.jsonl(record 尾产,只读)。"""
    dispatch_node = get_node("dispatch")
    if dispatch_node is None:
        emit("[dispatch] dispatch node 未注册,跳过")
        return {"stage": "dispatch", "error": "dispatch node 未注册", "failed": True}
    if not getattr(ctx, "dispatch_enabled", True):
        emit("[dispatch] 策略关闭 dispatch,跳过")
        return {"stage": "dispatch", "skipped": True}

    traffic_db = Path(ctx.session_dir) / "pipeline" / "proxy" / "traffic.sqlite"
    if not traffic_db.is_file():
        emit("[dispatch] 无 traffic.sqlite(page 未采集),跳过")
        return {"stage": "dispatch", "error": "无流量数据(page 未跑)", "failed": True}

    loop = asyncio.get_running_loop()

    emit("[dispatch] 读 clean.jsonl 派活")
    def _services():
        from agentsuite.tool.runner import build_traffic_services
        q, *_ = build_traffic_services(str(ctx.session_dir))
        return q
    try:
        q = await loop.run_in_executor(None, _services)
    except Exception as exc:  # noqa: BLE001
        emit(f"[dispatch] services 装配失败:{type(exc).__name__}: {exc}")
        return {"stage": "dispatch", "error": "services 装配失败", "failed": True}
    units = q.store.list_clean()
    done = q.store.list_dispatch_done_traffic_ids()
    pending_count = sum(1 for u in units if u.get("request_id") not in done)
    emit(f"[dispatch] {len(units)} 单元,已打包 {len(units) - pending_count},待跑 {pending_count}")
    batches = list(q.pack_units(byte_budget=8192, exclude_ids=done))
    emit(f"[dispatch] 打包 {len(batches)} 批(~8-10 条/批)")

    sem = ctx.glm_sem
    if sem is None:  # standalone 直调(不经 _run_stages)→ 本地 sem 退化单跑
        sem = asyncio.Semaphore(glm_concurrency_size())

    async def _dispatch_one(batch: list[dict[str, Any]]) -> dict[str, int]:
        rids = [str(u.get("request_id", "")) for u in batch]
        local = {"hits": 0, "skips": 0, "inconclusive": 0}
        try:
            async with sem:
                result = await dispatch_node.run(ctx, emit, batch=batch)
            drs = result.get("results") or []
        except Exception as exc:  # noqa: BLE001
            emit(f"[dispatch] 批 {rids} 异常:{type(exc).__name__}: {exc}")
            for rid in rids:
                local["inconclusive"] += 1
            return local
        for dr in drs:
            rid = str(getattr(dr, "traffic_id", ""))
            status = getattr(dr, "status", "inconclusive")
            if status == "hit":
                local["hits"] += 1
                emit(f"[dispatch] {rid} hit {getattr(dr, 'skill', '')}")
            elif status == "skip":
                local["skips"] += 1
            else:
                local["inconclusive"] += 1
        return local

    batch_stats = await asyncio.gather(*[_dispatch_one(b) for b in batches]) if batches else []
    hits = sum(s["hits"] for s in batch_stats)
    skips = sum(s["skips"] for s in batch_stats)
    inconclusive = sum(s["inconclusive"] for s in batch_stats)
    module_count = len(q.store.list_modules())
    emit(f"[dispatch] 完成:hit={hits} skip={skips} inconclusive={inconclusive} "
         f"模块候选={module_count}(交 verify)")
    return {"stage": "dispatch", "total": pending_count, "batches": len(batches),
            "hits": hits, "skips": skips, "inconclusive": inconclusive,
            "modules": module_count}


def _mark_candidate_resolved(session_dir: str, cand: dict[str, Any],
                             status: str = "resolved") -> None:
    """verify 消费完模块标 resolved。session_dir 必传(不传落内存 queue,改不到文件 queue 的模块)。"""
    from agentsuite.tool.data.store import AuditStore
    AuditStore(database_path=Path(session_dir) / "pipeline" / "proxy" / "traffic.sqlite",
          session_dir=session_dir).mark_module_resolved(cand["candidate_id"], status)


async def run_verify_stage(ctx: RunContext, emit: Emit) -> dict[str, Any]:
    """verify 终审:多 worker 流式 claim_module CAS 领模块(WHERE+rowcount 防双吃)→ verify_node.run 下 verdict+定级+落 findings。崩溃恢复:开跑前 reset_in_progress 重置僵尸 claim;dispatch_done.set 后排空即止。"""
    verify_node = get_node("verify")
    if verify_node is None:
        emit("[verify] verify node 未注册,跳过")
        return {"stage": "verify", "error": "verify node 未注册", "failed": True}

    traffic_db = Path(ctx.session_dir) / "pipeline" / "proxy" / "traffic.sqlite"
    if not traffic_db.is_file():
        emit("[verify] 无 traffic.sqlite(page 未采集),跳过")
        return {"stage": "verify", "error": "无流量数据(page 未跑)", "failed": True}

    from agentsuite.pipeline.store import FindingsStore
    from agentsuite.tool.data.store import AuditStore
    store = FindingsStore(database_path=Path(ctx.session_dir) / "pipeline" / "agent" / "findings.jsonl")  # findings 表
    traffic = AuditStore(database_path=traffic_db, session_dir=ctx.session_dir)

    stale = traffic.reset_in_progress()
    if stale:
        emit(f"[verify] 恢复 {stale} 个上次未完成的模块(继续验证)")

    sem = ctx.glm_sem
    if sem is None:  # standalone 直调(不经 _run_stages)→ 本地 sem
        sem = asyncio.Semaphore(glm_concurrency_size())
    dispatch_done = ctx.dispatch_done
    if dispatch_done is None:  # standalone 直调(测试):无并发 dispatch 产→即"已产完",排空即止
        dispatch_done = asyncio.Event()
        dispatch_done.set()

    n_workers = glm_concurrency_size()
    emit(f"[verify] 开始验证,{n_workers} 个 worker 并发领模块")

    agg = {"confirmed": 0, "rejected": 0, "inconclusive": 0}

    async def _worker() -> None:
        while True:
            cand = traffic.claim_module()
            if cand is None:
                if dispatch_done.is_set():
                    # 设 done 前最后一刻落的模块:double-check 再 claim 一次防漏
                    cand = traffic.claim_module()
                    if cand is None:
                        return
                else:
                    await asyncio.sleep(0.5)
                    continue
            cid = cand.get("candidate_id", "")
            try:
                async with sem:
                    result = await verify_node.run(ctx, emit, candidate=cand)
                report = result.get("result")
            except Exception as exc:  # noqa: BLE001
                emit(f"[verify] {cid} 验证异常:{type(exc).__name__}: {exc}")
                agg["inconclusive"] += 1
                _mark_candidate_resolved(ctx.session_dir, cand, "resolved")
                continue
            if report is None:
                agg["inconclusive"] += 1
                _mark_candidate_resolved(ctx.session_dir, cand, "resolved")
                continue
            findings = getattr(report, "findings", None) or []
            # findings 为空 → 用 report 本身构造一条 flat finding(skill 取首个输入 skill)
            if not findings:
                status = getattr(report, "status", "inconclusive")
                _pbs = cand.get("skills") or []
                findings = [{
                    "stage": "verify", "status": status,
                    "skill": _pbs[0] if _pbs else "",
                    "title": (_pbs[0] if _pbs else "module"),
                    "summary": getattr(report, "summary", "") or cand.get("notes", ""),
                    "evidence_ids": cand.get("traffic_ids") or [],
                    "confidence": getattr(report, "confidence", 0.0),
                }]
            # verify 终审:所有 verdict 直写 findings 表(severity 由 save_finding 从 summary 标签提)。
            for f in findings:
                w_status = str(f.get("status") or "inconclusive")
                store.save_finding(session_dir=ctx.session_dir, finding={
                    "stage": f.get("stage") or "verify",
                    "status": w_status, "skill": f.get("skill", ""),
                    "title": f.get("title", ""), "summary": f.get("summary", ""),
                    "evidence_ids": f.get("evidence_ids") or [],
                    "confidence": f.get("confidence", 0.0),
                }, source_candidate_id=cid)
                if w_status == "rejected":
                    agg["rejected"] += 1
                    emit(f"[verify] {cid} rejected {f.get('skill','')[:20]} (终审落表)")
                elif w_status == "confirmed":
                    agg["confirmed"] += 1
                    emit(f"[verify] {cid} confirmed {f.get('skill','')[:20]} (终审落表)")
                else:
                    agg["inconclusive"] += 1
                    emit(f"[verify] {cid} inconclusive (终审落表)")
            _mark_candidate_resolved(ctx.session_dir, cand, "resolved")

    await asyncio.gather(*[_worker() for _ in range(n_workers)])
    emit(f"[verify] 终审完成:confirmed={agg['confirmed']} rejected={agg['rejected']} "
         f"inconclusive={agg['inconclusive']}(全落 findings 表)")
    return {"stage": "verify", "confirmed": agg["confirmed"],
            "rejected": agg["rejected"], "inconclusive": agg["inconclusive"]}


async def run_report_stage(ctx: RunContext, emit: Emit) -> dict[str, Any]:
    """读 severity≥low findings + evidence 写 report.md。不重放不判误报(verify 已终审);agent 没写→规则模板 write_session_report 兜底。"""
    report_node = get_node("report")
    if report_node is None:
        emit("[report] report node 未注册,跳过")
        return {"stage": "report", "error": "report node 未注册", "failed": True}

    findings_path = Path(ctx.session_dir) / "pipeline" / "agent" / "findings.jsonl"
    if not findings_path.is_file():
        emit("[report] 无 findings.jsonl(verify 未跑),跳过")
        return {"stage": "report", "error": "无 findings(verify 未跑)", "failed": True}

    from agentsuite.pipeline.store import FindingsStore
    store = FindingsStore(database_path=findings_path)
    findings = store.list_findings(ctx.session_dir)
    from agentsuite.agent.report.runner import reportable_findings
    to_report = reportable_findings(findings)
    emit(f"[report] {len(findings)} 条 finding,待报告(severity≥low)={len(to_report)}")
    if not to_report:
        emit("[report] 无可报告 finding(severity≥low),跳过报告")
        return {"stage": "report", "skipped": True, "reported": 0}

    result = await report_node.run(ctx, emit, findings=findings)
    rep = result.get("result", {}) if isinstance(result.get("result"), dict) else {}

    report_md = Path(ctx.session_dir) / "report" / "report.md"
    if not report_md.is_file():
        try:
            from agentsuite.pipeline.report import write_session_report
            write_session_report(ctx.session_dir)
            emit("[report] agent 未产 report.md,规则模板兜底")
        except Exception as exc:  # noqa: BLE001
            emit(f"[report] 兜底报告失败:{type(exc).__name__}: {exc}")

    return {"stage": "report", "result": rep, "reported": len(to_report)}
