from __future__ import annotations

from typing import Any

from agentsuite.agent.base import BaseRunner, Emit, RunContext

from agentsuite.tool import load_common_params
from .agent import build_options, MANIFEST
from .models import DispatchResult


class DispatchRunner(BaseRunner):
    """一批 clean 单元的被迫深挖驱动。无浏览器,消费 traffic.sqlite(含 clean)。"""

    async def run_batch(self, session_dir: str,
                        batch: list[dict[str, Any]]) -> list[DispatchResult]:
        out_list = [
            DispatchResult(session_dir=session_dir,
                            traffic_id=str(u.get("request_id") or ""))
            for u in batch
        ]
        if not out_list:
            return out_list
        batch_rids = [o.traffic_id for o in out_list]
        try:
            prompt = self._build_prompt(session_dir, batch)
            self._emit(f"批 {len(batch)} 单元: {batch_rids}")

            result_text, structured, state = await self._drive(
                build_options_fn=lambda resume_id=None: build_options(
                    session_dir, batch_rids=batch_rids,
                    max_turns=self.max_turns,
                    session_timeout_s=self.session_timeout_s,
                    allow_mutating=self.allow_mutating,
                    emit=self._emit,
                    resume=resume_id,
                ),
                user_prompt=prompt,
                tag="dispatch",
            )
            self._resolve(result_text, structured, state, batch, out_list)
            for o in out_list:
                self._emit(f"单元 {o.traffic_id} status={o.status} "
                           f"severity={o.severity} tested={o.tested} evidence={len(o.evidence_ids)}")
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
            self._emit(f"批异常 {err}")
            for o in out_list:
                o.error = err
                o.status = "inconclusive"
                o.summary = err
        return out_list

    def _build_prompt(self, session_dir: str, batch: list[dict[str, Any]]) -> str:
        """组装本批 user prompt:纯数据(session_dir + 单元字段 + 公共参数实例)+ 一句触发语。

        所有规则(打包/skills/keys/notes/笛卡尔/noise/novel/公共参数判定+勿打包+剥离/
        覆盖率门禁/分发器角色/dispatch_send 返回值)在 system prompt(prompt.md),
        本方法不复制规则正文——system prompt 直接注入(ClaudeAgentOptions.system_prompt),
        agent 每批都带,不必在 user prompt 重述。"""
        lines = [f"流量会话目录:{session_dir}", "",
                 f"## 本批 {len(batch)} 个单元(clean 最小视图)"]
        for i, unit in enumerate(batch, 1):
            tid = unit.get("request_id", "")  # clean 的 request_id = traffic_id(history:<id>)
            lines += [
                f"### 单元 {i}",
                f"traffic_id: {tid}",
                f"method: {unit.get('method', '')}  host: {unit.get('host', '')}  path: {unit.get('path', '')}",
                f"query: {unit.get('query', '')}",
                f"json_body: {unit.get('json_body', '')}",
                f"form_body: {unit.get('form_body', '')}",
                f"response(嵌套键无值): {unit.get('response', '')}",
                f"status: {unit.get('status', '')}",
                "",
            ]
        # 本批公共参数实例(规则——判定/勿打包/剥离——在 system prompt)
        common = load_common_params(session_dir)
        if common:
            by_host: dict[str, list[dict]] = {}
            for p in common:
                by_host.setdefault(p.get("host", ""), []).append(p)
            cp_lines = []
            for h, ps in by_host.items():
                keys_str = "、".join(f"{p.get('key')}({p.get('freq', 0) * 100:.0f}%)"
                                     for p in ps)
                cp_lines.append(f"- {h}: {keys_str}")
            lines += ["## 本批公共参数(系统统计实例,规则见 system prompt)",
                      "\n".join(cp_lines), ""]
        lines.append(
            f"把这 {len(batch)} 个单元按 system prompt 规则调 dispatch_send 打包入队。"
        )
        return "\n".join(lines)

    def _resolve(self, result_text: str, structured: Any, state,
                 batch: list[dict[str, Any]],
                 out_list: list[DispatchResult]) -> None:
        """从 state.dispatched 映射每条 unit → DispatchResult(不再落盘)。非 noise 模块覆盖→hit(skill=首个非 noise skill);只 noise 覆盖→skip;未覆盖→inconclusive(门禁应已挡住,防御兜底)。tested=state.replays 非空。"""
        modules = [m for m in (state.dispatched or []) if isinstance(m, dict)]
        if modules:
            self._emit(f"分发器打包 {len(modules)} 个模块")
        # rid → [覆盖它的模块](同 rid 可能被多模块覆盖)
        by_rid: dict[str, list[dict]] = {}
        for m in modules:
            for tid in (m.get("traffic_ids") or []):
                by_rid.setdefault(str(tid), []).append(m)

        replay_ids = {str(r.get("replay_id")) for r in (state.replays or []) if r.get("replay_id")}
        tested = bool(replay_ids)

        for unit, out in zip(batch, out_list):
            rid = out.traffic_id
            cov = by_rid.get(rid)
            if not cov:
                out.status = "inconclusive"
                out.summary = "本单元未被任何模块覆盖(agent 未打包它)"
                out.tested = tested
                out.evidence_ids = []
                continue
            lead = None
            for m in cov:
                pbs = m.get("skills") or []
                if pbs == ["noise"] or str(m.get("status") or "") == "dropped":
                    continue
                lead = m
                break
            if lead is not None:
                pbs = lead.get("skills") or []
                skill = next((str(p) for p in pbs if p and p != "noise"), "novel")
                out.status = "hit"
                out.severity = "high"
                out.skill = skill
                out.summary = str(lead.get("notes") or "")
                # evidence_ids:本单元 traffic_id + 本单元重放证据(source_id==rid)
                evid: list[str] = [rid]
                for r in (state.replays or []):
                    if str(r.get("source_id") or "") == rid:
                        rid_eid = str(r.get("replay_id") or "")
                        if rid_eid:
                            evid.append(rid_eid)
                seen: set[str] = set()
                out.evidence_ids = []
                for e in evid:
                    if e and e not in seen:
                        seen.add(e)
                        out.evidence_ids.append(e)
                out.tested = tested
            else:
                out.status = "skip"
                out.summary = "noise(打成 noise 模块,不进 verify)"
                out.tested = tested
                out.evidence_ids = []


async def run_dispatch(
    session_dir: str,
    batch: list[dict[str, Any]],
    *,
    max_turns: int = 12,
    session_timeout_s: int = 300,
    allow_mutating: bool = True,
    on_event: Any = None,
) -> list[DispatchResult]:
    """node 稳定接口:传 session_dir + batch(clean 行,pack_units 打包)→ list[DispatchResult]。前置:traffic.sqlite + build_clean 已跑(batch 来自 list_clean)。"""
    runner = DispatchRunner(
        max_turns=max_turns, session_timeout_s=session_timeout_s,
        allow_mutating=allow_mutating, on_event=on_event,
    )
    return await runner.run_batch(session_dir, batch)


async def run_from_ctx(ctx: RunContext, emit: Emit,
                       batch: list[dict[str, Any]]) -> dict[str, Any]:
    """node 稳定接口(ctx→runner 适配):研判一批 clean 单元,返回 list[DispatchResult]。编排层拿去统计 hit/skip/inconclusive;模块候选已由 dispatch agent 调 dispatch_send 直接写 dispatch_queue 交 verify。"""
    results = await run_dispatch(
        ctx.session_dir, batch,
        max_turns=ctx.dispatch_max_turns,
        session_timeout_s=ctx.dispatch_timeout,
        allow_mutating=ctx.traffic_allow_mutating,
        on_event=lambda m: emit(f"[dispatch] {m}"),
    )
    return {"stage": "dispatch", "results": results}


class _DispatchNode:
    manifest = MANIFEST
    run = staticmethod(run_from_ctx)


NODE = _DispatchNode
