from __future__ import annotations

import json
import re
from typing import Any

from agentsuite.agent.base import BaseRunner, Emit, RunContext

from agentsuite.tool import load_common_params

from .agent import build_options, MANIFEST
from .models import TrafficReport, TRAFFIC_STATUSES

# 兼容 ```traffic 和 ```json 代码块(fallback 文本提取用)
_REPORT_RE = re.compile(r"```(?:traffic|json)\s*\n(.*?)\n```", re.DOTALL)


class VerifyRunner(BaseRunner):
    """流量分析重放驱动。无浏览器,消费 sqlite;不继承浏览器 runner 基类,直调 drive_with_resume,state.findings 收尾。"""

    async def run_verify(self, session_dir: str, candidate: dict | None = None) -> TrafficReport:
        """验证一组候选:读 traffic_ids 原始流量,变异重放比对下结论。candidate=None→全量扫描(旧兼容);有 candidate→只验证这组不发散。"""
        report = TrafficReport(session_dir=session_dir)
        try:
            if candidate is not None:
                cand_ids = candidate.get("traffic_ids") or []
                cand_pbs = candidate.get("skills") or []
                cid = candidate.get("candidate_id") or candidate.get("module_id") or ""
                self._emit(f"验证模块 {cid} ({len(cand_pbs)} skill × {len(cand_ids)} 条流量)")
            else:
                self._emit(f"全量扫描模式(自发现),读取 {session_dir}/traffic 流量")
            prompt = self._build_prompt(session_dir, candidate)

            result_text, structured, state = await self._drive(
                build_options_fn=lambda resume_id=None: build_options(
                    session_dir, max_turns=self.max_turns,
                    session_timeout_s=self.session_timeout_s,
                    allow_mutating=self.allow_mutating,
                    emit=self._emit,
                    resume=resume_id,
                    candidate_traffic_ids=(candidate.get("traffic_ids")
                                            if candidate else None),
                    candidate_skills=(candidate.get("skills")
                                      if candidate else None),
                ),
                user_prompt=prompt,
                tag="verify",
            )
            report.raw_result = result_text
            # 无 output_format→structured 恒 None;主路径 state.findings(verify_report 落),逐条 _normalize_finding 喂 stages。
            if state.findings:
                self._emit(f"验证产出 {len(state.findings)} 条结论")
                report.findings = [self._normalize_finding(f) for f in state.findings if isinstance(f, dict)]
            else:
                self._emit("结构化取结论失败,回退文本解析")
                self._parse_verdict(result_text, report)
            report._normalize_worst()
            report.replays_total = len(state.replays) if state.replays else 0
            self._emit(f"findings={len(report.findings)} status={report.status} replays={report.replays_total}")
        except Exception as exc:  # noqa: BLE001
            report.error = f"{type(exc).__name__}: {exc}"
            report.status = "inconclusive"
            report.summary = report.error
            self._emit(f"分析异常 {report.error}")
        return report

    def _build_prompt(self, session_dir: str, candidate: dict | None) -> str:
        """组装本模块 user prompt:纯数据(candidate JSON + 公共参数实例)+ 一句触发语。

        所有规则(穷尽 skill 工作流/verdict 判定/evidence 归属门禁/公共参数判定+勿当越权指针+可覆盖
        /定级映射)在 system prompt(prompt.md),本方法不复制规则正文——system prompt 直接注入
        (ClaudeAgentOptions.system_prompt,且 {SKILL_DIR} 占位符由 build_traffic_options 替换为
        skill 目录绝对路径),agent 每模块都带,不必在 user prompt 重述。"""
        if candidate is None:
            return ("全量扫描模式(无 dispatch 模块):自行从全部流量发现可疑点,"
                    "按 system prompt 规则用工具重放验证,verify_report 提交 verdict。")
        cand_desc = json.dumps(candidate, ensure_ascii=False, indent=2)
        lines = [
            "## 待验证模块(dispatch 打包)",
            f"```\n{cand_desc}\n```",
        ]
        # 本模块公共参数实例(规则——判定/勿当越权指针/可覆盖——在 system prompt)
        common = load_common_params(session_dir)
        if common:
            by_host: dict[str, list[dict]] = {}
            for p in common:
                by_host.setdefault(p.get("host", ""), []).append(p)
            cp_lines = "\n".join(
                f"- {h}: " + "、".join(
                    f"{p.get('key')}({p.get('freq', 0) * 100:.0f}%)" for p in ps)
                for h, ps in by_host.items())
            lines += ["", "## 本模块公共参数(系统统计实例,规则见 system prompt)", cp_lines]
        lines += ["",
                  "按 system prompt 规则穷尽 skill 思路重放验证这一个模块,verify_report 提交 verdict。"]
        return "\n".join(lines)

    def _normalize_finding(self, f: dict) -> dict:
        """finding → flat verdict 喂 stages。主路径:state.findings 已是 flat(verify_report 4 字段),pass-through + skill 取值;兼容文本 fallback 的旧 nested verdict→flat(severity/tested 不在此,save_finding 从 summary 标签提 severity)。"""
        if isinstance(f.get("verdict"), dict):
            verdict = f["verdict"]
            status = self._map_status(str(verdict.get("status") or "inconclusive"))
            v_summary = str(verdict.get("summary") or "")
            evs = f.get("evidence") or []
            lead = evs[0] if (isinstance(evs, list) and evs and isinstance(evs[0], dict)) else {}
            skill = str(lead.get("finding_type") or "")
            lead_reason = str(lead.get("reason") or "")
            summary = " | ".join(p for p in (lead_reason, v_summary) if p)
            return {
                "finding_id": str(f.get("finding_id") or ""),
                "stage": str(f.get("stage") or "verify"),
                "skill": skill,
                "title": summary or skill,
                "summary": summary,
                "evidence_ids": self._collect_ids(f),
                "confidence": self._status_confidence(status),
            }
        status = self._map_status(str(f.get("status") or "inconclusive"))
        skill = str(f.get("skill") or "")
        summary = str(f.get("summary") or "")
        ids = f.get("evidence_ids") or []
        confidence = float(f.get("confidence") or 0.0) or self._status_confidence(status)
        return {
            "finding_id": str(f.get("finding_id") or ""),
            "stage": str(f.get("stage") or "verify"),
            "skill": skill,
            "title": str(f.get("title") or "") or summary or skill,
            "summary": summary,
            "evidence_ids": [str(i) for i in ids] if isinstance(ids, list) else [],
            "confidence": confidence,
        }

    def _map_status(self, status: str) -> str:
        """status → TRAFFIC_STATUSES。noise/skip→rejected(非漏洞误报);不在枚举→inconclusive。"""
        s = str(status or "").strip().casefold()
        if s in TRAFFIC_STATUSES:
            return s
        if s in ("noise", "skip"):
            return "rejected"
        return "inconclusive"

    @staticmethod
    def _collect_ids(finding: dict) -> list[str]:
        """旧 nested schema 收集 id 引用(文本 fallback 兼容;flat 主路径直接用 evidence_ids 不走这)。"""
        ids: list[str] = []
        for lead in (finding.get("evidence") or []):
            if not isinstance(lead, dict):
                continue
            rid = str(lead.get("request_id") or "").strip()
            if rid:
                ids.append(rid)
            for key in ("original", "verification"):
                proof = lead.get(key)
                if not isinstance(proof, dict):
                    continue
                for sub in ("payload", "response"):
                    s = proof.get(sub)
                    if isinstance(s, dict) and str(s.get("kind") or "") == "id":
                        v = str(s.get("value") or "").strip()
                        if v:
                            ids.append(v)
        return list(dict.fromkeys(ids))

    @staticmethod
    def _status_confidence(status: str) -> float:
        return {"confirmed": 1.0, "rejected": 0.0, "inconclusive": 0.5,
                "noise": 0.0, "skip": 0.0}.get(str(status), 0.0)

    def _parse_verdict(self, result_text: str, report: TrafficReport) -> None:
        """从模型文本解析 ```traffic JSON 块(fallback)。兼容 {findings:[...]}(多条)和旧单 finding 两种格式。"""
        match = _REPORT_RE.search(result_text)
        if match is None:
            report.findings = [{
                "finding_id": "001", "stage": "verify",
                "status": "inconclusive", "skill": "", "title": "",
                "summary": "模型未输出结构化结论,原文见 raw_result",
                "evidence_ids": [], "confidence": 0.0,
            }]
            return
        raw_block = match.group(1).strip()
        data = None
        try:
            data = json.loads(raw_block)
        except json.JSONDecodeError:
            try:
                from json_repair import repair_json
                repaired = repair_json(raw_block, return_objects=True)
                data = repaired if isinstance(repaired, dict) else None
            except Exception:
                data = None
            if data is None:
                report.findings = [{
                    "finding_id": "001", "stage": "verify",
                    "status": "inconclusive", "skill": "", "title": "",
                    "summary": "结论块 JSON 解析失败,原文见 raw_result",
                    "evidence_ids": [], "confidence": 0.0,
                }]
                return
        if isinstance(data.get("findings"), list):
            report.findings = [self._normalize_finding(f) for f in data["findings"] if isinstance(f, dict)]
        else:
            report.findings = [self._normalize_finding(data)]


async def run_verify(
    session_dir: str,
    *,
    max_turns: int = 30,
    session_timeout_s: int = 600,
    allow_mutating: bool = True,
    on_event: Any = None,
    candidate: dict | None = None,
) -> TrafficReport:
    """node 稳定接口:传 session_dir + 配置 + candidate → TrafficReport。前置:traffic.sqlite 已落地。candidate=None→全量扫描(旧兼容);candidate=dict→只验证这组不发散。"""
    runner = VerifyRunner(
        max_turns=max_turns, session_timeout_s=session_timeout_s,
        allow_mutating=allow_mutating, on_event=on_event,
    )
    return await runner.run_verify(session_dir, candidate=candidate)


async def run_from_ctx(ctx: RunContext, emit: Emit,
                       candidate: dict | None = None) -> dict[str, Any]:
    """node 稳定接口(ctx→runner 适配):验证一组候选返回 TrafficReport。candidate=None→全量扫描(旧兼容);candidate=dict→只验证这组(traffic_ids)不发散。"""
    result = await run_verify(
        ctx.session_dir,
        max_turns=ctx.traffic_max_turns,
        session_timeout_s=ctx.traffic_timeout,
        allow_mutating=ctx.traffic_allow_mutating,
        on_event=lambda m: emit(f"[verify] {m}"),
        candidate=candidate,
    )
    return {"stage": "verify", "result": result}


class _VerifyNode:
    manifest = MANIFEST
    run = staticmethod(run_from_ctx)


NODE = _VerifyNode
