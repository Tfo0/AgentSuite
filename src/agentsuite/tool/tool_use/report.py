"""report 工具:提交一个 skill 的统一 verdict(精简 schema),verify 注册 verify_report。

stage 写死 verify——工具名已表明环节,agent 不传 stage(替旧 stage 参数)。类似
dispatch_send(dispatch 专属工具名带 agent 归属)。每次调用 = 一个 skill 的结论落成一条
artifact。两功能合一:
(a)防幻觉锚——逼 LLM 经此工具提交带证据的结论(gate 在 report_service 校验
    evidence_ids 引用真实存在于流量库);
(b)结构化产物——本次调用即落 state.findings 的一条 artifact 行(不另开输出通道)。

verdict 单元 = **一个 skill**(模块隐含):一个 skill 可能要多个 traffic_id 才能体现,
这些 traffic_id 进 evidence_ids,故不另设 traffic_id 字段。精简 verdict schema(4 字段,
全必填):
{skill, status, summary, evidence_ids}。
- skill:本结论针对的攻击方向(idor/sqli/info-leak/...;替旧 family,整条 finding 一个);
- status:机器可读结论{confirmed/rejected/inconclusive};severity 不在此——靠 summary
  开头标 [严重]/[高]/[中]/[低]/[无],系统 _extract_severity 提取(report_agent 信 verify 的);
- summary:人读汇总(结论+危害/为什么不成立,吸收旧 per-evidence reason);tested 删除
  (status 已隐含:confirmed/rejected=测过,inconclusive=未定论);
- evidence_ids:证据 traffic_id 列表(引用 DB 真实流量)。noise/skip 已并入 rejected,
  故 confirmed/inconclusive 须非空 evidence_ids(证据锚定防幻觉),rejected 可空。

proof(original/verification)不再内联提交——重放工具(traffic_repeater/brute/send)
产 evidence 落 traffic.sqlite evidence 表,verdict 只引用 evidence_ids。
"""
from __future__ import annotations
import json
from typing import Any
from claude_agent_sdk import tool
from ..models import RunState
from ..service.report_service import ReportService

SCHEMA = {
    "type": "object",
    "properties": {
        "skill": {
            "type": "string",
            "description": "本结论针对的攻击方向/漏洞家族(idor/sqli/info-leak/...;替旧 family)。"
            "穷尽每个输入 skill——dispatch 给的 skills 里每个 skill 都要走完整流程后提交一条 verdict",
        },
        "status": {
            "type": "string",
            "enum": ["confirmed", "rejected", "inconclusive"],
            "description": "机器可读结论。confirmed=证实漏洞;rejected=误报/无危害;"
            "inconclusive=有差异但无法判定(没测完的 skill 标这个,不能当 rejected)",
        },
        "summary": {
            "type": "string",
            "description": "人读汇总(证明了什么危害/为什么不成立),开头标 [严重]/[高]/[中]/[低]/[无]"
            "定级标签(系统据此提取 severity,report_agent 不重新定级)",
        },
        "evidence_ids": {
            "type": "array",
            "items": {"type": "string"},
            "description": "证据 traffic_id 列表(repeater:N/history:N/brute:N/send:N,引用 DB 真实流量)。"
            "一个 skill 可引多条(多流量才能体现)。rejected 可空;confirmed/inconclusive 须非空"
            "(证据锚定防幻觉)。重放工具产的证据直接引用其 id,不再内联 original/verification proof",
        },
    },
    "required": ["skill", "status", "summary", "evidence_ids"],
    "additionalProperties": False,
}
DESCRIPTION = (
    "提交本环节一个 skill 的 verdict。skill 定攻击方向,status 是结论,"
    "summary 开头标 [严重]/[高]/[中]/[低]/[无] 定级(系统提取 severity),evidence_ids 引用 DB 真实流量"
    "(repeater:N/history:N 等,否则被 evidence_exists 门禁拒)。rejected 可空 evidence_ids;"
    "confirmed/inconclusive 须非空。每个输入 skill 都要提交一条 verdict(没测的标 inconclusive)。"
)


def make_report(service: ReportService, state: RunState, *, name: str, stage: str):
    """建 report 工具。name=工具名(verify_report),stage=写死的环节(工具名已表明,agent 不传 stage)。"""
    @tool(name, DESCRIPTION, SCHEMA)
    async def report(args: dict[str, Any]) -> dict[str, Any]:
        try:
            finding = service.add_finding(
                stage=stage,
                skill=args["skill"],
                status=args["status"],
                summary=args["summary"],
                evidence_ids=args.get("evidence_ids") or [],
                state=state,
            )
            return {"content": [{"type": "text", "text": json.dumps(finding, ensure_ascii=False)}]}
        except ValueError as exc:
            return {"content": [{"type": "text", "text": f"提交 report 失败:{exc}"}], "is_error": True}
    return report
