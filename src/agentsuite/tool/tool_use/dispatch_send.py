"""dispatch_send 工具:把可疑流量分发到 verify 深挖(替旧 report 提交)。

dispatch_send 替代旧的 report 提交,把可疑流量分发到下游 verify 深挖。
一次调用打包一个模块(1+ traffic_ids + 1+ skill)写 dispatch_queue 表(幂等)。
"""
from __future__ import annotations
import json
from typing import Any
from claude_agent_sdk import ToolAnnotations, tool
from ..models import RunState
from ..service.dispatch_service import DispatchService

SCHEMA = {
    "type": "object",
    "properties": {
        "traffic_ids": {
            "type": "array", "items": {"type": "string"},
            "description": "req,≥1:要分发相关测试模块需打包的业务流量 id(history:<id>)",
        },
        "skills": {
            "type": "array", "items": {"type": "string"},
            "description": "req:分发目标(漏洞家族 key 如 upload/bucket/idor/fuzz,= skill 目录的 stem)。[]=无 catalog 匹配(novel attack,走 verify 自由模式)。['noise']=噪音丢弃",
        },
        "keys": {
            "type": "array", "items": {"type": "string"}, "maxItems": 5,
            "description": "opt,≤5:证据指针(触发分发的流量内字符串,如 /?getToken / fileId=123)",
        },
        "notes": {"type": "string", "description": "req:一句话分组理由(为什么这几条流量是一包、疑点什么家族)。禁打法步骤(先打X后打Y)——打法赛点归 skill/<stem>.md,verify 读它打。只有 skills=[](novel,目录没覆盖)时 notes 才写思路草案"},
    },
    "required": ["traffic_ids", "skills", "notes"],
    "additionalProperties": False,
}
DESCRIPTION = ("dispatch_send 把可疑流量分发到 verify 深挖(替旧 report 提交)。"
               "traffic_ids[]×skills[] 打包成一个模块写 dispatch_queue 表(幂等,同 traffic_ids 组返回已存 module_id 不重写)。"
               "skills=[]=novel(无 catalog,走 verify 自由);['noise']=丢弃。"
               "返回 {module_id,traffic_ids,skills,keys,notes,status,stripped?}。"
               "traffic_ids 任一不存在→error;keys≤5;notes 必填(一句话分组理由,禁打法;skills=[] novel 时才写思路)")

def make_dispatch_send(service: DispatchService, state: RunState):
    @tool(
        "dispatch_send", DESCRIPTION, SCHEMA,
        annotations=ToolAnnotations(maxResultSizeChars=1024 * 1024),
    )
    async def dispatch_send(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = service.dispatch(
                traffic_ids=[str(t) for t in args["traffic_ids"]],
                skills=[str(p) for p in args.get("skills") or []],
                keys=[str(k) for k in (args.get("keys") or [])],
                notes=str(args.get("notes") or ""),
                state=state,
            )
            return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}
        except ValueError as exc:
            return {"content": [{"type": "text", "text": f"分发失败:{exc}"}], "is_error": True}
    return dispatch_send
