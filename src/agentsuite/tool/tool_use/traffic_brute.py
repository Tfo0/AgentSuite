"""traffic_brute 工具:对某字段批量换值逐个重发,看哪个值让响应变。"""
from __future__ import annotations
import json
from typing import Any
from claude_agent_sdk import ToolAnnotations, tool
from ..models import RunState
from ..service.replay_service import ReplayService

SCHEMA = {
    "type": "object",
    "properties": {
        "traffic_id": {"type": "string", "description": "要改的请求 id:原始 history:<id> 或重放证据(可链式)"},
        "find": {"type": "string", "description": "带键(id=456)自动保键只换值,只值(456)裸替;多次命中不返回"},
        "values": {"type": "array", "items": {"type": "string"}, "description": "候选值表,每值重放一次(≤500)"},
        "stop_on_change": {"type": "boolean", "description": "命中(响应有变化)即停,默认 true"},
        "max_attempts": {"type": "integer", "minimum": 1, "maximum": 500, "description": "封顶,默认 100"},
    },
    "required": ["traffic_id", "find", "values"],
    "additionalProperties": False,
}
DESCRIPTION = ("对一条已采到请求的某字段,批量换一串候选值逐个重发,看哪个值让响应变(测 IDOR 换号/枚举)。\n"
               "三步:① traffic_get(raw=true) 拿 raw ② 抄要换的字段当 find ③ 给 values 值表,逐值重发比对。\n"
               "例:换 id 号测 IDOR → find='id=456' values=['111','222'] → 实发 id=111/id=222(键自动保留)。\n"
               "只改值;置空/删/加字段用 repeater 或 send。")

def make_traffic_brute(service: ReplayService, state: RunState):
    @tool(
        "traffic_brute", DESCRIPTION, SCHEMA,
        # SDK layer-2:单条结果>1MB 落 sidecar,agent 自己 Read 分段读,不撑上下文/不破缓冲
        annotations=ToolAnnotations(maxResultSizeChars=1024 * 1024),
    )
    async def traffic_brute(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = service.replay_brute(
                str(args["traffic_id"]),
                str(args["find"]),
                [str(v) for v in args["values"]],
                stop_on_change=bool(args.get("stop_on_change", True)),
                max_attempts=int(args.get("max_attempts") or 100),
                state=state,
            )
            return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}
        except ValueError as exc:
            return {"content": [{"type": "text", "text": f"爆破失败:{exc}"}], "is_error": True}
    return traffic_brute
