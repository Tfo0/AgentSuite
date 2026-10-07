"""traffic_repeater 工具:改已有请求的一段文本重发看响应。"""
from __future__ import annotations
import json
from typing import Any
from claude_agent_sdk import ToolAnnotations, tool
from ..models import RunState
from ..service.replay_service import ReplayService

SCHEMA = {
    "type": "object",
    "properties": {
        "traffic_id": {"type": "string", "description": "要改的请求 id:原始 history:<id> 或重放证据 repeater:N/brute:N/send:N(可链式)"},
        "find": {"type": "string", "description": "多次命中不返回,尽量一次写全"},
        "replace": {"type": "string", "description": "替换 find 的新文本"},
    },
    "required": ["traffic_id", "find", "replace"],
    "additionalProperties": False,
}
DESCRIPTION = ("类似burpsuite工具中的repeater模块; 通过修改http_raw进行重放测试\n"
               "三步:① traffic_get(raw=true) 拿 raw ② 抄要改的那段当 find ③ 写新段当 replace,本工具重发。\n"
               "加/删字段=整段替换(find 原 body → replace 新 body);replace 空删匹配文本留分隔符尾巴。\n"
             )

def make_traffic_repeater(service: ReplayService, state: RunState):
    @tool(
        "traffic_repeater", DESCRIPTION, SCHEMA,
        # SDK layer-2:单条结果>1MB 落 sidecar,agent 自己 Read 分段读,不撑上下文/不破缓冲
        annotations=ToolAnnotations(maxResultSizeChars=1024 * 1024),
    )
    async def traffic_repeater(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = service.replay_repeater(
                str(args["traffic_id"]),
                args.get("find") or None, args.get("replace") or None,
                state=state,
            )
            return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}
        except ValueError as exc:
            return {"content": [{"type": "text", "text": f"编辑重放失败:{exc}"}], "is_error": True}
    return traffic_repeater
