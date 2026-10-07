"""traffic_diff 工具:diff 任意两流量已存响应(替 with_diff/baseline_id)。

读两份已存响应(history 表 response_json / 证据 response_json)比对,不重发请求。
替 repeater 的 with_diff + send 的 baseline_id——可 diff 任意两 id,不只 baseline-vs-edit。
"""
from __future__ import annotations
import json
from typing import Any
from claude_agent_sdk import ToolAnnotations, tool
from ..service.query_service import QueryService

SCHEMA = {
    "type": "object",
    "properties": {
        "baseline_id": {"type": "string", "description": "基准流量 id(history:<id> 或 repeater:N/brute:N/send:N/...)"},
        "candidate_id": {"type": "string", "description": "对照流量 id(任意,同 baseline 则空 diff)"},
    },
    "required": ["baseline_id", "candidate_id"],
    "additionalProperties": False,
}
DESCRIPTION = ("diff 任意两流量已存响应(不重发)。返 {status_diff:'200 vs 401', body_diff:unified diff,"
               " time_diff:'120ms vs 90ms'(history 无 timing→n/a), baseline_size, candidate_size}。"
               "同 id→空 diff;id 不存在→error;二进制 body→body_diff 跳过只 size;响应相同→empty diff。"
               "IDOR 检测:traffic_diff(baseline_id=history:N, candidate_id=repeater:N)")

def make_traffic_diff(service: QueryService):
    @tool(
        "traffic_diff", DESCRIPTION, SCHEMA,
        annotations=ToolAnnotations(maxResultSizeChars=1024 * 1024),
    )
    async def traffic_diff(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = service.diff_traffic(
                str(args["baseline_id"]), str(args["candidate_id"]),
            )
            return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}
        except ValueError as exc:
            return {"content": [{"type": "text", "text": f"diff 失败:{exc}"}], "is_error": True}
    return traffic_diff
