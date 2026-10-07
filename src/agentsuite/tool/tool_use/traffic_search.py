"""traffic_search 工具:全局子串搜 history(request+response 全文本),返命中行+片段。

upstream-tracing 用:流量 A 用了不可遍历 id X(UUID/密文),一次 search(X) 找哪个流量
的 response 里出现过 X → X 来源流量 B;再看 B 的请求参数可否遍历。替 O(N) 次 traffic_get
翻找。返投影(命中行 + 命中点 ±80 字符片段),不返全文——拿 traffic_id 再 traffic_get 详读。
"""
from __future__ import annotations
import json
from typing import Any
from claude_agent_sdk import ToolAnnotations, tool
from ..service.query_service import QueryService

SCHEMA = {
    "type": "object",
    "properties": {
        "search": {"type": "string", "description": "子串(非正则),搜 history 的 request+response 全文本"},
        "page_no": {"type": "integer", "description": "页码(默认 1)"},
        "page_size": {"type": "integer", "description": "每页条数(默认 20,上限 30)"},
    },
    "required": ["search"],
    "additionalProperties": False,
}
DESCRIPTION = ("全局子串搜 history(request+response 全文本),返命中行+片段。"
               "填 search 子串 → 返 {total, items:[{traffic_id, method, host, path, status, "
               "matched_in:[request|response], fragment}]},matched_in 标命中在 request 还是 "
               "response(response 命中=该流量响应里带过这个 id,upstream-tracing 找来源)。"
               "upstream-tracing:流量用了不可遍历 id X,search(X) 找哪个流量的 response 出现过 X "
               "→ 来源流量,再 traffic_get 看其请求参数能否遍历。拿 traffic_id 详读用 traffic_get。")

def make_traffic_search(service: QueryService):
    @tool(
        "traffic_search", DESCRIPTION, SCHEMA,
        annotations=ToolAnnotations(maxResultSizeChars=1024 * 1024),
    )
    async def traffic_search(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = service.search_traffic(
                str(args["search"]),
                page_no=int(args.get("page_no") or 1),
                page_size=int(args.get("page_size") or 20),
            )
            return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}
        except ValueError as exc:
            return {"content": [{"type": "text", "text": f"search 失败:{exc}"}], "is_error": True}
    return traffic_search
