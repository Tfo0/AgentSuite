"""traffic_get 工具:读单条流量。raw 布尔切形态——true(默认)返 http_raw 文本
(repeater 抄一段当 find),false 返结构化(send 拼接/看响应)。section 选段。

存储是 store shape(HttpRequest.to_dict());raw 模式直接 to_raw_http 渲染现场拼,
结构化模式工具层翻译成统一对象(agent 可见三位一体)。二选一不重复。
"""
from __future__ import annotations
import json
from typing import Any
from claude_agent_sdk import ToolAnnotations, tool
from ..service.query_service import QueryService, _DEFAULT_BODY_LIMIT, unify_request, unify_response

SCHEMA = {
    "type": "object",
    "properties": {
        "traffic_id": {"type": "string", "description": "history:<id>(原始) 或 repeater:N/brute:N/send:N(证据)"},
        "section": {"type": "string", "enum": ["all", "request", "response"], "description": "读取段,默认 all。raw=true 时:request→只请求包 / response→只响应包 / all→请求包+空行+响应包"},
        "raw": {"type": "boolean", "description": "默认 true。true=返 http_raw 文本;false=返结构化", "default": True},
        "offset": {"type": "integer", "description": "raw=true→对整条 raw 文本的字符偏移;raw=false→对 response.body 偏移。默认 0,镜像 harness Read 翻页", "default": 0},
        "limit": {"type": "integer", "description": "最多返回字符数,默认 32768(32KB)。raw=true→raw 截断看 raw_truncated;raw=false→response.body 截断看 body_truncated。0 或负=全量(逃生口)", "default": 32768},
    },
    "required": ["traffic_id"],
    "additionalProperties": False,
}
DESCRIPTION = ("读单条流量。raw=true(默认)返 http_raw 文本(section 选 request/response/all);"
               "raw=false 返结构化(method/host/path/query/headers/body + 响应 body 分页)。"
               "大响应默认 32KB,看 raw_truncated/body_truncated=true 就 offset+=limit 翻页。")

def make_traffic_get(service: QueryService):
    @tool(
        "traffic_get", DESCRIPTION, SCHEMA,
        # SDK layer-2:单条结果>1MB(大 raw/响应体)落 sidecar,agent 自己 Read 分段读,不撑上下文/不破缓冲
        annotations=ToolAnnotations(maxResultSizeChars=1024 * 1024),
    )
    async def traffic_get(args: dict[str, Any]) -> dict[str, Any]:
        try:
            _limit = args.get("limit")
            result = service.get_traffic(
                str(args["traffic_id"]),
                section=str(args.get("section") or "all"),
                raw=bool(args.get("raw", True)),
                offset=int(args.get("offset") or 0),
                limit=int(_limit) if _limit is not None else _DEFAULT_BODY_LIMIT,
            )
            result["traffic_id"] = result.pop("id")
            # raw 模式已返 {raw,raw_total,raw_truncated}(无 request/response 键,下方 if 天然跳过);
            # 结构化模式翻译 store shape → note 统一对象(agent 可见三位一体)
            if "request" in result:
                result["request"] = unify_request(result["request"])
            if "response" in result:
                result["response"] = unify_response(result["response"])
            return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}
        except ValueError as exc:
            return {"content": [{"type": "text", "text": f"读取失败:{exc}"}], "is_error": True}
    return traffic_get
