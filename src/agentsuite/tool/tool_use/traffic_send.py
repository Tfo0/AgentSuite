"""traffic_send 工具:从零构造请求重放(kind 驱动 body,host/path/query 拆分)。

设计=生成 vs 填:不让 agent 生成规范 HTTP body 串(escape/boundary/编码静默错),
而是有 schema 让 agent 填(kind+value),工具序列化 + CT 配对。三级阶梯:
  Tier1 kind 驱动(json/form/multipart,工具兜序列化+CT)→
  Tier2 text(原样,agent 自设 CT,逃生口)→
  Tier3 Bash(绕过 traffic 仪表,断证据链,见 prompt 约束)。
send 让常见 case 停在 Tier1(有 evidence),agent 只在被逼时爬到 Tier3。

★砍了 baseline_id:不再内置 baseline 对照。要 diff 原始流量 → 调 traffic_diff
(baseline_id=history:N, candidate_id=返回的 send:N) 读两份已存响应比。
"""
from __future__ import annotations
import json
from typing import Any
from claude_agent_sdk import ToolAnnotations, tool
from agentsuite.proxy.http import HttpBody, HttpHeader, HttpRequest
from ..models import RunState
from ..service.body_encoder import encode_body
from ..service.replay_service import ReplayService

SCHEMA = {
    "type": "object",
    "properties": {
        "method": {"type": "string", "description": "HTTP 方法(GET/POST/PUT/PATCH/DELETE/...)"},
        "scheme": {"type": "string", "enum": ["http", "https"], "description": "默认 https", "default": "https"},
        "host": {"type": "string", "description": "主机名(如 scm.bytedance.com),不含 scheme/path"},
        "path": {"type": "string", "description": "路径(如 /api/getUsrInfo),以 / 开头"},
        "query": {"type": "string", "description": "query string(如 key=123&page=1),不含 ?。v1 string(agent 构造);dict 待定"},
        "headers": {
            "type": "object",
            "description": "请求头 {name: value}。Content-Type 由 body.kind 自动配"
                           "(json/form/multipart 自动;kind=text 时才需此处自设)。HTTP/2 伪头自动剥。Cookie/Authorization 都在此",
        },
        "body": {
            "type": "object",
            "description": "请求体(kind 驱动序列化+Content-Type 配对,灭手写 JSON/form/multipart 串的"
                           "escape/CT 配错静默失败)。kind 决定 value 形状:"
                           "json=dict/list;form=dict 或 [[k,v]...];text=string(原样发,自设 CT);"
                           "multipart=parts 列表,每项 {name, value(文本 part)|file_path(文件 part),"
                           "filename?,content_type?}",
            "properties": {
                "kind": {"type": "string", "enum": ["json", "form", "text", "multipart"]},
                "value": {"description": "按 kind 定:dict/list/string/parts[](省略=空 body)"},
            },
            "required": ["kind"],
        },
    },
    "required": ["method", "host", "path"],
    "additionalProperties": False,
}
DESCRIPTION = ("从零拼请求发出去——repeater 搞不定的:改 method(易歧义)/删 header(留空头)/body kind 序列化(multipart/嵌套 JSON/换 CT)/从零发无 base(测没采到的端点)。进证据链产 send:N(Bash curl 不进证据链别用)。\n"
              "三步:① 抄原流量 method/host/path 或从零构造 ② 填 query/headers ③ body.kind 驱动序列化(json/form/multipart/text)+ CT 自动配。\n"
              "产 send:N;和原流量比差异调 traffic_diff(baseline_id, candidate_id=send:N)。")

def make_traffic_send(service: ReplayService, state: RunState):
    @tool(
        "traffic_send", DESCRIPTION, SCHEMA,
        # SDK layer-2:单条结果>1MB 落 sidecar,agent 自己 Read 分段读,不撑上下文/不破缓冲
        annotations=ToolAnnotations(maxResultSizeChars=1024 * 1024),
    )
    async def traffic_send(args: dict[str, Any]) -> dict[str, Any]:
        try:
            headers = tuple(
                HttpHeader(str(k), str(v)) for k, v in (args.get("headers") or {}).items()
            )
            body_arg = args.get("body")
            body = None
            if body_arg and body_arg.get("kind"):
                kind = str(body_arg["kind"])
                value = body_arg.get("value")
                display_text, raw_bytes, ct = encode_body(kind, value)
                # kind 驱动 CT:覆盖 headers 里已有的 Content-Type(灭 body/CT 不一致静默失败)。
                # text kind ct=None → 不动 headers,agent 自设(逃生口)。
                if ct is not None:
                    headers = (*tuple(h for h in headers if h.name.casefold() != "content-type"),
                               HttpHeader("Content-Type", ct))
                body = HttpBody(text=display_text, content_type=ct, raw_bytes=raw_bytes)
            # scheme+host+path+query 拼 url(query string 原样拼,agent 自负责编码)
            scheme = str(args.get("scheme") or "https")
            host = str(args["host"])
            path = str(args["path"] or "/")
            query = str(args.get("query") or "")
            url = f"{scheme}://{host}{path}"
            if query:
                url += "?" + query
            request = HttpRequest(
                method=str(args["method"]), url=url,
                headers=headers, body=body,
            )
            result = service.replay_send(request, state=state)
            return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}
        except ValueError as exc:
            return {"content": [{"type": "text", "text": f"自由发包失败:{exc}"}], "is_error": True}
    return traffic_send
