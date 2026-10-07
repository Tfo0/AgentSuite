"""HTTP 交换 DTO:录制 store 与 tool traffic 能力共享的契约。

放 service(平级 mcp 的纯逻辑库)而非 mcp/traffic,是为了让 mcp/page 和
mcp/traffic 两个能力包互不依赖:page 只从 service 取 DTO,不 import mcp.traffic;
反之亦然。service 是更底层的能力库,mcp 调它合理。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class HttpHeader:
    name: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "value": self.value}


@dataclass(frozen=True)
class HttpBody:
    text: str | None = None
    content_type: str | None = None
    file_path: str | None = None
    truncated: bool = False
    # raw_bytes:send-only 透传,不落盘。kind 驱动 body(json/form/multipart)的真实
    # 发送 bytes(文件二进制 + utf-8 文本);text kind 留 None → send 走 .text(= 方案A
    # 行为,agent 全控编码)。to_dict 跳过它 → store 存/traffic_get 显的是 text
    # (display form,文件 part 占位 [FILE N bytes]),raw_bytes 不进 DB / 不撑 1MB ceiling。
    raw_bytes: bytes | None = None

    def to_dict(self) -> dict[str, Any]:
        # 手动排除 raw_bytes:它是 send-only,不落盘(asdict 会带它 → 二进制灌进 TEXT 列)。
        return {
            "text": self.text,
            "content_type": self.content_type,
            "file_path": self.file_path,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: tuple[HttpHeader, ...] = ()
    body: HttpBody | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": [header.to_dict() for header in self.headers],
            "body": self.body.to_dict() if self.body else None,
        }


@dataclass(frozen=True)
class HttpResponse:
    status: int
    reason: str = ""
    headers: tuple[HttpHeader, ...] = ()
    body: HttpBody | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "headers": [header.to_dict() for header in self.headers],
            "body": self.body.to_dict() if self.body else None,
        }


@dataclass(frozen=True)
class HttpExchange:
    exchange_id: str
    request: HttpRequest
    response: HttpResponse | None = None
    source: str = "unknown"
    raw_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

def strip_pseudo_headers(headers: dict[str, str]) -> dict[str, str]:
    """剥 HTTP/2 伪头(`:method`/`:path`/`:scheme`/`:authority`/`:status` 等 `:` 开头的)。

    录制源的全量头可能把 HTTP/2 帧伪头当普通头泄进来,存进
    traffic.sqlite 后,HTTP/1.1 重放(requests)把它们当普通头发 → 非法 → 重放失败
    (agent 被迫手抄 headers 绕开 baseline)。在采集点(recorder)和发送点
    (replay_service send)都剥一次:采集点让存储/traffic_get 干净,发送点是兜底
    (旧库 + agent 自抄 headers 都 cover)。`:status` 是响应伪头(请求侧无),一并剥。
    """
    return {k: v for k, v in headers.items() if not k.startswith(":")}


# ── 原始 HTTP 文本还原(给人 review 数据包)──────────────────────────────────
# 从 get_traffic 返回的 request/response dict 现算 raw 文本,不落盘不缓存。
# 两种存储 shape 都吃:
# - history(get_traffic view 层翻译):{method,url,headers:[{name,value}],post_data:str}
#   / response {status,headers,body_text:str}
# - evidence(json.loads 原样 HttpRequest/HttpResponse.to_dict):{method,url,headers,body:{text}}
#   / response {status,reason,headers,body:{text}}
# 二进制上传 body 已是占位(_redact_binary_upload 替描述 或 HttpBody.text 的 [FILE N bytes]
# 占位)——raw_bytes 是 send-only 不落盘,无法还原,by design 丢精度。

_REASON_PHRASES = {
    200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
    307: "Temporary Redirect", 308: "Permanent Redirect",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 409: "Conflict", 413: "Payload Too Large",
    422: "Unprocessable Entity", 429: "Too Many Requests",
    500: "Internal Server Error", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout",
}


def _header_pairs(headers: Any) -> list[tuple[str, str]]:
    """headers 统一成 [(name, value)]。吃 list[{name,value}](DTO 存储形)或
    dict{name:value}(兜底),其他形状返回 []。"""
    out: list[tuple[str, str]] = []
    if isinstance(headers, list):
        for h in headers:
            if isinstance(h, dict) and "name" in h:
                out.append((str(h.get("name", "")), str(h.get("value", ""))))
            elif isinstance(h, (tuple, list)) and len(h) == 2:
                out.append((str(h[0]), str(h[1])))
    elif isinstance(headers, dict):
        for k, v in headers.items():
            out.append((str(k), str(v)))
    return out


def _request_body_text(req: dict[str, Any]) -> str:
    """request body 文本:evidence 形(json.loads(request_json) 原样 HttpRequest.to_dict)
    用 body.text;history 形(get_traffic view 层)用 post_data。优先 nested:get_traffic
    给 evidence 灌了空 body_text 而 body.text 才是原文,先取 nested 才不被空串短路。"""
    body = req.get("body")
    if isinstance(body, dict):
        text = body.get("text")
        if isinstance(text, str):
            return text
    post = req.get("post_data")
    if isinstance(post, str):
        return post
    return ""


def _response_body_text(resp: dict[str, Any]) -> str:
    """response body 文本:evidence 形用 body.text;history 形用 body_text。
    优先 nested:get_traffic 只分页 body_text(history 字段),evidence 的 body_text 被置空
    但原 body 键保留,先取 body.text 才兜回 evidence 原文。"""
    body = resp.get("body")
    if isinstance(body, dict):
        text = body.get("text")
        if isinstance(text, str):
            return text
    bt = resp.get("body_text")
    if isinstance(bt, str):
        return bt
    return ""


def _body_text(b: Any) -> str | None:
    """HttpBody dict({text,content_type,file_path,truncated}) 取 .text;str 直接返回;None 返回 None。

    body 是 HttpBody dict 时取 .text 才是裸 body 串(供 list_raw/_get_raw 翻译)。
    proxy.store / tool.data.store 两处共享。
    """
    if b is None:
        return None
    if isinstance(b, dict):
        return b.get("text")
    if isinstance(b, str):
        return b
    return str(b)


def _body_field(b: Any, key: str) -> str | None:
    """从 HttpBody dict 取一字段(如 content_type);非 dict 返回 None。"""
    if isinstance(b, dict):
        return b.get(key)
    return None


def _render_request(req: dict[str, Any]) -> str:
    method = str(req.get("method") or "GET").upper() or "GET"
    url = str(req.get("url") or "")
    parts = urlsplit(url) if url else None
    if parts is not None and parts.netloc:
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        host = parts.netloc
    else:
        target = url or "/"
        host = ""
    headers = _header_pairs(req.get("headers"))
    has_host = any(n.casefold() == "host" for n, _ in headers)
    lines = [f"{method} {target} HTTP/1.1"]
    if host and not has_host:
        lines.append(f"Host: {host}")
    for n, v in headers:
        lines.append(f"{n}: {v}")
    return "\r\n".join(lines) + "\r\n\r\n" + _request_body_text(req)


def _render_response(resp: dict[str, Any]) -> str:
    raw_status = resp.get("status")
    try:
        status = int(raw_status) if raw_status is not None else 0
    except (TypeError, ValueError):
        status = 0
    reason = str(resp.get("reason") or "").strip()
    if not reason and status in _REASON_PHRASES:
        reason = _REASON_PHRASES[status]
    status_line = f"HTTP/1.1 {status} {reason}".rstrip()
    headers = _header_pairs(resp.get("headers"))
    lines = [status_line]
    for n, v in headers:
        lines.append(f"{n}: {v}")
    return "\r\n".join(lines) + "\r\n\r\n" + _response_body_text(resp)


def to_raw_http(request: dict[str, Any] | None,
                response: dict[str, Any] | None = None) -> str:
    """把 get_traffic 返回的 request/response dict 还原成原始 HTTP 文本(给人 review 数据包)。

    request 给 → 渲染请求包(method+path HTTP/1.1 + Host 兜底 + headers + body);
    response 给 → 渲染响应包(HTTP/1.1 status reason + headers + body)。两者都给
    → 请求包 + 空行 + 响应包拼接。任一可省(传 None 跳过)。空入参 → ""。

    请求行只取 path+query(urlsplit),不含 scheme/host(那是 Host 头的活)。
    Host 头不在 headers 里则从 url netloc 兜底补一行。body 文本吃两种 shape
    (history 的 post_data/body_text 与 evidence 的 body.text 都 fallback 到位)。
    二进制上传 body 是占位不还原(raw_bytes 不落盘),by design 丢精度。
    """
    parts: list[str] = []
    if request:
        parts.append(_render_request(request))
    if response:
        parts.append(_render_response(response))
    return "\r\n\r\n".join(parts)
