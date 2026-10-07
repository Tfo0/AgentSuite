"""全局 find/replace 编辑内核:整条请求当文本,find 唯一命中才替(歧义护栏)。

第一性:LLM 抄明文里看到的一段(find)换成新的(replace),不解析结构,纯文本匹配。
agent 不学规则——想改啥就 find 抄那段、replace 写新的;空串=删匹配文本;多处命中护栏
报错逼加长 find;未命中报错。删整字段要干净(不留尾巴)→ traffic_send 重建。

作用域(计数 find 命中,跨域求和,唯一才替):
- method: request.method
- url: request.url(含 scheme/host/path/query)
- header: 每条 "Name: value" 串(find 可抄整行或只 value;cookie 在 Cookie 头 value 里)
- body: body.text

护栏:find 总命中 0→未找到;>1→多处命中加长 find;==1→替在命中域。
砍了 part 限作用域:消歧义靠护栏反馈(agent 加长 find),不靠预约束。method 罕见歧义
(method 是孤立词加长不了,且 body 含同字面会撞)→ 走 traffic_send 改 method。
"""
from __future__ import annotations

from agentsuite.proxy.http import HttpBody, HttpHeader, HttpRequest


def apply_find_replace(
    request: HttpRequest,
    find: str | None,
    replace: str | None,
) -> HttpRequest:
    """整条请求全局 find/replace:find 在 method/url/header/body 唯一命中才替,返回新 HttpRequest。

    多处命中→报错(加长 find);未命中→报错;空 find→报错。replace 空串=删匹配文本(留尾巴,
    干净删整字段用 traffic_send)。
    """
    return _edit_global(request, find, replace)


# ---- 全局 ----
def _edit_global(request: HttpRequest, find: str | None, replace: str | None) -> HttpRequest:
    """全局 find/replace:跨 method/url/header/body 计数 find,唯一匹配才替。

    多处命中→歧义报错(逼加长 find);未命中→报错。header 作用域搜 'Name: value' 串
    (故 find 可抄整行或只 value;cookie 在 Cookie 头 value 里被同一作用域覆盖)。
    """
    if not str(find or "").strip():
        raise ValueError("find 不能为空(抄明文里要改的那段)")
    find_s = str(find)
    replace_s = str(replace or "")
    hits: list[tuple[str, int, int]] = []  # (field, count, header_index or -1)
    cm = request.method.count(find_s)
    if cm:
        hits.append(("method", cm, -1))
    cu = request.url.count(find_s)
    if cu:
        hits.append(("url", cu, -1))
    for i, h in enumerate(request.headers):
        cv = f"{h.name}: {h.value}".count(find_s)
        if cv:
            hits.append(("header", cv, i))
    body_text = request.body.text if (request.body and request.body.text) else ""
    cb = body_text.count(find_s)
    if cb:
        hits.append(("body", cb, -1))
    total = sum(h[1] for h in hits)
    if total == 0:
        raise ValueError(f"未找到:{find_s}")
    if total > 1:
        where = ", ".join(f"{h[0]}×{h[1]}" for h in hits)
        raise ValueError(f"多处命中 {find_s}({total} 次:{where}),加长 find 精确定位")
    field_, _, hidx = hits[0]
    if field_ == "method":
        return _replace(request, method=request.method.replace(find_s, replace_s, 1))
    if field_ == "url":
        return _replace(request, url=request.url.replace(find_s, replace_s, 1))
    if field_ == "header":
        old = request.headers[hidx]
        full = f"{old.name}: {old.value}"
        new_full = full.replace(find_s, replace_s, 1)
        if ": " in new_full:
            n, _, v = new_full.partition(": ")
            new_h = HttpHeader(n, v)
        else:
            # replace 后无 ': '(如删整行留空串)→ 留空头(脏,干净删整 header 用 traffic_send)
            new_h = HttpHeader(new_full, "")
        new_headers = tuple(new_h if i == hidx else h for i, h in enumerate(request.headers))
        return _replace(request, headers=new_headers)
    # body
    new_body = HttpBody(text=body_text.replace(find_s, replace_s, 1),
                        content_type=request.body.content_type if request.body else None,
                        file_path=request.body.file_path if request.body else None,
                        truncated=False)
    return _replace(request, body=new_body)


def _replace(request: HttpRequest, *, method: str | None = None, url: str | None = None,
             headers: tuple[HttpHeader, ...] | None = None,
             body: HttpBody | None = None) -> HttpRequest:
    return HttpRequest(
        method=method if method is not None else request.method,
        url=url if url is not None else request.url,
        headers=headers if headers is not None else request.headers,
        body=body if body is not None else request.body,
    )
