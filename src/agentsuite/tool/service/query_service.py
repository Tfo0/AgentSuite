"""query_service:list 流量 + get 单条(原始或证据)。

只读(+写 clean 派生表),调 store。无 LLM。
"""
from __future__ import annotations

import difflib
import json
import re
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

from ..data.store import AuditStore
from agentsuite.proxy.http import to_raw_http


# _DEFAULT_BODY_LIMIT / _paginate_body 在 _paging.py(replay_service 共用,
# 避免 replay→query→replay 循环 import)
from ._paging import _DEFAULT_BODY_LIMIT, _paginate_body

# traffic_list 的 post_data 预览上限(字符)。概览不背全请求 body——
# agent 看 method/url/status/post_data 预览挑流量,看中再 traffic_get 详读。256 够显 JSON/form 结构。
_LIST_POST_PREVIEW = 256


# ── view 层二进制上传占位(get_traffic 专用)─────────────────────────────
# 痛点:文件上传 multipart 把整个文件二进制塞进 post_data(实测 248KB),
# agent 拿到 traffic_get 后一直啃 request body 的乱码,不去看 response 返回的 key。
# view 层替成占位:history.request_json(DB 原文)不动,traffic_repeater 重放从 DB
# 直接读原文(store.get)不依赖 traffic_get 返回的 body,故占位零副作用(不影响重放)。
_BINARY_BODY_THRESHOLD = 8192   # post_data 超此字符数 + multipart → 占位
_BINARY_REPLACEMENT_MIN = 100   # 或 U+FFFD(二进制→控制字符替换)≥ 此数 → 占位

# JS 响应体 inline 截断(note 实现清单 #10:history 响应体按 content-type 区分截断)。
# minified JS bundle 几百 KB-MB,agent 读全文无益(白噪声),默认只回前 2048 够认是 JS
# 端点 + 看头部;为后续 aijsextract 铺路(全量由专门工具抽端点/密钥,不靠 agent 啃 inline)。
# 只在 agent 用默认 limit(== _DEFAULT_BODY_LIMIT)时套;显式传 limit(含 0=全量)翻页读更多。
_JS_BODY_LIMIT = 2048


def _is_js_content_type(ct: str | None) -> bool:
    """Content-Type 是否 JS(text/javascript / application/javascript 等)。"""
    base = str(ct or "").lower().split(";", 1)[0].strip()
    return base in (
        "text/javascript", "application/javascript",
        "application/x-javascript", "text/ecmascript",
        "application/ecmascript",
    )


def _header_value(headers: list[Any] | None, name: str) -> str | None:
    """从 list[{name,value}] headers 取一个值(case-insensitive)。None/非 list 返回 None。"""
    if not isinstance(headers, list):
        return None
    lower = name.lower()
    for h in headers:
        if isinstance(h, dict) and str(h.get("name", "")).lower() == lower:
            return h.get("value")
    return None


def _parse_multipart_parts(text: str, boundary: str) -> list[dict[str, Any]] | None:
    """从 multipart body 文本提 parts 概要(name/filename/content_type/size)。

    text 含 U+FFFD(二进制→控制字符替换后),但 boundary 与 part headers 是 ASCII,
    解析仍可靠;文件 part body 长度是近似(U+FFFD 单 char 压缩了原多字节二进制)。
    返回 [{name, filename?, content_type?, size}] 或 None(解析失败→调用方 fallback 纯长度占位)。
    """
    sep = "--" + boundary
    chunks = text.split(sep)
    # 首段 preamble(常空),末段 "--\r\n" 结尾;中间才是 parts
    inner = chunks[1:-1] if len(chunks) >= 3 else []
    parts: list[dict[str, Any]] = []
    for chunk in inner:
        chunk = chunk.lstrip("\r\n")
        hsep = chunk.find("\r\n\r\n")
        if hsep < 0:
            continue
        head, body = chunk[:hsep], chunk[hsep + 4:]
        p: dict[str, Any] = {}
        for line in head.split("\r\n"):
            if not line or ":" not in line:
                continue
            k, _, v = line.partition(":")
            k, v = k.strip().lower(), v.strip()
            if k == "content-disposition":
                mn = re.search(r'name="([^"]*)"', v)
                if mn:
                    p["name"] = mn.group(1)
                mf = re.search(r'filename="([^"]*)"', v)
                if mf:
                    p["filename"] = mf.group(1)
            elif k == "content-type":
                p["content_type"] = v
        p["size"] = len(body.rstrip("\r\n"))
        parts.append(p)
    return parts or None


def _redact_binary_upload(req: dict[str, Any]) -> dict[str, Any]:
    """view 层占位:multipart 二进制/超大请求体 → post_data 替成占位描述。

    命中(content-type 含 multipart/form-data 且 post_data 超阈值 或 U+FFFD 多)才替;
    其余原样返回同一对象。返回新 dict(不原地改 store 投影);加 body_omitted/body_total
    告知 agent 原文仍在 DB(traffic_repeater 重放从 DB 读)。证据 path 的 req 无 post_data
    字符串(是 body dict)→ 天然不命中,不动。
    """
    post = req.get("post_data")
    if not isinstance(post, str):
        return req
    n_repl = post.count("�")
    if len(post) <= _BINARY_BODY_THRESHOLD and n_repl < _BINARY_REPLACEMENT_MIN:
        return req
    ctype = _header_value(req.get("headers"), "content-type")
    if not ctype or "multipart/form-data" not in ctype.lower():
        return req
    boundary = None
    for tok in ctype.split(";"):
        tok = tok.strip()
        if tok.lower().startswith("boundary="):
            boundary = tok[len("boundary="):].strip().strip('"')
            break
    total = len(post)
    parts = _parse_multipart_parts(post, boundary) if boundary else None
    if parts:
        bits = []
        for p in parts:
            if p.get("filename"):
                ct = p.get("content_type", "application/octet-stream")
                bits.append(f'file="{p["filename"]}" {ct} {p.get("size", 0)}chars')
            else:
                bits.append(f'field "{p.get("name", "")}"')
        desc = "multipart parts: " + ", ".join(bits)
    else:
        desc = "multipart/form-data binary upload"
    placeholder = (
        f"<binary upload omitted {total}chars — {desc}; "
        f"raw 仍在 DB,traffic_repeater 重放从 DB 读原文;agent 看 response 返回的 key>"
    )
    out = dict(req)
    out["post_data"] = placeholder
    out["body_omitted"] = True
    out["body_total"] = total
    return out


# ── 三位一体视图翻译:store request/response shape → note 统一对象 ──────────────
# 存储保持 store shape(HttpRequest.to_dict():{method,url,headers[list],body[HttpBlob]} /
# history view:{method,url,headers,post_data}),recorder/store/migration/to_raw_http/web
# 全不动。只在 traffic_get 工具出参翻译成 note 的统一对象(agent 可见三位一体):
# request{method,scheme,host,path,query,headers{dict},body{kind,value}}
# response{status,headers{dict},body,body_omitted,body_total}
# url 拆 scheme/host/path/query(urlsplit);body 从 content_type 推 kind(json/form/multipart/text)。
def _infer_kind(content_type: str | None) -> str:
    """从 Content-Type 推 body kind。json/form/multipart/text。"""
    ct = str(content_type or "").lower()
    if "json" in ct:
        return "json"
    if "x-www-form-urlencoded" in ct:
        return "form"
    if "multipart/form-data" in ct:
        return "multipart"
    return "text"


def _headers_to_dict(headers: Any) -> dict[str, str]:
    """list[{name,value}] → dict{name:value}(后者覆盖前者,case 保留)。非 list 返回 {}。"""
    out: dict[str, str] = {}
    if isinstance(headers, list):
        for h in headers:
            if isinstance(h, dict):
                out[str(h.get("name", ""))] = str(h.get("value", ""))
    elif isinstance(headers, dict):
        for k, v in headers.items():
            out[str(k)] = str(v)
    return out


def unify_request(req: dict[str, Any]) -> dict[str, Any]:
    """store request shape → note 统一 request 对象。

    吃两种 store shape:history view{method,url,headers,post_data}(经 _redact_binary_upload
    可能带 body_omitted/body_total)+ evidence{method,url,headers,body{HttpBlob}}。
    输出:{method,scheme,host,path,query,headers{dict},body{kind,value}}。body kind 从
    Content-Type 推(json/form/multipart/text);value=body 文本(或二进制占位)。
    """
    url = str(req.get("url") or "")
    parts = urlsplit(url) if url else None
    headers = _headers_to_dict(req.get("headers"))
    ct = None
    for n, v in headers.items():
        if n.casefold() == "content-type":
            ct = v
    body_value: str | None = None
    body_dict = req.get("body")
    if isinstance(body_dict, dict) and body_dict.get("text") is not None:
        body_value = str(body_dict.get("text"))
        ct = ct or body_dict.get("content_type")
    elif req.get("post_data") is not None:
        body_value = str(req.get("post_data"))
    kind = _infer_kind(ct)
    out: dict[str, Any] = {
        "method": req.get("method"),
        "scheme": (parts.scheme if parts else "") or "https",
        "host": (parts.hostname if parts else "") or "",
        "path": (parts.path if parts else "") or "/",
        "query": (parts.query if parts else "") or "",
        "headers": headers,
        "body": {"kind": kind, "value": body_value or ""},
    }
    if req.get("body_omitted"):
        out["body_omitted"] = True
        out["body_total"] = req.get("body_total")
    return out


def unify_response(resp: dict[str, Any]) -> dict[str, Any]:
    """store response shape → note 统一 response 对象。

    吃两种:history view{status,headers,content_type,body_text}(经 get_traffic 分页带
    body_truncated/body_total)+ evidence ResponseSnapshot{status,body_text,elapsed_ms,
    body_truncated}(无 headers)。输出:{status,headers{dict},body,body_omitted,body_total,
    body_truncated}。body=body_text 分页切片;body_total=全长(agent 据此翻页)。
    """
    body_text = resp.get("body_text")
    if body_text is None and isinstance(resp.get("body"), dict):
        body_text = resp["body"].get("text")
    body_text = str(body_text or "")
    return {
        "status": resp.get("status"),
        "headers": _headers_to_dict(resp.get("headers")),
        "body": body_text,
        "body_omitted": bool(resp.get("body_omitted")),
        "body_total": resp.get("body_total") if resp.get("body_total") is not None else len(body_text),
        "body_truncated": bool(resp.get("body_truncated")),
    }


def load_common_params(session_dir: str | Path) -> list[dict[str, Any]]:
    """读 session_dir/pipeline/proxy/noise.jsonl(lib.build_clean 落的公共参数表)。

    公共参数 = 按子域名,host 内 query key 出现频次>50%(判键不判值)——该 host 框架/
    风控参数,非越权向量。跨 ≥2 host 都 >50% 的 key 视为跨域资源标识符,build_clean
    已剔除(不在此表,必须测)。dispatch/verify agent 注入提示词用(dispatch 勿打包进
    keys;verify 软提示可覆盖——可能是 per-user 授权 ID,换号实测才算证伪,提示词不替
    agent 下结论)。dispatch_service.dispatch 也读它 strip keys。文件缺失/坏 → 空表
    (老 session / lib.build_clean 未跑 → 不注入不剥离,降级不崩)。
    """
    p = Path(session_dir) / "pipeline" / "proxy" / "noise.jsonl"
    try:
        if not p.is_file():
            return []
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [d for d in data if isinstance(d, dict) and d.get("key")]


class QueryService:
    """读流量:list 分页 + get 单条(原始流量或重放证据,按 id)。"""

    def __init__(self, store: AuditStore) -> None:
        self.store = store

    def list_traffic(self, *, page_no: int = 1, page_size: int = 20,
                     source: str = "history") -> dict[str, Any]:
        """分页读流量摘要。概览用:post_data 只回前 256 字符预览 + post_data_len,
        详读 traffic_get。原 resource_type 是 no-op(traffic 表无此列,静态后缀 +
        agent 自判取代 xhr/fetch 区分),已从签名删。source='history'(默认,原始流量)
        /'evidence'(重放证据 repeater/brute/send,verify 读重放证据用)。
        """
        if page_no < 1:
            raise ValueError("page_no 不能小于 1")
        if page_size < 1 or page_size > 30:
            raise ValueError("page_size 必须在 1 到 30 之间")
        result = self.store.list_raw(page_no=page_no, page_size=page_size, source=source)
        # post_data_preview 截前 256 字符 + post_data_len:概览不背全 body(agent 看中再 traffic_get 详读)
        for item in result.get("items", []):
            post = item.pop("post_data", "") or ""
            item["post_data_len"] = len(post)
            item["post_data_preview"] = post[:_LIST_POST_PREVIEW]
        return result

    def search_traffic(self, search: str, *, page_no: int = 1,
                       page_size: int = 20) -> dict[str, Any]:
        """全局子串搜 history(request+response 全文本),返匹配行+片段。

        upstream-tracing 用(idor-test「不可遍历 id 往上追溯源上游参数」):流量 A 用了
        不可遍历 id X,一次 search_traffic(X) 找哪个流量的 response 里出现过 X →
        X 的来源流量 B;再看 B 的请求参数可否遍历。替 O(N) 次 traffic_list+traffic_get
        翻找。thin wrapper 调 store.search_raw。返 {total,page_no,page_size,items=[
        {traffic_id,method,host,path,status,matched_in,fragment}]}。
        """
        return self.store.search_raw(search, page_no=page_no, page_size=page_size)

    def get_traffic(self, traffic_id: str, *, section: str = "all",
                    raw: bool = False,
                    offset: int = 0, limit: int = _DEFAULT_BODY_LIMIT) -> dict[str, Any]:
        """读单条。section: request/response/all。

        raw=True(★agent 主路径,tool_use 层 SCHEMA 默认 true 显式传):to_raw_http 现场渲染
        完整 HTTP 文本(请求包+响应包),offset/limit 对**整条 raw 文本**分页(默认 32KB),
        返 {id, raw, raw_total, raw_truncated}。repeater 抄 raw 里一段当 find、写新段当 replace。
        二进制上传 body 是占位不还原(_redact_binary_upload 已替)。section 仍生效:
        request→只请求包 / response→只响应包 / all→请求包+\\r\\n\\r\\n+响应包。

        raw=False(默认,保后端/web/测试兼容):走结构化——offset/limit 对 response.body_text
        做 Read 式分页(默认 0..32768 字符),返 {id, request, response,...}。response 带
        body_truncated(是否被截)+ body_total(总长),agent 据此翻页。limit<=0 → 全量(逃生口)。
        只分页 body_text;status/headers/content_type 都小,始终全返。post_data(请求体)默认原样回
        (留给 traffic_repeater 抄 find 原文),但 multipart 二进制上传(文件)会被 view 层替成占位
        (_redact_binary_upload),避免 248KB 文件二进制灌进上下文——原文仍在 DB,repeater 重放从 DB 读不受影响。
        """
        data = self.store.get(traffic_id)
        if data is None:
            raise ValueError(f"流量不存在:{traffic_id}")
        req = _redact_binary_upload(data.get("request") or {})
        if raw:
            # raw 模式:to_raw_http 渲染完整 raw 文本(吃 store shape),再对整条 raw 分页。
            # raw=true 是 agent 主路径(repeater 抄 find);不走 JS cap/结构化 unify。
            full_resp = data.get("response") or {}
            req_in = req if section in ("all", "request") else None
            resp_in = full_resp if section in ("all", "response") else None
            full_raw = to_raw_http(req_in, resp_in)
            sliced, truncated, total = _paginate_body(full_raw, offset, limit)
            return {"id": traffic_id, "raw": sliced,
                    "raw_total": total, "raw_truncated": truncated}
        resp = data.get("response") or {}
        # JS 响应体按 content-type 区分截断(实现清单 #10):minified bundle 默认只回前
        # _JS_BODY_LIMIT(2048);非 JS 默认 32KB。仅当用默认 limit 时套——agent 显式传
        # limit(含 0=全量)翻页读更多不受限。history 有 content_type 字段;evidence
        # (ResponseSnapshot)无 content_type → 不命中,原样 32KB(evidence 是 agent 自产重放)。
        ct = resp.get("content_type")
        if ct is None:
            ct = _header_value(resp.get("headers"), "content-type")
        if _is_js_content_type(ct) and limit == _DEFAULT_BODY_LIMIT:
            limit = _JS_BODY_LIMIT
        body = resp.get("body_text")
        sliced, truncated, total = _paginate_body(body, offset, limit)
        resp = {**resp, "body_text": sliced, "body_truncated": truncated, "body_total": total}
        if section == "request":
            return {"id": traffic_id, "request": req}
        if section == "response":
            return {"id": traffic_id, "response": resp}
        # all:保留证据的 baseline/diff/edit/baseline_stable/source_id 等额外字段
        out = {k: v for k, v in data.items() if k not in ("request", "response")}
        out["request"] = req
        out["response"] = resp
        return {"id": traffic_id, **out}

    # ---- diff:任意两流量已存响应比对(替 with_diff/baseline_id) ----
    def diff_traffic(self, baseline_id: str, candidate_id: str) -> dict[str, Any]:
        """读两份**已存**响应比对(不重发)。替 repeater 的 with_diff + raw 的 baseline_id。

        baseline/candidate 可是任意 traffic_id(history:<id> 或 repeater:N/brute:N/send:N)。
        history 响应在录制时已采,response_json 存着;证据响应在重放
        时已采。两份直接读出比,不发请求。返 note 的 string diff shape:
        - status_diff:"200 vs 401"(同则 "")
        - body_diff:unified diff(同则 "identical";空/二进制 body→"skipped")
        - time_diff:"120ms vs 90ms"(history 无 elapsed_ms→"n/a")
        - baseline_size/candidate_size:body 字节数
        """
        if str(baseline_id) == str(candidate_id):
            return {"status_diff": "", "body_diff": "", "time_diff": "",
                    "baseline_size": 0, "candidate_size": 0}
        base = self._extract_comparable(baseline_id)
        cand = self._extract_comparable(candidate_id)
        bs, cs = base["status"], cand["status"]
        status_diff = f"{bs} vs {cs}" if bs != cs else ""
        bb, cb = base["body_text"], cand["body_text"]
        baseline_size, candidate_size = len(bb), len(cb)
        if not bb or not cb:
            body_diff = "skipped (empty/binary body)"
        elif bb == cb:
            body_diff = "identical"
        else:
            diff_lines = list(difflib.unified_diff(
                bb.splitlines(keepends=False), cb.splitlines(keepends=False),
                fromfile="baseline", tofile="candidate", lineterm=""))
            body_diff = "\n".join(diff_lines[:200])
            if len(diff_lines) > 200:
                body_diff += f"\n...({len(diff_lines) - 200} more lines)"
        be, ce = base["elapsed_ms"], cand["elapsed_ms"]
        if be is None or ce is None:
            time_diff = "n/a (history 无 timing)"
        else:
            time_diff = f"{be}ms vs {ce}ms" if be != ce else ""
        return {"status_diff": status_diff, "body_diff": body_diff,
                "time_diff": time_diff, "baseline_size": baseline_size,
                "candidate_size": candidate_size}

    def _extract_comparable(self, traffic_id: str) -> dict[str, Any]:
        """读 traffic_id 的已存响应,归一成 {status, body_text, elapsed_ms}。

        history(_get_raw):{status, headers, content_type, body_text}——无 elapsed_ms。
        evidence(ResponseSnapshot.to_dict):{status, body_text, elapsed_ms, body_truncated}。
        不存在→ValueError(traffic_diff 边界:id 不存在→error)。
        """
        data = self.store.get(traffic_id)
        if data is None:
            raise ValueError(f"流量不存在:{traffic_id}")
        resp = data.get("response") or {}
        body_text = resp.get("body_text")
        # evidence 形 response 可能是 HttpResponse.to_dict(有 nested body.text)——兜底取
        if body_text is None and isinstance(resp.get("body"), dict):
            body_text = resp["body"].get("text")
        return {
            "status": resp.get("status"),
            "body_text": str(body_text or ""),
            "elapsed_ms": resp.get("elapsed_ms"),
        }


    def pack_units(self, byte_budget: int = 65536, *,
                   exclude_ids: set[str] | None = None
                   ) -> Iterator[list[dict[str, Any]]]:
        """把 clean 行按字节预算动态打包成批次,供 dispatch 喂 agent(一次一单位元=一批)。

        行体积差异大(7d 实测 lean ~0.7KB / fat ~7KB,差 10×),定数会 over/underpack
        (lean 目标塞太多撑爆、fat 目标塞太少浪费)。按累计 JSON 序列化字节 ≤ byte_budget
        切批,自适应:lean 目标多装、fat 目标少装,稳在预算内。默认 64KB——7d 实测
        p50=686B → ~90 行/批,fat ~7KB → ~9 行/批。dispatch stage 传 8192(8KB)
        → lean ~11 行/批(目标 8-10),fat 自适应少条。留余量给 system prompt +
        traffic_get tool_result + agent 推理(单条 traffic_result 受 SDK 1MB ceiling 约束,
        与此独立)。budget 可调:triage 想多看就调大,deep-dive 想聚焦就调小。
        exclude_ids:已落 verdict 的 request_id 集(续跑跳过,stage 传 done set)。
        """
        rows = self.store.list_clean()
        excl = exclude_ids or set()
        batch: list[dict[str, Any]] = []
        size = 0
        for r in rows:
            if str(r.get("request_id", "")) in excl:
                continue
            rsz = len(json.dumps(r, ensure_ascii=False))
            if batch and size + rsz > byte_budget:
                yield batch
                batch, size = [], 0
            batch.append(r)
            size += rsz
        if batch:
            yield batch

