"""proxy clean:build_clean 编排(record 尾跑,产 clean.jsonl + noise.jsonl)。

管线(spec proxy/CLAUDE.md §管线时序):
  filter(raw summaries → drop_summary → dedup → clusters)
  → nosie(clusters → common_params;clusters 是 post-drop+post-dedup rep 集,不读 raw)
  → min_unit(per cluster:store.get full + matches_full(body 规则)+ 剥 common_params)→ clean 行
  → 写 clean.jsonl + noise.jsonl

两阶段 noise drop(顺序不可换,invariant #5):
1. summary 阶段(drop_summary,预去重):host/method/path/query + 静态后缀 + OPTIONS 整条丢。
   body 规则此阶段跳过(summary 无 post_data)。
2. full 阶段(matches_full,cluster rep):只判 body 规则(只对 rep 取 body,不为每条 raw 取)。

common_params 消费 clusters 不读 raw(invariant #6):频次按 cluster(唯一端点)计不按 raw
条数,噪音请求不进计数——common_params 描述 agent 看到的 post-filter 集。

搬自 tool/service/query_service.py(extract_keys/_json_body_of/_form_body_of/
_response_of/_min_unit verbatim,build_clean 重写末尾写 jsonl;_drop_noise_summary→filter.
drop_summary,_dedup→filter.dedup,_common_params→nosie.common_params)。proxy 不 import tool
(invariant #2),NoiseFilter own 在 filter.py、HTTP 类型走 proxy/http.py(扁平化后无独立 model 中立层)。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from .filter import NoiseFilter

from .store import ProxyStore
from .filter import dedup, drop_summary
from .http import _header_pairs
from . import nosie

# ── clean:tap 一次的最小单元提取(借鉴 tap/summary.py)──────────
# 响应取嵌套键结构(无值),json_body/form_body 留原值(用户例:{"id":"123"})。
# 所有文本字段都有硬截断 → 单行体积有界。
_MAX_BODY = 4096         # 请求体原值截断(json_body/form_body)
_MAX_QUERY = 1024        # query 原值截断(长 sign/a_bogus/msToken 噪声截掉,业务参数够用)
_MAX_RESP = 2048         # 响应截断:JSON extract_keys 后也硬截,非 JSON 同(统一有界)


def extract_keys(obj: Any) -> str | None:
    """JSON 嵌套键结构(无值):{code, data:{mobile, idCard}}。

    借鉴 tap/summary.py——保留嵌套层级,agent 能看到敏感字段嵌在哪层信封里
    (data.mobile vs 顶层 mobile)。list 取并集键。
    """
    if isinstance(obj, dict):
        parts = []
        for k, v in obj.items():
            child = extract_keys(v)
            parts.append(f"{k}:{child}" if child else str(k))
        return "{" + ", ".join(parts) + "}" if parts else "{}"
    if isinstance(obj, list):
        merged: set[str] = set()
        for item in obj:
            child = extract_keys(item)
            if child:
                for k in child.strip("{}[]").split(", "):
                    if k:
                        merged.add(k)
        return "[" + ", ".join(sorted(merged)) + "]" if merged else "[...]"
    return None


def _json_body_of(post_data: Any) -> str:
    """请求 JSON 体原值(截断),非 JSON 空。clean.json_body 用。

    用户例:{"id":"123","sign":"abcdefg"}——留值(agent 要看发了什么,供 replay/篡改)。
    dict/list → dumps;string 且 json.loads 成功 → 原串;否则空(归 form_body)。
    """
    if post_data is None:
        return ""
    if isinstance(post_data, (dict, list)):
        return json.dumps(post_data, ensure_ascii=False)[:_MAX_BODY]
    if isinstance(post_data, str):
        s = post_data.strip()
        if not s:
            return ""
        try:
            json.loads(s)
            return s[:_MAX_BODY]
        except (json.JSONDecodeError, ValueError):
            return ""
    return ""


def _form_body_of(post_data: Any) -> str:
    """请求 form 体原值(截断),非 form 空。clean.form_body 用。

    用户例:id=123&sign=abcdefg——留值。只收 form-ish 串(含 =,且非 JSON)。
    """
    if not isinstance(post_data, str):
        return ""
    s = post_data.strip()
    if not s or "=" not in s:
        return ""
    try:
        json.loads(s)  # JSON 也可能含 =(边界),排除归 json_body
        return ""
    except (json.JSONDecodeError, ValueError):
        return s[:_MAX_BODY]


# 文本 content-type marker(与 recorder.TEXT_CONTENT_MARKERS 同一份;不 import recorder
# 以免 clean 经 recorder 拉 mitmproxy 依赖)。非文本且非空 → 二进制,占位。共享同一份
# marker 保证 clean 的二进制判定与 recorder 的 _should_capture_body 采 body 决策对齐:
# recorder 当文本采的(body_text 非空)clean 当文本处理;recorder 不采的(None)clean 占位。
_TEXT_CT_MARKERS = ("application/json", "application/javascript", "application/xml",
                    "application/x-www-form-urlencoded", "text/")


def _is_binary_ct(ct: str) -> bool:
    """content-type 是否二进制:非空且不含文本 marker。image/video/pdf/octet-stream 等 → True。"""
    ct_l = (ct or "").lower()
    return bool(ct_l) and not any(m in ct_l for m in _TEXT_CT_MARKERS)


# HTML content-type marker:text/html、application/xhtml+xml。HTML 响应整条占位(体大且
# clean 漏斗无语义价值——页面 HTML 不是 API 数据,截断只留半截更没用),和二进制一样
# 直接占位,agent 看 ct 即知"这接口回 HTML 页面",要全文自己 traffic_get。
_HTML_CT_MARKERS = ("text/html", "application/xhtml")


def _is_html_ct(ct: str) -> bool:
    """content-type 是否 HTML:text/html、application/xhtml+xml。"""
    ct_l = (ct or "").lower()
    return any(m in ct_l for m in _HTML_CT_MARKERS)


def _response_of(body_text: Any, content_type: str | None = None) -> str:
    """响应:JSON→extract_keys 嵌套键(无值);HTML/二进制→占位;text→截断。clean.response 用。

    HTML 和二进制响应整条占位:agent 看 content-type 即知响应类型(回 HTML 页面 / 回
    二进制),要全文自己 traffic_get——clean 漏斗只留语义信号,不展开体大无价值的体。
    HTML 体大且非 API 数据(页面 HTML),截断只留半截更没用;二进制 recorder 不采 body
    (body_text=None)。无 body(204/304)但 ct 是 HTML/二进制也占位(ct 是权威信号)。
    JSON → extract_keys 留嵌套键结构(数据信封语义,agent 看敏感字段嵌在哪层)。
    其余 text(text/plain、xml 串等非 JSON 可解析文本)→ 截断 _MAX_RESP。
    JSON 的 extract_keys 也硬截断 _MAX_RESP——深嵌套/多键 JSON 可能超(7d 实测 max 2283)。
    """
    ct = content_type or ""
    if ct and _is_html_ct(ct):
        return f"[HTML响应 {ct}]"
    if not body_text:
        # body_text None/空:binary content-type → 二进制占位(recorder 不采 body);
        # 否则(无 body 204/304、text 类型空 body)→ 空。
        if ct and _is_binary_ct(ct):
            return f"[二进制响应 {ct}]"
        return ""
    body = body_text if isinstance(body_text, str) else str(body_text)
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return body[:_MAX_RESP]  # text 截断
    return (extract_keys(obj) or "")[:_MAX_RESP]


# 二进制 multipart 上传 per-part 占位(对齐 view 层 query_service._redact_binary_upload
# 触发条件;proxy 不 import tool,逻辑同构阈值同)。命中 → 解析 multipart,保留 part 头
# (字段名/文件名/content-type)+ 文本字段值,只把含 U+FFFD(录制时二进制→控制字符替残留)
# 的 part body 替成 [二进制 N字符]。agent 看 form_body 即知"哪几个字段是上传文件/什么类型",
# 不必每条都 traffic_get。解析失败(无 boundary/无 part)才 fallback 整体占位。
_BINARY_UPLOAD_THRESHOLD = 8192   # post_data 字符数超此 + multipart → 进 per-part(同 view 层)
_BINARY_UPLOAD_REPL_MIN = 100     # 或 U+FFFD(二进制控制字符替)≥ 此 → 进 per-part


def _req_content_type(req: dict[str, Any]) -> str:
    """请求 content-type(req headers 是 list[{name,value}](store.get 的
    HttpRequest.to_dict 格式)或 dict{原大小写 key}(recorder 内存形),casefold 查)。

    复用 http._header_pairs 归一化两种 shape——store.get 返 list[{name,value}],
    旧代码按 dict .items() 走会在真实 multipart 上传流量上崩(list 无 items)。
    """
    return next(
        (v for k, v in _header_pairs(req.get("headers")) if k.casefold() == "content-type"),
        "",
    )


def _is_binary_upload(req: dict[str, Any], post: Any) -> bool:
    """请求体是否二进制 multipart 上传:content-type 含 multipart/form-data 且
    (len>8KB 或 U+FFFD≥100)。命中 → 走 _redact_multipart per-part 占位。"""
    if not isinstance(post, str) or not post:
        return False
    if len(post) <= _BINARY_UPLOAD_THRESHOLD and post.count("�") < _BINARY_UPLOAD_REPL_MIN:
        return False
    return "multipart/form-data" in _req_content_type(req).lower()


def _extract_boundary(content_type: str) -> str | None:
    """从 multipart content-type 提 boundary(大小写不敏感,去引号)。无则 None。"""
    for tok in (content_type or "").split(";"):
        tok = tok.strip()
        if tok.lower().startswith("boundary="):
            return tok[len("boundary="):].strip().strip('"')
    return None


def _redact_multipart(post: str, content_type: str) -> str | None:
    """multipart per-part 占位:保留 part 头(字段名/文件名/content-type)+ 文本字段值,
    只把含 U+FFFD(录制时二进制→控制字符替换残留)的 part body 替成 [二进制 N字符]。

    返重写的 multipart 串(截断 _MAX_BODY);解析失败(无 boundary / 无 part)返 None
    → 调用方 fallback 整体占位。boundary 与 part 头是 ASCII,post 即便 body 是
    U+FFFD soup 也可靠切分(切分逻辑对齐 tool 层 _parse_multipart_parts)。
    N 字符是录制后 sanitized 长度(U+FFFD 压了原多字节二进制),非原字节数,故标"字符"。
    """
    boundary = _extract_boundary(content_type)
    if not boundary:
        return None
    sep = "--" + boundary
    chunks = post.split(sep)
    if len(chunks) < 3:  # 首段 preamble + 末段 --结尾,中间才是 parts;<3 = 无 part
        return None
    out_parts: list[str] = []
    for chunk in chunks[1:-1]:
        c = chunk.lstrip("\r\n")
        hsep = c.find("\r\n\r\n")
        if hsep < 0:
            # 无头/体分隔的异常 part:原样留(lstripped),不替
            out_parts.append(c)
            continue
        head, body = c[:hsep], c[hsep + 4:]
        if "�" in body:  # 二进制残留 → 占位,保留 head(字段名/文件名/ct 都在头里)
            n = len(body.rstrip("\r\n"))
            body = f"[二进制 {n}字符]\r\n"
        out_parts.append(f"{head}\r\n\r\n{body}")
    if not out_parts:
        return None
    rebuilt = sep + "\r\n" + (sep + "\r\n").join(out_parts) + sep + "--\r\n"
    return rebuilt[:_MAX_BODY]


def _min_unit(full: dict[str, Any], *, method: str,
              host: str, raw_path: str, request_id: str,
              noise_query_keys: set[str] | None = None) -> dict[str, Any]:
    """从 store.get 全量记录摊一个 clean 行。

    一遍 store.get 里顺手提,不二次扫 traffic。raw_path 是 traffic.path 列(无 query),
    query 从 url 取(urlsplit)再截断 _MAX_QUERY。1 rep/cluster,直接 min_unit。
    cluster_key 不落表(去重身份是内部,agent 不要)。

    noise_query_keys: 该 host 内出现频次>阈值(默认 50%)的 query key——host 级框架/
    风控参数(aid/device_type 这种该站每条都塞的),从 clean.query 展示串剔除(只过滤
    展示层,原始 traffic.sqlite 全留取证)。build_clean 按子域名统计后传入(per-host)。
    """
    req = full.get("request") or {}
    resp = full.get("response") or {}
    url = req.get("url") or ""
    query = urlsplit(url).query
    if noise_query_keys and query:
        kept = [(k, v) for k, v in parse_qsl(query, keep_blank_values=True)
                if k not in noise_query_keys]
        query = urlencode(kept)
    post = req.get("post_data")
    if _is_binary_upload(req, post):
        # 二进制 multipart 上传 → per-part 占位:保留字段名/文件名/ct + 文本字段值,只替
        # 二进制 part body;解析失败(boundary 缺/无 part)才 fallback 整体占位
        ct = _req_content_type(req)
        redacted = _redact_multipart(post, ct) if isinstance(post, str) else None
        if redacted is not None:
            json_body, form_body = "", redacted
        else:
            json_body, form_body = "", f"[二进制上传 {ct.split(';')[0].strip()}]"
    else:
        json_body, form_body = _json_body_of(post), _form_body_of(post)
    return {
        "request_id": request_id,
        "method": method,
        "host": host,
        "path": raw_path,
        "query": query[:_MAX_QUERY],
        "json_body": json_body,
        "form_body": form_body,
        "response": _response_of(resp.get("body_text"), resp.get("content_type")),
        "status": resp.get("status"),
    }


def _clean_path(session_dir: str | Path) -> Path:
    return Path(session_dir) / "pipeline" / "proxy" / "clean.jsonl"


def write_clean_jsonl(session_dir: str | Path,
                      rows: list[dict[str, Any]]) -> Path:
    """落 clean 行到 session_dir/pipeline/proxy/clean.jsonl(一行一 cluster,JSON lines)。

    dispatch 读这个(tool store.list_clean 改读 jsonl,Phase2)。clean 不进 sqlite
    (invariant #4:clean/nosie/multipart 走文件不经 store)。
    """
    p = _clean_path(session_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(r, ensure_ascii=False) for r in rows]
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return p


def build_clean(session_dir: str | Path,
                *, threshold: float = 0.5) -> dict[str, Any]:
    """record 尾跑:filter→clusters + nosie→common_params → min_unit → 写 clean.jsonl + noise.jsonl。

    纯函数(读 traffic.sqlite history → 写 session_dir/pipeline/proxy/),独立可调,不依赖录制。
    返回统计:total_raw / kept(post-drop pre-dedup)/ clusters / clean / skipped_* /
    common_params + 落盘文件路径。空 history → 空 clean.jsonl + 空 noise.jsonl(不崩)。

    两阶段 noise drop 顺序不可换(summary 先省 full 力气);common_params 消费 clusters
    (post-drop+post-dedup)不读 raw(频次按 cluster 计,噪音不进计数)。
    """
    store = ProxyStore(session_dir)
    noise = NoiseFilter.load()  # lib/filter.py + filter.yaml

    all_summaries = store.list_all_raw_summaries()
    total_raw = len(all_summaries)

    # 1. summary 阶段噪音 drop(host/method/path/query + 静态后缀 + OPTIONS,预去重)
    summaries, sk_noise = drop_summary(all_summaries, noise)
    # 2. method|host|noQuery 去重 → 1 rep/cluster(body 优先)
    clusters, sk_static, sk_options = dedup(summaries)

    # nosie:公共参数消费 clusters(post-drop+post-dedup rep 集),不读 raw。
    # 按子域名分组统计(host 内 key 频次>threshold),跨 host 共享 key 剔除(资源标识符)。
    cluster_reps = [c["rep"] for c in clusters.values()]
    common_params_list = nosie.common_params(cluster_reps, threshold=threshold)
    noise_qkeys_by_host = nosie.noise_query_keys_by_host(common_params_list)
    nosie_path = nosie.write_nosie_json(session_dir, common_params_list)

    # 3. full 阶段:per cluster store.get full + matches_full(只判 body 规则)→ min_unit
    min_units: list[dict[str, Any]] = []
    sk_noise_body = 0
    for key, c in clusters.items():
        rid = c["rep"]["request_id"]
        full = store.get(rid) or {}
        if full and noise.has_body_rules and noise.matches_full(full):
            sk_noise_body += 1
            continue
        host = (c["rep"]["host"] or "").lower()
        min_units.append(_min_unit(
            full, method=c["rep"]["method"],
            host=c["rep"]["host"], raw_path=c["rep"]["path"], request_id=rid,
            noise_query_keys=noise_qkeys_by_host.get(host, set())))

    clean_path = write_clean_jsonl(session_dir, min_units)

    return {
        "total_raw": total_raw,
        "kept": len(summaries) - sk_static - sk_options,
        "skipped_static": sk_static,
        "skipped_options": sk_options,
        "skipped_noise": sk_noise + sk_noise_body,
        "clusters": len(clusters),
        "clean": len(min_units),
        "common_params": common_params_list,
        "clean_jsonl": str(clean_path),
        "nosie_json": str(nosie_path),
    }
