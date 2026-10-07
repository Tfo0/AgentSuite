"""proxy filter:NoiseFilter(类 + filter.yaml 加载)+ drop/summary/dedup。

own NoiseFilter(proxy:recorder 采集时 + build_clean 漏斗处共享同一份)。filter.yaml
紧贴本模块(proxy/filter.yaml),load() 读它。
drop_noise(录制落盘前 matches_record)+ drop_summary(预去重 matches_summary)+
dedup(method|host|noQuery)+ matches_full(cluster rep body 规则)。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

# filter.yaml 紧贴本模块(lib/),recorder 与 build_clean 共享读。
_FILTER_YAML = Path(__file__).resolve().parent / "filter.yaml"


class NoiseFilter:
    """编译后的噪音拒绝规则。

    无参数构造 = 空规则(不过滤,降级用)。load() 从 filter.yaml 读并编译;
    缺失/解析失败 → 空规则(不崩)。测试可传自定义 rules 隔离 prod yaml。
    """

    def __init__(self, rules: list[dict[str, Any]] | None = None) -> None:
        # __init__ 也走 _compile:接受 raw 规则(host/path/... dict,未归一 5 字段)
        # 或已编译规则,统一成 {name, host, path, query, body, method} 五字段齐全。
        # 空规则(无任何字段)跳过(否则全匹配丢一切)。无参数 = 空规则(不过滤,降级用)。
        self._rules: list[dict[str, Any]] = self._compile(rules or [])

    @classmethod
    def load(cls, path: Path | str | None = None) -> "NoiseFilter":
        """从 filter.yaml 读 + 编译。缺失/坏 yaml → 空规则(不崩)。"""
        p = Path(path) if path else _FILTER_YAML
        try:
            raw = p.read_text(encoding="utf-8")
        except Exception:
            return cls()  # 缺失 → 不过滤
        try:
            data = yaml.safe_load(raw) or {}
        except Exception:
            return cls()
        return cls(cls._compile(data.get("drop") or []))

    @staticmethod
    def _compile(drop: list[Any]) -> list[dict[str, Any]]:
        """raw drop 列表 → 编译规则列表。空规则(无任何字段)跳过(否则全匹配丢一切)。"""
        rules: list[dict[str, Any]] = []
        for r in drop:
            if not isinstance(r, dict):
                continue
            host = _lower_strs(r.get("host"))
            path = _lower_strs(r.get("path"))
            path_endswith = _lower_strs(r.get("path_endswith"))
            query = _lower_strs(r.get("query"))
            body = _lower_strs(r.get("body"))
            response_ct = _lower_strs(r.get("response_ct"))
            method = [str(m).upper() for m in (r.get("method") or [])
                      if isinstance(m, str) and m.strip()]
            if not (host or path or path_endswith or query or body or response_ct or method):
                continue  # 全空规则 = 通配丢一切,危险,跳过
            rules.append({
                "name": str(r.get("name") or ""),
                "host": host, "path": path, "path_endswith": path_endswith,
                "query": query, "body": body, "response_ct": response_ct, "method": method,
            })
        return rules

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def has_body_rules(self) -> bool:
        """是否含 body 规则(决定 build_clean full 阶段要不要取 post_data 比对)。"""
        return any(r["body"] for r in self._rules)

    @property
    def static_suffixes(self) -> list[str]:
        """所有规则的 path_endswith 合并(单一来源 filter.yaml,供 fuzz_service 等查静态后缀)。

        fuzz 主动探测收集候选时用它跳过静态端点(省力气),和 build_clean 过滤共享
        同一份后缀——改 filter.yaml 的 static-asset-suffix 规则即同步生效,不在
        fuzz_service 再硬编码一份。
        """
        out: list[str] = []
        for r in self._rules:
            out.extend(r["path_endswith"])
        return out

    def matches_record(self, record: dict[str, Any]) -> bool:
        """录製时一次过判全规则全维度(record 有 method/url/post_data 全字段)。

        不像 build_clean 的两阶段拆 summary/full(summary 无 body 才拆),录製时拿到
        完整 record(request+response),host/method/path/query/body 全有,一遍过所有
        规则所有维度。供 run_record_session_mitm 落盘前 drop 噪音 record 用。
        record 是 mitmproxy CaptureAddon 产的 record dict:{request:{method,url,
        resource_type,headers,post_data,post_data_truncated}, response:{...}, ...}。
        """
        if not self._rules:
            return False
        req = record.get("request") or {}
        sp = urlsplit(req.get("url") or "")
        method = (req.get("method") or "GET").upper()
        host = (sp.netloc or "").lower()
        path = (sp.path or "/").lower()
        query = (sp.query or "").lower()
        post = req.get("post_data")
        if isinstance(post, str):
            body = post.lower()
        elif isinstance(post, (dict, list)):
            body = json.dumps(post, ensure_ascii=False).lower()
        else:
            body = ""
        resp = record.get("response") or {}
        response_ct = (resp.get("content_type") or "").lower()
        for r in self._rules:
            if _all_fields_match(r, method, host, path, query, body, response_ct=response_ct):
                return True
        return False

    def matches_summary(self, summary: dict[str, Any]) -> bool:
        """summary 阶段(build_clean 预去重):匹配 host/method/path/query/response_ct。

        summary 是 store.list_all_raw_summaries 返回的 {request_id, method, url,
        host, path, status, has_body, response_ct}。body 字段规则此阶段跳过(summary
        无 post_data)→ 留 matches_full 在 cluster rep 上判。命中任一非 body 规则即丢。
        response_ct 是非 body 维度(summary 带它),JS-by-response-ct 在此阶段 pre-dedup 丢。
        """
        method = (summary.get("method") or "GET").upper()
        host = (summary.get("host") or "").lower()
        path = (summary.get("path") or "/").lower()
        query = urlsplit(summary.get("url") or "").query.lower()
        response_ct = (summary.get("response_ct") or "").lower()
        for r in self._rules:
            if r["body"]:
                continue  # body 规则留 full 阶段
            if _all_fields_match(r, method, host, path, query, body="", response_ct=response_ct):
                return True
        return False

    def matches_full(self, full: dict[str, Any]) -> bool:
        """full 阶段(build_clean 去重后取 cluster rep):只判含 body 字段的规则。

        full 是 store.get(rid) 返回的 {request: {method, url, post_data, ...},
        response: {...}}。host/path 从 url 取(full 无 host/path 列);body 从
        post_data 取(str 直接小写,dict/list 先 dumps)。无 body 规则的已在
        summary 阶段判完,此处只过 body 规则(它们可能还组合了 host 等字段)。
        """
        if not self._rules or not self.has_body_rules:
            return False
        req = full.get("request") or {}
        sp = urlsplit(req.get("url") or "")
        method = (req.get("method") or "GET").upper()
        host = (sp.netloc or "").lower()
        path = (sp.path or "/").lower()
        query = (sp.query or "").lower()
        post = req.get("post_data")
        if isinstance(post, str):
            body = post.lower()
        elif isinstance(post, (dict, list)):
            body = json.dumps(post, ensure_ascii=False).lower()
        else:
            body = ""
        resp = full.get("response") or {}
        response_ct = (resp.get("content_type") or "").lower()
        for r in self._rules:
            if not r["body"]:
                continue  # 非 body 规则已 summary 阶段判完,不重判
            if _all_fields_match(r, method, host, path, query, body, response_ct=response_ct):
                return True
        return False


def _lower_strs(val: Any) -> list[str]:
    """yaml 字段值 → 小写 substring 列表。支持单串或列表,过滤空/非串。"""
    if isinstance(val, str):
        items = [val]
    elif isinstance(val, (list, tuple)):
        items = [v for v in val if isinstance(v, str)]
    else:
        return []
    return [v.lower() for v in items if v.strip()]


def _all_fields_match(rule: dict[str, Any], method: str, host: str,
                      path: str, query: str, body: str,
                      response_ct: str = "") -> bool:
    """规则内 AND:列出的字段全满足才丢。省略字段(list 空)= 该维度不约束(通配)。

    host/path/query/body/response_ct: 任一 substring 命中即满足该字段。
    path_endswith: path 末尾后缀精确匹配(任一 endswith 命中即满足)——区别于 path
      substring:后缀要精确(防 .json substring 误杀 /api.json/v2 这类 RESTful 中段)。
    response_ct: 响应 content-type 小写 substring(任一命中即满足)——按响应类型丢
      (application/javascript 等),补 request 后缀盲区:JS 从非 .js 路径出时 request 侧
      看不出(SPA chunk / CDN 重写挂 API 风格路径),响应 ct 才是权威信号。非 body 维度,
      summary 阶段(summary 带 response_ct)+ full/record 阶段(response 有 content_type)都能判。
    method: 任一精确等于即满足。空 list = 该字段不约束(不影响其它字段判断)。
    """
    if rule["method"] and method not in rule["method"]:
        return False
    if rule["host"] and not any(k in host for k in rule["host"]):
        return False
    if rule["path"] and not any(k in path for k in rule["path"]):
        return False
    if rule["path_endswith"] and not any(path.endswith(s) for s in rule["path_endswith"]):
        return False
    if rule["query"] and not any(k in query for k in rule["query"]):
        return False
    if rule["body"] and not any(k in body for k in rule["body"]):
        return False
    if rule["response_ct"] and not any(k in response_ct for k in rule["response_ct"]):
        return False
    return True


def drop_noise(records: list[dict[str, Any]], noise: NoiseFilter
              ) -> tuple[list[dict[str, Any]], int]:
    """落盘前 drop 噪音流量,返回 (kept, skipped_count)。

    noise 无规则(rule_count=0)时原样返回(不滤),与原内联逻辑一致。有规则时
    按 matches_record 整条丢,计数 = 原量 - 留量。
    """
    if not noise.rule_count:
        return records, 0
    kept = [r for r in records if not noise.matches_record(r)]
    return kept, len(records) - len(kept)


def drop_summary(summaries: list[dict[str, Any]], noise: NoiseFilter
                 ) -> tuple[list[dict[str, Any]], int]:
    """summary 阶段噪音 drop:host/method/path/query 关键词(预去重,省 dedup 力气)。

    无规则(NoiseFilter 空)= 不过滤,原样返回(skipped=0)。命中任一非 body
    规则 → drop。body 规则留 matches_full 在 cluster rep 上判(summary 无 post_data)。
    """
    if not noise.rule_count:
        return summaries, 0
    kept: list[dict[str, Any]] = []
    sk = 0
    for s in summaries:
        if noise.matches_summary(s):
            sk += 1
        else:
            kept.append(s)
    return kept, sk


def dedup(summaries: list[dict[str, Any]]
          ) -> tuple[dict[str, dict[str, Any]], int, int]:
    """method|host|noQuery 去重,1 rep/cluster(body 优先)。

    静态后缀 + OPTIONS drop 已在 drop_summary(matches_summary 判 filter.yaml 的
    static-asset-suffix path_endswith + options-cors-preflight method),此处不重复判。
    skipped_static / skipped_options 留 0 兼容返回(并入 skipped_noise)。
    cluster_key=host|METHOD|noQuery(noQuery=path 去 ? 及之后,raw path 不归一 {id})。
    同 key 多 history 行 → 只留 has_body 优先的代表(无 body 的对敏感字段判断无用)。
    返回 (clusters{key:{rep,count}}, skipped_static, skipped_options)。
    """
    clusters: dict[str, dict[str, Any]] = {}
    sk_static = sk_options = 0  # 均已上移 drop_summary,留 0 兼容返回
    for s in summaries:
        method = (s.get("method") or "GET").upper()
        path = s.get("path") or "/"
        host = (s.get("host") or "").lower()
        if not host:
            continue
        nq = path.split("?", 1)[0] or "/"  # noQuery:path 去 ? 及之后
        key = f"{host}|{method}|{nq}"
        c = clusters.get(key)
        if c is None:
            clusters[key] = {"rep": s, "count": 1}
        else:
            c["count"] += 1
            # body 优先:有 body 的当代表(rank 敏感字段判断要 response_keys)
            if s.get("has_body") and not c["rep"].get("has_body"):
                c["rep"] = s
    return clusters, sk_static, sk_options
