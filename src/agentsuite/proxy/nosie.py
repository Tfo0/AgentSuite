"""lib nosie:公共参数(common_params)剥离 → 写 noise.jsonl。

「nosie」= common params 的历史拼写(用户沿用,不重命名)。公共参数 = 某子域名(host)
下、>threshold 流量都带的 query key——该 host 的框架/风控参数(aid/device_type/sign
这种该站每条都塞的),换号无意义,从 clean.query 展示层 + dispatch keys 剥离。

判定(2026-10 重写,弃值判键 + 按子域名):
- 按子域名(host)分组,host 内 key 出现频次 >threshold 才算该 host 公共参数。
- 判 key 出现(不判值恒定):旧 distinct=1 错——资源标识符 shopid 用户只录一个值也
  恒定,会被误剥;改判 key 频次后,资源标识符只挂相关端点(<50%)不进,框架参数每
  端点都挂(>50%)进。
- 跨 ≥2 host 都 >threshold 的 key → 跨域资源标识符(a.test.com 和 b.test.com 都带的
  shopid),必须测,剔除不剥(用户例:shopid 跨子域共享,b 必须测 shopid)。

消费 filter 的 clusters(post-drop+post-dedup 的 rep 集),不读 raw——频次按 host 内
cluster(唯一端点)计不按 raw 条数,噪音请求不进计数(invariant #6)。host 内
<_MIN_SAMPLE → 不判(小样本易全中)。

产物落 session_dir/pipeline/proxy/noise.jsonl(喂 dispatch/verify prompt 注入 + dispatch_service
strip dispatch keys)。clean/nosie 走文件不经 store(invariant #4)。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

_THRESHOLD = 0.5
_MIN_SAMPLE = 5


def common_params(clusters: list[dict[str, Any]], *,
                  threshold: float = _THRESHOLD) -> list[dict[str, Any]]:
    """clusters → 公共参数表 [{key, host, freq}],按 host 再 freq 降序。

    按子域名(host)分组:host 内 key 出现频次 >threshold → 该 host 公共参数(判键不
    判值)。跨 ≥2 host 都 >threshold 的 key → 跨域资源标识符,剔除(必须测)。

    clusters 是 filter 产出的 post-drop+post-dedup rep 集(含 url/host)。host 从
    rep.host 取,缺则 urlsplit(url).netloc。host 内 <_MIN_SAMPLE → 不判。分母 =
    该 host 的 cluster 数(唯一端点)。
    """
    by_host: dict[str, list[dict[str, Any]]] = {}
    for s in clusters:
        h = (s.get("host") or "").lower()
        if not h:
            h = (urlsplit(s.get("url") or "").netloc or "").lower()
        if not h:
            continue
        by_host.setdefault(h, []).append(s)

    host_key_freq: dict[str, dict[str, tuple[int, int]]] = {}
    for h, reps in by_host.items():
        n = len(reps)
        if n < _MIN_SAMPLE:
            continue
        counts: dict[str, int] = {}
        for s in reps:
            q = urlsplit(s.get("url") or "").query
            if not q:
                continue
            # 单 rep 内重复 key(?tag=a&tag=b)只计一次——count 是含该 key 的 rep 数
            # (≤n),非出现次数;否则重复 key 膨胀 c/n,把只挂 <50% reps 的 key 误剥
            # (契约:频次按 cluster 计/每端点都挂才进,单位是端点不是出现次数)。
            seen = {k for k, _ in parse_qsl(q, keep_blank_values=True)}
            for k in seen:
                counts[k] = counts.get(k, 0) + 1
        host_key_freq[h] = {k: (c, n) for k, c in counts.items()
                            if n and c / n > threshold}

    # 跨 host 共享(≥2 host 都 >threshold)→ 跨域资源标识符,剔除(必须测)
    key_hosts: dict[str, set[str]] = {}
    for h, kmap in host_key_freq.items():
        for k in kmap:
            key_hosts.setdefault(k, set()).add(h)
    cross_host = {k for k, hs in key_hosts.items() if len(hs) >= 2}

    out: list[dict[str, Any]] = []
    for h, kmap in host_key_freq.items():
        for k, (c, n) in kmap.items():
            if k in cross_host:
                continue
            out.append({"key": k, "host": h, "freq": round(c / n, 4)})
    out.sort(key=lambda p: (p["host"], -p["freq"]))
    return out


def noise_query_keys_by_host(common_params_list: list[dict[str, Any]]
                             ) -> dict[str, set[str]]:
    """common_params 结果 → {host: set[keys]}(clean.query 按 host 剔展示层)。

    精剔:某 key 只从它所属 host 的 clean 行 query 里剔,不污染别的 host(那上面
    该 key 可能 <50% 是信号)。
    """
    out: dict[str, set[str]] = {}
    for p in common_params_list:
        out.setdefault(p.get("host", ""), set()).add(p["key"])
    return out


def noise_query_keys(clusters: list[dict[str, Any]], *,
                     threshold: float = _THRESHOLD) -> set[str]:
    """公共参数 key 全集(跨 host 并集,= common_params 的 key 投影)。

    dispatch_service strip 用(global union 安全:跨域资源标识符已在上游剔除,剩
    下的都是 host 级框架参数)。clean.query 展示层用 noise_query_keys_by_host(按
    host 精剔)。
    """
    return {p["key"] for p in common_params(clusters, threshold=threshold)}


def _nosie_path(session_dir: str | Path) -> Path:
    return Path(session_dir) / "pipeline" / "proxy" / "noise.jsonl"


def write_nosie_json(session_dir: str | Path, params: list[dict[str, Any]]) -> Path:
    """落 common_params 到 session_dir/pipeline/proxy/noise.jsonl(喂 dispatch/verify prompt)。"""
    p = _nosie_path(session_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(params, ensure_ascii=False), encoding="utf-8")
    return p


def read_nosie_json(session_dir: str | Path) -> list[dict[str, Any]]:
    """读 noise.jsonl;缺/坏/非 list → 空表(降级不崩)。"""
    p = _nosie_path(session_dir)
    try:
        if not p.is_file():
            return []
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [d for d in data if isinstance(d, dict) and d.get("key")]
