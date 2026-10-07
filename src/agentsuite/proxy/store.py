"""proxy 的 traffic.sqlite io 出口:录制写 history + build_clean 读 history。

recorder.py 的 dump + _exchanges_from_records 落这。store.py 是
proxy 唯一 sqlite io 出口:filter/nosie/clean/recorder 调它,不自己写 SQL。clean 不进
sqlite(改 clean.jsonl,见 clean.py),故本文件无 clean 表。

proxy 不 import tool(避免跨线),故自写 history 读写 + schema(与 tool/data/store 的
history 表同列同约束——store 注释显式对齐本文件前身 store)。

history 表 schema 与 store._HISTORY_DDL 字节对齐(同列同约束同索引),改任一处须同步。
agent id 统一 <kind>:<seq>:原始流量 id=history:<id>(自增 rowid);exchange_id(flow.id)
是 history 内部去重键 UNIQUE,不给 agent。
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

from agentsuite.proxy.http import HttpBody, HttpExchange, HttpHeader, HttpRequest, HttpResponse, _body_field, _body_text

_SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exchange_id TEXT NOT NULL UNIQUE,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    request_json TEXT NOT NULL,
    response_json TEXT,
    status_code INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_history_exchange ON history (exchange_id);
"""


# ── 写:recorder dump(mitmproxy CaptureAddon records → HttpExchange → history)──

def _exchanges_from_records(
    records: list[dict[str, Any]],
    *,
    source: str = "history",
    skip_non_http: bool = True,
) -> list[HttpExchange]:
    """records → HttpExchange。内嵌转换(同 store 逻辑,lib 不 import a 线)。

    跳过 data:image/font 等非业务请求,只保留 http:// https:// 的 XHR/fetch/doc。
    record 字段由 mitmproxy CaptureAddon 产。source 留参兼容(history 表无 source 列,
    值不用——history 是唯一来源)。
    """
    exchanges: list[HttpExchange] = []
    for record in records:
        req = record.get("request") or {}
        url = str(req.get("url") or "")
        if skip_non_http and not url.startswith(("http://", "https://")):
            continue
        method = str(req.get("method") or "GET")
        req_headers = tuple(
            HttpHeader(str(k), str(v))
            for k, v in (req.get("headers") or {}).items()
        )
        post_data = req.get("post_data")
        req_body = (
            HttpBody(text=str(post_data), content_type=_header_value(req_headers, "content-type"))
            if post_data else None
        )
        request = HttpRequest(method=method, url=url, headers=req_headers, body=req_body)

        response = None
        raw_resp = record.get("response")
        if isinstance(raw_resp, dict):
            resp_headers = tuple(
                HttpHeader(str(k), str(v))
                for k, v in (raw_resp.get("headers") or {}).items()
            )
            resp_body = None
            if raw_resp.get("body_text"):
                resp_body = HttpBody(
                    text=str(raw_resp["body_text"]),
                    content_type=raw_resp.get("content_type"),
                )
            response = HttpResponse(
                status=int(raw_resp.get("status") or 0),
                headers=resp_headers,
                body=resp_body,
            )

        exchange_id = str(record.get("request_id") or f"flow:{method}:{url}")
        exchanges.append(HttpExchange(
            exchange_id=exchange_id,
            source=source,
            request=request,
            response=response,
        ))
    return exchanges


def _header_value(headers: tuple[HttpHeader, ...], name: str) -> str | None:
    lower = name.casefold()
    for header in headers:
        if header.name.casefold() == lower:
            return header.value
    return None


class ProxyStore:
    """traffic.sqlite 的 proxy io 出口:写 history(录制 dump)+ 读 history(build_clean)。

    database_path=None 用内存 sqlite(测试)。clean/nosie 走文件不经本类。
    session_dir=/path → /path/pipeline/proxy/traffic.sqlite(平级 proxy/ 子目录,
    ProxyStore 接 session_dir 内部拼 pipeline/proxy/;recorder 传 session_dir,不传子目录)。
    """

    def __init__(self, session_dir=None, *, database_path=None):
        if database_path is not None:
            self.database_path = Path(database_path).resolve()
        elif session_dir is not None:
            self.database_path = (Path(session_dir) / "pipeline" / "proxy" / "traffic.sqlite").resolve()
        else:
            self.database_path = None
        # 内存模式复用单条连接(:memory: 每次新建=数据不跨调用持久,build_clean
        # dump 后 list_all_raw_summaries 读空)。对齐 tool/data/store._connect 模式。
        self._memory: sqlite3.Connection | None = None

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """history 库连接(pipeline/proxy/traffic.sqlite)。

        内存模式(database_path=None)复用 self._memory(单条 :memory: 连接,跨调用
        持久);文件模式每次 connect 用完即 close(对齐 tool/data/store._connect)。
        读路径(list_all_raw_summaries/get)也建父目录 + executescript(_SCHEMA)(IF
        NOT EXISTS 幂等),让 build_clean 在全新 session_dir(无 prior dump)独立可调不崩。
        WAL + busy_timeout(5s)对齐 tool store(并发 dispatch/claim 不互斥)。
        """
        if self.database_path is None:
            if self._memory is None:
                self._memory = sqlite3.connect(":memory:")
                self._memory.row_factory = sqlite3.Row
                self._memory.executescript(_SCHEMA)
                self._memory.commit()
            yield self._memory
            return
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.database_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(_SCHEMA)  # IF NOT EXISTS 幂等;standalone build_clean 要
        conn.commit()
        try:
            yield conn
        finally:
            conn.close()

    def dump(self, records: list[dict[str, Any]]) -> tuple[int, list[str]]:
        """把 records 落 traffic.sqlite(history 表,原始流量行)。

        返回 (写入条数, exchange_id 列表)。exchange_id 是内部去重键(flow.id /
        request_XXXXXX),不给 agent——agent 见 history:<id>(list_all_raw_summaries 投影)。
        records 空返回 (0, []),不建库(无谓写入)。
        """
        if not records:
            return 0, []
        if self.database_path is not None:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        exchanges = _exchanges_from_records(records)
        traffic_ids: list[str] = []
        with self._connect() as conn:
            for ex in exchanges:
                conn.execute(
                    """INSERT OR REPLACE INTO history
                       (exchange_id, method, url, host, path,
                        request_json, response_json, status_code, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                    (
                        ex.exchange_id,
                        ex.request.method,
                        ex.request.url,
                        urlsplit(ex.request.url).hostname or "",
                        urlsplit(ex.request.url).path or "/",
                        json.dumps(ex.request.to_dict(), ensure_ascii=False),
                        json.dumps(ex.response.to_dict(), ensure_ascii=False) if ex.response else None,
                        ex.response.status if ex.response else None,
                    ),
                )
                traffic_ids.append(ex.exchange_id)
            conn.commit()
        return len(traffic_ids), traffic_ids

    def list_all_raw_summaries(self):
        """全量读 history 摘要(build_clean dedup 用)。

        供 build_clean 去重用:只取列(method/url/host/path/status)+ body 是否非空
        (length(json_extract(response_json,'$.body.text'))>0,rep 选 body 优先用)
        + 响应 content_type(按响应类型丢 JS 等)。
        返回 [{request_id, method, url, host, path, status, has_body, response_ct}]。
        host/path 直读列;response_ct 从 $.body.content_type 取。
        """
        out = []
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT id, method, url, host, path, status_code, "
                "coalesce(length(json_extract(response_json,'$.body.text')),0) AS blen, "
                "coalesce(json_extract(response_json,'$.body.content_type'),'') AS rct "
                "FROM history ORDER BY id"
            )
            for row in cur:
                out.append({
                    "request_id": f"history:{row['id']}",
                    "method": row["method"],
                    "url": row["url"],
                    "host": (row["host"] or "").lower(),
                    "path": row["path"] or "/",
                    "status": row["status_code"],
                    "has_body": row["blen"] > 0,
                    "response_ct": (row["rct"] or "").lower(),
                })
        return out

    def get(self, traffic_id):
        """按 id 读单条 history。history:<id> → {request, response};其余 None。

        request_json 是 HttpRequest.to_dict():{method,url,headers(list[{name,value}]),
        body(HttpBody dict)}。response_json 是 HttpResponse.to_dict()。post_data/body_text
        取 body.text,content_type 取 body.content_type(同 store._get_raw,build_clean 用)。
        """
        if not isinstance(traffic_id, str) or not traffic_id.startswith("history:"):
            return None
        try:
            num = int(traffic_id[len("history:"):])
        except (TypeError, ValueError):
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT request_json, response_json, status_code FROM history WHERE id=?",
                (num,),
            ).fetchone()
            if row is None:
                return None
            req = json.loads(row["request_json"]) if row["request_json"] else {}
            resp = json.loads(row["response_json"]) if row["response_json"] else {}
            status_code = row["status_code"]
        return {
            "request": {
                "method": req.get("method"),
                "url": req.get("url"),
                "headers": req.get("headers"),
                "post_data": _body_text(req.get("body")),
            },
            "response": {
                "status": resp.get("status") or status_code,
                "headers": resp.get("headers"),
                "content_type": _body_field(resp.get("body"), "content_type"),
                "body_text": _body_text(resp.get("body")),
            },
        }
