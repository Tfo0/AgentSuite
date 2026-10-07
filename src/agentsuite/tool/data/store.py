"""traffic store:history + evidence 两表 DB(pipeline/proxy/traffic.sqlite)
+ dispatch_queue DB(agent 派活队列,pipeline/agent/dispatch_queue.sqlite 独立,不和
proxy 流量耦合)。

agent id 统一 <kind>:<seq> 格式:
- history:<id>          原始捕获流量(history 表自增 id)
- <source>:<source_seq>  重放证据(evidence 表,各 source 内自增)
  source = repeater/brute/send

history 表:mitmproxy 捕获的结构化 HttpExchange。host/path/method/url/status_code
独立列(去重/查询用);request_json/response_json 是 HttpRequest/HttpResponse.to_dict(),
body 是 HttpBody dict({text,content_type,file_path,...}),取 .text 才是裸体。path 列无
query(query 只在 url)。headers 是 list[{name,value}]。exchange_id=mitm flow.id(内部
去重键 UNIQUE,不给 agent)。

evidence 表:重放证据(repeater/brute/send,各 source 内 source_seq 自增,PRIMARY KEY
(source, source_seq))。request/response/baseline/edit/diff 存全量 JSON;source_id 链
history:<id>(send 从零构造传 "send" 字面量无 history 根,归属门禁天然拒,见
report_service._evidence_root_history)。旧版 evidence 曾出 DB 落 JSON 文件(artifact_store,
"冷产物"),已回迁进表(__init__ _migrate_evidence_jsonl 导入旧 evidence.jsonl)。接口不变,
调用方(service/工具/runner)零改。

HttpExchange DTO 在 model/http.py(共享)。
"""
from __future__ import annotations

import json
import sqlite3
import hashlib
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agentsuite.proxy.http import HttpBody, HttpHeader, HttpRequest, _body_field, _body_text

# 证据 id 前缀 → kind(= evidence.source)。agent id = <prefix>:<source_seq>。
# send=从零发包重放(traffic_send 产,source_id="send" 字面量无 history 根)。
# raw 前缀已退场(_migrate_legacy 把旧 DB raw_send/raw 行归一到 send),不在 map 里——
# raw:N 不再是合法证据 id(灭歧义:同工具只认 send:N 一个前缀)。
_PREFIX_KIND = {"repeater": "repeater", "brute": "brute", "send": "send"}


class AuditStore:
    """两表 DB history/evidence(traffic.sqlite)+ dispatch_queue DB(独立)。

    history/evidence/dispatch_queue 都进 sqlite。database_path=None 用内存 sqlite
    (history+evidence 共一个内存库;dispatch_queue 单独内存库,测试)。文件/内存库都在
    _connect 时建表(IF NOT EXISTS 幂等,不冲突)。
    """

    def __init__(self, database_path: str | Path | None = None, *,
                 session_dir: str | Path | None = None) -> None:
        self.database_path = Path(database_path).resolve() if database_path else None
        self.session_dir = Path(session_dir).resolve() if session_dir else None
        self._memory: sqlite3.Connection | None = None          # history+evidence 内存库(测试)
        self._queue_memory: sqlite3.Connection | None = None    # dispatch_queue 内存库(测试)
        # dispatch_queue 队列拆出 traffic.sqlite,单独落 pipeline/agent/dispatch_queue.sqlite
        # (agent 编排介质,不和 proxy 流量耦合)。无 session_dir(内存 sqlite 测试)→ None。
        if self.session_dir is not None:
            self.queue_path: Path | None = (
                self.session_dir / "pipeline" / "agent" / "dispatch_queue.sqlite").resolve()
        else:
            self.queue_path = None
        if self.database_path is not None:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if self.queue_path is not None:
            self.queue_path.parent.mkdir(parents=True, exist_ok=True)
        # traffic.sqlite:建 history+evidence 表 + 迁移旧 traffic 表 + 导入旧 evidence.jsonl
        with self._connect() as conn:
            conn.executescript(_HISTORY_DDL)
            conn.executescript(_EVIDENCE_DDL)
            self._migrate_legacy(conn)
            self._migrate_evidence_jsonl(conn)
            conn.execute("DROP TABLE IF EXISTS dispatch_queue")  # 已拆 queue db,旧 traffic.sqlite 残留清掉
            conn.commit()
        # queue db:建 dispatch_queue 表 + 迁移旧 schema(traffic_id 行→module 行)
        with self._connect_queue() as conn:
            conn.executescript(_DISPATCH_QUEUE_DDL)
            self._migrate_dispatch_queue(conn)
            conn.commit()

    def _migrate_legacy(self, conn: sqlite3.Connection) -> None:
        """一次性迁移:旧单表 traffic(capture+evidence 混)→ 2 表 history+evidence。

        (1) capture 行 → history(exchange_id 保留作内部去重键)。
        (2) evidence 行 → evidence(source=原 source,raw_send/raw→send 统一;source_seq 按
            source 内 rowid 序自增;source_id 若是 capture exchange_id → 转 history:<id>)。
        (3) DROP 旧 traffic(+ 索引随表删)。

        幂等:traffic 表不存在(新库)→ 跳过。迁移后 evidence source_seq 与旧 rowid 不同
        (各 source 内序)→ 旧 prefix:N 引用悬空,测试库可重跑重生。
        """
        tcols = {row["name"] for row in conn.execute("PRAGMA table_info(traffic)")}
        if not tcols:
            return  # 新库无旧 traffic 表,跳过

        # capture 行 → history,建 exchange_id→history.id 映射(给 evidence source_id 转)
        ex_to_hist: dict[str, int] = {}
        cap_rows = conn.execute(
            "SELECT exchange_id, method, url, host, path, request_json, response_json, "
            "status_code, created_at FROM traffic WHERE source='capture' ORDER BY id"
        ).fetchall()
        for r in cap_rows:
            c = conn.execute(
                "INSERT INTO history (exchange_id, method, url, host, path, "
                "request_json, response_json, status_code, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (r["exchange_id"], r["method"], r["url"], r["host"], r["path"],
                 r["request_json"], r["response_json"], r["status_code"], r["created_at"]),
            )
            ex_to_hist[r["exchange_id"]] = c.lastrowid

        # evidence 行 → evidence(source_seq 按 source 内序,source_id UUID→history:id)。
        # 旧单表 traffic 可能是早期 schema(只有 capture 基础列,无 source_id/baseline_json/
        # edit_json/diff_json/baseline_stable),按 tcols 实际有的列取,缺的填 NULL——否则
        # SELECT 不存在的列直接 OperationalError(如 b742 早期录制库全部 source=capture)。
        def _col(name: str) -> str:
            return name if name in tcols else "NULL"
        ev_rows = conn.execute(
            "SELECT source, " + _col("source_id") + " AS source_id, method, url, host, "
            "path, request_json, response_json, status_code, "
            + _col("baseline_json") + " AS baseline_json, "
            + _col("edit_json") + " AS edit_json, "
            + _col("diff_json") + " AS diff_json, "
            + _col("baseline_stable") + " AS baseline_stable, created_at "
            "FROM traffic WHERE source != 'capture' ORDER BY id"
        ).fetchall()
        seq_counter: dict[str, int] = {}
        for r in ev_rows:
            src = "send" if r["source"] in ("raw_send", "raw") else r["source"]
            seq_counter[src] = seq_counter.get(src, 0) + 1
            sid = r["source_id"] or ""
            if sid in ex_to_hist:  # source_id 是 capture exchange_id → 转 history:<id>
                sid = f"history:{ex_to_hist[sid]}"
            # evidence 已回 DB:evidence 行 INSERT 进 evidence 表(旧 traffic 行的
            # request_json/response_json 已是 JSON 串,直接搬;baseline/edit/diff 缺列→{})。
            conn.execute(
                "INSERT OR IGNORE INTO evidence "
                "(source, source_seq, source_id, request_json, response_json, "
                "baseline_json, edit_json, diff_json, baseline_stable) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (src, seq_counter[src], sid,
                 r["request_json"] or "{}",
                 r["response_json"] or "{}",
                 r["baseline_json"] or "{}",
                 r["edit_json"] or "{}",
                 r["diff_json"] or "{}",
                 1 if (r["baseline_stable"] is not None and r["baseline_stable"]) else 0),
            )
        conn.execute("DROP TABLE IF EXISTS traffic")
        # evidence 已回 DB(evidence 表),不再 DROP。dispatch_result 是真废弃表。
        conn.execute("DROP TABLE IF EXISTS dispatch_result")

    def _migrate_dispatch_queue(self, conn: sqlite3.Connection) -> None:
        """dispatch_queue 旧 schema → 新 module schema 的迁移。

        三档旧形状:
        - 最旧:traffic_id+skill 笛卡尔扇出行(无 traffic_ids_json)→ DROP 重建。
        - 中:module schema 但列名 skills_json(skill 词表统一前)→ DROP 重建为 skills_json。
          dispatch_queue 是派活工作单(运行态,重跑重生),DROP 只丢在途队列(可重录/重
          dispatch),不碰 history。
        - 新:已含 skills_json → 补 verify_verdict_json 列(2026-09-23 加,旧新 schema 库没有)。
        """
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(dispatch_queue)")}
        if not cols:
            return  # _DISPATCH_QUEUE_DDL 刚建的新形状(含 verify_verdict_json)
        if "traffic_ids_json" not in cols:
            # 最旧 schema:traffic_id+skill 行 → DROP 重建为新 module 行
            conn.execute("DROP TABLE dispatch_queue")
            conn.executescript(_DISPATCH_QUEUE_DDL)
            return
        if "skills_json" not in cols:
            # 旧 module schema(列名 skills_json,skill 词表统一前)→ DROP 重建为 skills_json
            conn.execute("DROP TABLE dispatch_queue")
            conn.executescript(_DISPATCH_QUEUE_DDL)
            return
        # 新 module schema — 补 verify_verdict_json 列(2026-09-23 加,旧新 schema 库没有)
        if "verify_verdict_json" not in cols:
            conn.execute("ALTER TABLE dispatch_queue ADD COLUMN verify_verdict_json TEXT")

    def _migrate_evidence_jsonl(self, conn: sqlite3.Connection) -> None:
        """旧 evidence.jsonl(artifact_store 时代,evidence 出 DB 落 JSON)→ evidence 表。

        evidence 已回 DB,旧 session 若留 pipeline/history/evidence.jsonl,在此导入新表。
        幂等:evidence 表非空(已迁/新写)→ 跳过。无 session_dir(内存测试)/jsonl 不存在 → 跳过。
        导入后不删 jsonl(留 backup;新写走表,jsonl 不再读)。
        """
        if self.session_dir is None:
            return
        jpath = self.session_dir / "pipeline" / "history" / "evidence.jsonl"
        if not jpath.is_file():
            return
        if conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] > 0:
            return  # 已迁或已有新数据
        for ln in jpath.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                d = json.loads(ln)
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(d, dict):  # 非 dict 行(裸串/数/手改坏行)跳过,不崩 init
                continue
            src = str(d.get("source") or "")
            if src not in _PREFIX_KIND:
                continue
            seq = d.get("source_seq")
            if not isinstance(seq, int):
                _, _, raw = str(d.get("traffic_id") or "").partition(":")
                if not raw.isdigit():
                    continue
                seq = int(raw)
            conn.execute(
                "INSERT OR IGNORE INTO evidence "
                "(source, source_seq, source_id, request_json, response_json, "
                "baseline_json, edit_json, diff_json, baseline_stable) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (src, seq, str(d.get("source_id") or ""),
                 json.dumps(d.get("request") or {}, ensure_ascii=False),
                 json.dumps(d.get("response") or {}, ensure_ascii=False),
                 json.dumps(d.get("baseline") or {}, ensure_ascii=False),
                 json.dumps(d.get("edit") or {}, ensure_ascii=False),
                 json.dumps(d.get("diff") or {}, ensure_ascii=False),
                 1 if d.get("baseline_stable") else 0),
            )

    # ---- 读:列表(history 原始流量 / evidence 重放证据) ----
    def list_raw(self, *, page_no: int = 1, page_size: int = 20,
                 resource_type: str | None = None,
                 source: str = "history") -> dict[str, Any]:
        """分页读流量摘要。

        source='history'(默认):原始流量(history 表),id=history:<id>。
        source='evidence':重放证据(evidence 表),id=<source>:<source_seq>,
            带 source/has_diff/baseline_stable——供 verify 读重放证据。
        resource_type 留参兼容(已 no-op:静态后缀+agent 自判取代 xhr/fetch)。
        返回 {total,page_no,page_size,items=[{request_id,method,url,status,post_data,
            source?,has_diff?,baseline_stable?}]}。
        """
        if page_no < 1:
            raise ValueError("page_no 不能小于 1")
        if page_size < 1 or page_size > 30:
            raise ValueError("page_size 必须在 1 到 30 之间")
        offset = (page_no - 1) * page_size
        items: list[dict[str, Any]] = []
        if source == "evidence":
            # evidence 已回 DB:分页读 evidence 表摘要
            # (traffic_id/method/host/path/status/post_data/source/has_diff/baseline_stable)。
            with self._connect() as conn:
                total = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
                rows = conn.execute(
                    "SELECT source, source_seq, source_id, request_json, "
                    "response_json, diff_json, baseline_stable "
                    "FROM evidence ORDER BY source, source_seq LIMIT ? OFFSET ?",
                    (page_size, offset),
                ).fetchall()
            for row in rows:
                req = json.loads(row["request_json"]) if row["request_json"] else {}
                resp = json.loads(row["response_json"]) if row["response_json"] else {}
                diff = json.loads(row["diff_json"]) if row["diff_json"] else {}
                parts = urlsplit(req.get("url") or "")
                items.append({
                    "traffic_id": f"{row['source']}:{row['source_seq']}",
                    "method": req.get("method"),
                    "host": (parts.hostname or ""),
                    "path": parts.path or "/",
                    "status": resp.get("status"),
                    "post_data": _body_text(req.get("body")),
                    "source": row["source"],
                    "source_id": row["source_id"] or "",
                    "has_diff": bool(diff.get("status") or diff.get("body")),
                    "baseline_stable": bool(row["baseline_stable"]),
                })
            return {"total": total, "page_no": page_no, "page_size": page_size, "items": items}
        else:
            with self._connect() as conn:
                total = conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]
                rows = conn.execute(
                    "SELECT id, method, url, host, path, request_json, status_code "
                    "FROM history ORDER BY id LIMIT ? OFFSET ?",
                    (page_size, offset),
                ).fetchall()
            for row in rows:
                req = json.loads(row["request_json"]) if row["request_json"] else {}
                items.append({
                    "traffic_id": f"history:{row['id']}",
                    "method": row["method"],
                    "host": (row["host"] or ""),
                    "path": row["path"] or "/",
                    "status": row["status_code"],
                    "post_data": _body_text(req.get("body")),
                })
        return {"total": total, "page_no": page_no, "page_size": page_size, "items": items}

    # ---- 读:全局子串搜 history(request+response)----
    def search_raw(self, needle: str, *, page_no: int = 1,
                   page_size: int = 20) -> dict[str, Any]:
        """全局子串搜 history 表(request_json + response_json),返匹配行 + 片段。

        upstream-tracing 用:目标流量用了不可遍历 id(UUID/密文),搜哪个流量的响应里
        出现过该 id → 找到 id 来源流量,再看其请求参数可否遍历。一次 LIKE 扫两列覆盖
        request(url/headers/body 全在 request_json)+ response(headers/body 全在
        response_json)全文本;无 FTS(history 表 per-session 千行级,LIKE 够快)。
        返 {total,page_no,page_size,items=[{traffic_id,method,host,path,status,
        matched_in,fragment}]}。matched_in 标 id 出现在 request 还是 response
        (upstream-tracing 要 response 命中=来源);fragment 是命中点 ±80 字符片段
        (单条多命中取首个)。evidence(JSON 文件 store)不进 SQL 搜,v1 只 history。
        """
        if not needle:
            raise ValueError("search 不能为空")
        if page_no < 1:
            raise ValueError("page_no 不能小于 1")
        if page_size < 1 or page_size > 30:
            raise ValueError("page_size 必须在 1 到 30 之间")
        pat = f"%{needle}%"
        offset = (page_no - 1) * page_size
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM history "
                "WHERE request_json LIKE ? OR response_json LIKE ?",
                (pat, pat),
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT id, method, url, host, path, status_code, "
                "request_json, response_json FROM history "
                "WHERE request_json LIKE ? OR response_json LIKE ? "
                "ORDER BY id LIMIT ? OFFSET ?",
                (pat, pat, page_size, offset),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            reqj = row["request_json"] or ""
            respj = row["response_json"] or ""
            matched: list[str] = []
            if needle in reqj:
                matched.append("request")
            if needle in respj:
                matched.append("response")
            # upstream-tracing 要 id 来源=response 命中优先;否则 request 命中
            src = respj if "response" in matched else reqj
            items.append({
                "traffic_id": f"history:{row['id']}",
                "method": row["method"],
                "host": row["host"] or "",
                "path": row["path"] or "/",
                "status": row["status_code"],
                "matched_in": matched,
                "fragment": _snippet(src, needle),
            })
        return {"total": total, "page_no": page_no, "page_size": page_size, "items": items}

    # ---- 读:单条(原始 history 或重放证据,按 id) ----
    def get(self, traffic_id: str) -> dict[str, Any] | None:
        """按 id 读单条。history:<id> → {request, response}(从 history 表解析)。
        <source>:<seq>(证据) → {request, response, baseline, edit, diff, baseline_stable, source_id}。"""
        if traffic_id.startswith("history:"):
            return self._get_raw(traffic_id)
        for prefix, kind in _PREFIX_KIND.items():
            if traffic_id.startswith(f"{prefix}:"):
                return self._get_evidence(traffic_id, prefix, kind)
        return None

    def _get_raw(self, request_id: str) -> dict[str, Any] | None:
        """从 history 表读原始流量,翻译成 {request, response} dict。

        request_json 是 HttpRequest.to_dict():{method,url,headers(list[{name,value}]),
        body(HttpBody dict)}。response_json 是 HttpResponse.to_dict():{status,reason,
        headers(list),body(HttpBody dict)}。post_data/body_text 取 body.text,
        content_type 取 body.content_type。headers 留 list(消费方 _min_unit 不用,
        get_raw_request 自己转 HttpHeader 元组)。
        """
        num = _parse_evidence_id(request_id, "history")
        if num is None:
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
        return {
            "request": {
                "method": req.get("method"),
                "url": req.get("url"),
                "headers": req.get("headers"),
                "post_data": _body_text(req.get("body")),
            },
            "response": {
                "status": resp.get("status") or row["status_code"],
                "headers": resp.get("headers"),
                "content_type": _body_field(resp.get("body"), "content_type"),
                "body_text": _body_text(resp.get("body")),
            },
        }

    def _get_evidence(self, evidence_id: str, prefix: str, kind: str) -> dict[str, Any] | None:
        # evidence 已回 DB:按 <source>:<source_seq> 直查 evidence 表(原样
        # request/response/baseline/edit/diff/baseline_stable/source_id,shape 同旧
        # record_json 消费者不变)。prefix/kind 留参兼容旧调用(traffic_id 自带命名空间)。
        del prefix, kind
        parsed = _split_evidence_id(evidence_id)
        if parsed is None:
            return None
        src, seq = parsed
        with self._connect() as conn:
            row = conn.execute(
                "SELECT source_id, request_json, response_json, baseline_json, "
                "edit_json, diff_json, baseline_stable FROM evidence "
                "WHERE source=? AND source_seq=?",
                (src, seq),
            ).fetchone()
        if row is None:
            return None
        return {
            "request": json.loads(row["request_json"]) if row["request_json"] else {},
            "response": _normalize_resp(
                json.loads(row["response_json"]) if row["response_json"] else {}),
            "baseline": _normalize_resp(
                json.loads(row["baseline_json"]) if row["baseline_json"] else {}),
            "edit": json.loads(row["edit_json"]) if row["edit_json"] else {},
            "diff": json.loads(row["diff_json"]) if row["diff_json"] else {},
            "baseline_stable": bool(row["baseline_stable"]),
            "source_id": row["source_id"],
        }

    # ---- 写:证据落盘(evidence 表,source+source_seq) ----
    def save_evidence(self, *, kind: str, source_id: str, request: dict,
                      response: dict, baseline: dict, edit: dict,
                      diff: dict, baseline_stable: bool) -> str:
        """写一条重放证据,返回 id(<source>:<source_seq>,source_seq 该 source 内自增)。

        evidence 在 DB:INSERT evidence 表(source_seq = 该 source 内 MAX+1)。
        接口不变,调用方(replay_service)零改。
        """
        src = _PREFIX_KIND.get(kind)
        if src is None:
            raise ValueError(f"未知证据 kind: {kind}(须 repeater/brute/send)")
        with self._connect() as conn:
            seq = conn.execute(
                "SELECT COALESCE(MAX(source_seq), 0) + 1 FROM evidence WHERE source=?",
                (src,),
            ).fetchone()[0]
            conn.execute(
                "INSERT INTO evidence "
                "(source, source_seq, source_id, request_json, response_json, "
                "baseline_json, edit_json, diff_json, baseline_stable) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (src, seq, source_id,
                 json.dumps(request, ensure_ascii=False),
                 json.dumps(response, ensure_ascii=False),
                 json.dumps(baseline, ensure_ascii=False),
                 json.dumps(edit, ensure_ascii=False),
                 json.dumps(diff, ensure_ascii=False),
                 1 if baseline_stable else 0),
            )
            conn.commit()
        return f"{src}:{seq}"

    # ---- 读:任意流量 → HttpRequest(service 重放用,支持链式) ----
    def get_raw_request(self, traffic_id: str) -> HttpRequest | None:
        """读任意流量(history 或证据)转 HttpRequest(供 replay_service 重放)。

        链式重放:repeater/brute 可基于证据 id(repeater:N/brute:N/send:N)再编辑重放
        (Burp Repeater tab 模式:改→发→再改)。get() 统一入口吃两种 id,本方法从两种
        request shape 建 HttpRequest:
        - history(_get_raw 翻译):{method,url,headers(list),post_data} → body 从 post_data
        - evidence(request_json 原样 HttpRequest.to_dict):{method,url,headers(list),body{HttpBlob}}
          → body 从 body.text
        headers 兼容 list[{name,value}](新)与 dict(老迁移行)。
        """
        data = self.get(traffic_id)
        if data is None:
            return None
        req = data.get("request") or {}
        raw_headers = req.get("headers") or []
        if isinstance(raw_headers, dict):
            header_pairs = raw_headers.items()
        else:
            header_pairs = (
                (h.get("name", ""), h.get("value", ""))
                for h in raw_headers if isinstance(h, dict)
            )
        headers = tuple(HttpHeader(str(k), str(v)) for k, v in header_pairs)
        body = None
        # evidence 形:body dict(HttpBody)有 text → 优先;history 形:post_data 字符串。
        body_dict = req.get("body")
        if isinstance(body_dict, dict) and body_dict.get("text") is not None:
            ct = body_dict.get("content_type")
            if ct is None:
                for h in headers:
                    if h.name.casefold() == "content-type":
                        ct = h.value
            body = HttpBody(text=str(body_dict.get("text")), content_type=ct,
                             file_path=body_dict.get("file_path"))
        elif req.get("post_data"):
            ct = None
            for h in headers:
                if h.name.casefold() == "content-type":
                    ct = h.value
            body = HttpBody(text=str(req.get("post_data")), content_type=ct)
        return HttpRequest(
            method=str(req.get("method") or "GET"),
            url=str(req.get("url") or ""),
            headers=headers,
            body=body,
        )

    # ---- 读:证据的门禁校验(report_service 用) ----
    def evidence_has_diff(self, evidence_id: str) -> bool:
        """证据的 diff 是否有客观变化(status 或 body 为 true)。confirmed 门禁用。

        evidence 在 DB:直查 evidence.diff_json 解析。
        """
        parsed = _split_evidence_id(evidence_id)
        if parsed is None:
            return False
        src, seq = parsed
        with self._connect() as conn:
            row = conn.execute(
                "SELECT diff_json FROM evidence WHERE source=? AND source_seq=?",
                (src, seq),
            ).fetchone()
        if row is None:
            return False
        diff = json.loads(row["diff_json"]) if row["diff_json"] else {}
        return bool(diff.get("status") or diff.get("body"))

    def evidence_exists(self, traffic_id: str) -> bool:
        """traffic_id 是否在流量库真实存在(history:<id> 或 <source>:<seq>)。report 门禁用。

        不要求 diff,只要求 id 真实(防幻觉=证据客观存在,不机械要求 diff)。
        evidence_has_diff 保留(skill edit 的 evidence_id 门禁仍用)。
        """
        tid = str(traffic_id or "").strip()
        if not tid:
            return False
        if tid.startswith("history:"):
            num = _parse_evidence_id(tid, "history")
            if num is None:
                return False
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT 1 FROM history WHERE id=?", (num,)
                ).fetchone()
            return row is not None
        parsed = _split_evidence_id(tid)
        if parsed is None:
            return False
        src, seq = parsed
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM evidence WHERE source=? AND source_seq=?", (src, seq)
            ).fetchone()
        return row is not None


    def list_clean(self) -> list[dict[str, Any]]:
        """全量读 clean(供 dispatch 队列消费,按 clean.jsonl 顺序)。

        clean 改 jsonl 不进 sqlite(lib/CLAUDE.md):lib.build_clean 落
        session_dir/pipeline/proxy/clean.jsonl,本方法读它。session_dir 由
        build_traffic_services 传入;内存测试无 session_dir → 空表(降级不崩)。
        """
        if not self.session_dir:
            return []
        p = self.session_dir / "pipeline" / "proxy" / "clean.jsonl"
        try:
            if not p.is_file():
                return []
            return [d for d in (json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip())
                    if isinstance(d, dict)]
        except (OSError, json.JSONDecodeError, ValueError):
            return []

    # ---- 读:dispatch 续跑跳过(从 dispatch_queue 派生) ----
    def list_dispatch_done_traffic_ids(self) -> set[str]:
        """已打包进 module 的 traffic_id 集(续跑:queue 跳过这些单元)。

        从 dispatch_queue 派生:traffic_id ∈ ⋃ module.traffic_ids = 已 dispatch 过。
        比"已落 status"更准——dispatch agent 调 dispatch_send 写了 queue 但 stage 崩在
        落盘前,queue 派生仍跳过(幂等重跑无害:module_id 哈希幂等,重复打包返回已存行)。
        """
        done: set[str] = set()
        with self._connect_queue() as conn:
            rows = conn.execute("SELECT traffic_ids_json FROM dispatch_queue").fetchall()
        for r in rows:
            for tid in json.loads(r["traffic_ids_json"] or "[]"):
                done.add(str(tid))
        return done

    # ---- 写/读:dispatch_queue(dispatch 工具产物,dispatch agent 打包的模块) ----
    @staticmethod
    def _module_id(traffic_ids: list[str]) -> str:
        """sorted(traffic_ids) 的稳定哈希 → 幂等键。同组流量(不论顺序)→ 同 module_id,
        UNIQUE(module_id) 强制"每组流量只打包一次"(重复 dispatch_send 返回已存行不重写)。"""
        key = "|".join(sorted(t.strip() for t in traffic_ids if t))
        return "m_" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]

    def upsert_module(self, *, traffic_ids: list[str], skills: list[str],
                     keys: list[str] | None, notes: str,
                     status: str = "unverified") -> tuple[str, str]:
        """幂等写一个模块行。module_id = sorted(traffic_ids) 哈希 → UNIQUE 幂等:
        同组流量重复打包返回已存 module_id+status 不重写(不更新 skills/keys/notes)。
        返 (module_id, status)。

        skills=[]=novel(无 catalog 匹配,走 verify 自由);['noise']→status='dropped'
        (调用方传,不进 verify)。status 由调用方定(dispatch_service:noise→dropped)。
        """
        if not traffic_ids:
            raise ValueError("traffic_ids 不能为空(模块至少捆 1 条流量)")
        module_id = self._module_id(traffic_ids)
        keys_json = json.dumps(keys or [], ensure_ascii=False)
        skills_json = json.dumps(skills or [], ensure_ascii=False)
        tids_json = json.dumps(traffic_ids, ensure_ascii=False)
        with self._connect_queue() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO dispatch_queue "
                "(module_id, traffic_ids_json, skills_json, keys_json, notes, status) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (module_id, tids_json, skills_json, keys_json, notes or "", status),
            )
            row = conn.execute(
                "SELECT status FROM dispatch_queue WHERE module_id=?", (module_id,),
            ).fetchone()
            conn.commit()
            return module_id, str(row["status"])

    def list_modules(self, *, status: str | None = None,
                     statuses: list[str] | None = None) -> list[dict[str, Any]]:
        """列 dispatch_queue 模块(交 verify 深挖 + dispatch _resolve 覆盖率审计)。
        status 单值过滤 或 statuses 多值过滤(如 ['unverified','inconclusive']);都缺省=全量。"""
        with self._connect_queue() as conn:
            if statuses:
                ph = ",".join("?" for _ in statuses)
                rows = conn.execute(
                    f"SELECT id, module_id, traffic_ids_json, skills_json, keys_json, "
                    f"notes, verify_verdict_json, status FROM dispatch_queue WHERE status IN ({ph}) ORDER BY id",
                    statuses,
                ).fetchall()
            elif status:
                rows = conn.execute(
                    "SELECT id, module_id, traffic_ids_json, skills_json, keys_json, "
                    "notes, verify_verdict_json, status FROM dispatch_queue WHERE status=? ORDER BY id",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, module_id, traffic_ids_json, skills_json, keys_json, "
                    "notes, verify_verdict_json, status FROM dispatch_queue ORDER BY id"
                ).fetchall()
        return [{
            "row_id": row["id"],
            "module_id": row["module_id"],
            "traffic_ids": json.loads(row["traffic_ids_json"] or "[]"),
            "skills": json.loads(row["skills_json"] or "[]"),
            "keys": json.loads(row["keys_json"] or "[]"),
            "notes": row["notes"],
            "verify_verdict": json.loads(row["verify_verdict_json"] or "[]"),
            "status": row["status"],
        } for row in rows]

    def mark_module_resolved(self, module_id: str, status: str = "resolved") -> None:
        """verify 消费完一个模块标 resolved(或 inconclusive)。按 module_id 更新。"""
        with self._connect_queue() as conn:
            conn.execute(
                "UPDATE dispatch_queue SET status=? WHERE module_id=?",
                (status, module_id),
            )
            conn.commit()

    def claim_module(self) -> dict[str, Any] | None:
        """原子领一个待验模块(unverified/inconclusive → in_progress)。流式 verify 用:
        N 个 worker 并发领,CAS 防双吃(WHERE status IN (...) 守卫 + rowcount 判赢,不依赖
        sqlite RETURNING)。返模块 dict(同 list_modules 项 + _source/candidate_id 形状)
        或 None(无待验)。被领模块 status=in_progress,verify 跑完由 mark_module_resolved
        标 resolved;崩了残留由 reset_in_progress 回收。"""
        with self._connect_queue() as conn:
            rows = conn.execute(
                "SELECT id, module_id, traffic_ids_json, skills_json, keys_json, "
                "notes, status FROM dispatch_queue "
                "WHERE status IN ('unverified','inconclusive') ORDER BY id"
            ).fetchall()
            claimed: dict[str, Any] | None = None
            for row in rows:
                cur = conn.execute(
                    "UPDATE dispatch_queue SET status='in_progress' "
                    "WHERE id=? AND status IN ('unverified','inconclusive')",
                    (row["id"],),
                )
                if cur.rowcount == 1:
                    claimed = {
                        "candidate_id": row["module_id"], "_source": "traffic",
                        "traffic_ids": json.loads(row["traffic_ids_json"] or "[]"),
                        "skills": json.loads(row["skills_json"] or "[]"),
                        "keys": json.loads(row["keys_json"] or "[]"),
                        "notes": row["notes"] or "",
                        "status": "in_progress",
                    }
                    break
            conn.commit()
            return claimed

    def reset_in_progress(self) -> int:
        """崩溃恢复:把上次跑到一半的 in_progress(verify worker 崩了的僵尸 claim)重置回
        unverified。verify 开跑前调。返重置行数。"""
        with self._connect_queue() as conn:
            cur = conn.execute(
                "UPDATE dispatch_queue SET status='unverified' WHERE status='in_progress'"
            )
            conn.commit()
            return cur.rowcount


    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """history 库连接(pipeline/proxy/traffic.sqlite)。内存模式用 :memory: 复用 self._memory。"""
        if self.database_path is None:
            if self._memory is None:
                self._memory = sqlite3.connect(":memory:")
                self._memory.row_factory = sqlite3.Row
                self._memory.executescript(_HISTORY_DDL)
                self._memory.executescript(_EVIDENCE_DDL)
            yield self._memory
            return
        conn = sqlite3.connect(self.database_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        # 并发写:MCP 子进程(dispatch_send 写 queue)+ 主进程(claim_module UPDATE status)。
        # WAL 允许并发读+单写不互斥,busy_timeout 防 SQLITE_BUSY 等待重试。
        # 流式 dispatch↔verify(主进程 claim + 子进程 upsert 同时跑)必需。
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _connect_queue(self) -> Iterator[sqlite3.Connection]:
        """dispatch_queue 库连接(pipeline/agent/dispatch_queue.sqlite,独立于 history db)。
        内存模式用 :memory: 复用 self._queue_memory。WAL + busy_timeout 同 history(并发 claim/upsert)。"""
        if self.queue_path is None:
            if self._queue_memory is None:
                self._queue_memory = sqlite3.connect(":memory:")
                self._queue_memory.row_factory = sqlite3.Row
                self._queue_memory.executescript(_DISPATCH_QUEUE_DDL)
            yield self._queue_memory
            return
        conn = sqlite3.connect(self.queue_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            yield conn
        finally:
            conn.close()


def _snippet(text: str, needle: str, *, width: int = 160) -> str:
    """命中点 ±width/2 字符片段(grep -C 式),前后截断加「…」。单条多命中取首个。

    给 search_raw 用:agent 看 fragment 就知道 id 夹在哪个字段/上下文里,不用再
    traffic_get 全量读。text 是 request_json/response_json 原文(JSON 串里值原样出现)。
    """
    if not text:
        return ""
    i = text.find(needle)
    if i < 0:
        return text[:width]
    half = width // 2
    start = max(0, i - half)
    end = min(len(text), i + len(needle) + half)
    frag = text[start:end]
    if start > 0:
        frag = "…" + frag
    if end < len(text):
        frag = frag + "…"
    return frag


def _parse_evidence_id(evidence_id: str, prefix: str) -> int | None:
    p, sep, raw = evidence_id.partition(":")
    if sep != ":" or p != prefix or not raw.isdigit():
        return None
    return int(raw)


def _normalize_resp(resp: dict | None) -> dict:
    """response 归一:缺 body_text(或空)但有嵌套 body.text → 回填 body_text(读层
    兜底,兼容旧 evidence 记录 body 嵌套形态)。从 artifact_store 搬来(evidence 回 DB,
    artifact_store 删除,_get_evidence/list_raw 读层在此归一)。非 dict → {}。"""
    if not isinstance(resp, dict):
        return {}
    if not resp.get("body_text"):
        body = resp.get("body")
        if isinstance(body, dict) and body.get("text") is not None:
            resp = {**resp, "body_text": body.get("text")}
    return resp


def _split_evidence_id(traffic_id: str) -> tuple[str, int] | None:
    """拆 <source>:<seq>,source 须在 _PREFIX_KIND(repeater/brute/send)。
    不合法/非数字 → None。history:<id> 不在此(走 _parse_evidence_id "history")。"""
    src, sep, raw = str(traffic_id or "").strip().partition(":")
    if sep != ":" or src not in _PREFIX_KIND or not raw.isdigit():
        return None
    return src, int(raw)


def _is_evidence_id(traffic_id: str) -> bool:
    """是否为证据 id(<source>:<seq>,source=repeater/brute/send)。"""
    return _split_evidence_id(traffic_id) is not None


_DISPATCH_QUEUE_DDL = """
-- dispatch_queue:dispatch agent 打包的模块行(替旧 traffic_id×skill fan-out)。
-- module_id = sorted(traffic_ids) 稳定哈希 → UNIQUE 幂等(同组流量重复打包返回已存行不重写)。
-- skills=[]=novel(无 catalog);['noise']→status=dropped;其余 unverified 交 verify 深挖。
CREATE TABLE IF NOT EXISTS dispatch_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_id TEXT NOT NULL UNIQUE,
    traffic_ids_json TEXT NOT NULL,
    skills_json TEXT NOT NULL DEFAULT '[]',
    keys_json TEXT,
    notes TEXT,
    verify_verdict_json TEXT,            -- verify 判定(confirmed/inconclusive finding 列表);null=未验/全 rejected
    status TEXT NOT NULL DEFAULT 'unverified',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_dispatch_queue_status ON dispatch_queue (status);
"""


_HISTORY_DDL = """
-- history 表:mitmproxy 捕获的结构化 HttpExchange(原始流量,proxy 产物)。
-- evidence 进 DB(evidence 表,重放证据 repeater/brute/send);dispatch_queue 拆独立 db
-- (pipeline/agent/dispatch_queue.sqlite,agent 编排介质不和 history 耦合)。
-- agent id 统一 <kind>:<seq>:history:<id> / <source>:<source_seq>。
-- 旧单表 traffic 已弃用(_migrate_legacy 迁移后 DROP)。
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


_EVIDENCE_DDL = """
-- evidence 表:重放证据(repeater/brute/send,各 source 内 source_seq 自增)。
-- request/response/baseline/edit/diff 存全量 JSON;source_id 链 history:<id>
-- (send 从零构造传 "send" 字面量无 history 根)。PRIMARY KEY (source, source_seq)。
-- 旧 evidence.jsonl(artifact_store 时代,evidence 出 DB 落 JSON)由
-- _migrate_evidence_jsonl 导入(幂等:表非空则跳过,jsonl 不删留 backup)。
CREATE TABLE IF NOT EXISTS evidence (
    source TEXT NOT NULL,
    source_seq INTEGER NOT NULL,
    source_id TEXT NOT NULL DEFAULT '',
    request_json TEXT NOT NULL DEFAULT '{}',
    response_json TEXT NOT NULL DEFAULT '{}',
    baseline_json TEXT NOT NULL DEFAULT '{}',
    edit_json TEXT NOT NULL DEFAULT '{}',
    diff_json TEXT NOT NULL DEFAULT '{}',
    baseline_stable INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source, source_seq)
);
CREATE INDEX IF NOT EXISTS idx_evidence_source_id ON evidence (source_id);
"""
