"""重放编排 + 简版 diff。

极简:ResponseSnapshot 只采 status/body_text/elapsed_ms/body_truncated。
compare 只比 status/body/time 三个客观维度。语义判断归 LLM(读 response 自判)。

repeater/brute/send 三入口共用 _run_pipeline:baseline(重放原始) → candidate(重放编辑后)
→ diff → 落 evidence(source=repeater/brute/send,各 source 内 source_seq 自增)。无 baseline
时 candidate 单发,diff 全 false。
"""
from __future__ import annotations

import time
from typing import Any, Protocol

import requests
import urllib3

# 重放是安全审计的核心动作:对捕获的 HTTPS 端点 verify=False 重放是预期行为
# (目标可能是自签名/内网/本地证书),urllib3 每次都喷 InsecureRequestWarning 刷屏。
# 这里是 verify=False 的合法用点,告警纯噪音,模块加载时消音。
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from agentsuite.proxy.http import HttpRequest, strip_pseudo_headers

from ..data.store import AuditStore
from ..models import ResponseDiff, ResponseSnapshot, RunState
from .edit_engine import apply_find_replace
# 同包 service 共享分页 helper(leaf 模块,避免 replay→query→replay 循环 import)。
# edit/send inline 的 response/baseline body 也套 32KB cap,和 traffic_get 出参一致。
from ._paging import _DEFAULT_BODY_LIMIT, _paginate_body

_BODY_LIMIT = 256 * 1024


class HttpTransport(Protocol):
    def send(self, request: HttpRequest, *, timeout_seconds: float, verify_tls: bool) -> ResponseSnapshot: ...


class RequestsHttpTransport:
    """requests 发包,采极简 ResponseSnapshot。

    session=None(默认)走 requests.request 模块函数,每次新连接——traffic agent
    主动重放/brute 走这条,行为不变。
    传 session(requests.Session)则走 session.request,复用 keepalive 连接,省掉
    重复 TCP/TLS 握手。Session 非线程安全,多线程场景每线程须持各自 Session,不能共享。
    """

    def __init__(self, *, allow_mutating: bool = False,
                 session: Any = None) -> None:
        self.allow_mutating = allow_mutating
        self.session = session

    def send(self, request: HttpRequest, *, timeout_seconds: float = 10.0,
             verify_tls: bool = False) -> ResponseSnapshot:
        self._check_policy(request)
        # raw_bytes(kind 驱动 body 的真发送 bytes,含文件二进制)优先,否则 text;
        # 都 None 时 data=None(GET 等)。text kind raw_bytes=None → 走 .text(= 方案A 行为)。
        data = (request.body.raw_bytes if request.body and request.body.raw_bytes is not None
                else (request.body.text if request.body else None))
        # 剥 HTTP/2 伪头:全量头泄进来的 :method/:path 等当普通头发给
        # HTTP/1.1(requests)会失败。send 是兜底(旧库 + agent 自抄 headers 都 cover);
        # 采集点 recorder 也剥(让存储/traffic_get 干净)。
        headers = strip_pseudo_headers({h.name: h.value for h in request.headers})
        started = time.perf_counter()
        if self.session is not None:
            resp = self.session.request(
                method=request.method, url=request.url,
                headers=headers, data=data,
                timeout=timeout_seconds, verify=verify_tls, allow_redirects=False,
            )
        else:
            resp = requests.request(
                method=request.method, url=request.url,
                headers=headers, data=data,
                timeout=timeout_seconds, verify=verify_tls, allow_redirects=False,
            )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        body_bytes = resp.content
        encoding = resp.encoding or "utf-8"
        body_text = body_bytes[:_BODY_LIMIT].decode(encoding, errors="replace")
        return ResponseSnapshot(
            status=resp.status_code,
            body_text=body_text,
            elapsed_ms=elapsed_ms,
            body_truncated=len(body_bytes) > _BODY_LIMIT,
        )

    def _check_policy(self, request: HttpRequest) -> None:
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not self.allow_mutating:
            raise ValueError("当前策略禁止重放有副作用的 HTTP 方法")


def compare_snapshots(baseline: ResponseSnapshot, candidate: ResponseSnapshot) -> ResponseDiff:
    """简版 diff:只比 status/body/time。客观事实,不判语义。"""
    return ResponseDiff(
        status=baseline.status != candidate.status,
        body=baseline.body_text != candidate.body_text,
        time=candidate.elapsed_ms - baseline.elapsed_ms,
    )


def _brute_replace(find: str, value: str) -> str:
    """构造 brute 的 replace:find 带 'Name: value'(含 ': ')→ 拼回 'Name: <value>' 保名只换值;
    find 带 'key=val'(含 '=' 无 ': ')→ 拼回 'key=<value>' 保键只换值;find 只值(无 ': '/'=')→
    裸 value(全局纯文本替,键/名在 find 外不动,自然保留)。

    ★IDOR 换号必须保留参数名:find='id=456'+values=['111'] 要产出 id=111,不是 111。全局纯
    文本下裸 value 当 replace 会把 find 整段('id=456')替成 value('111')→ 键 id 没了,IDOR 全废
    (agent 以为测了 id=111 实际发 111)。故 find 带键时 replace 必须也带键。find 只值('456')
    时裸 value 替只换值('id='在 find 外不动)→ 保键。靠检测 find 含 ': '(header 整行)或 '='
    (query/cookie kv)判断是否带键,不依赖 part(part 已砍)。
    ★检测顺序:先 ': ' 后 '='——header 行如 'Cookie: role=admin' 同时含 ':' 和 '=',必须先按
    ': ' 判为 header(名=Cookie),否则 '=' 分支会把名拆成 'Cookie: role' 错成 'Cookie: role=<v>'。
    """
    if ": " in find:  # header 整行 'Name: old'(含 ': ')→ 保名只换值
        fn = find.partition(":")[0]
        return f"{fn.strip()}: {value}"
    if "=" in find:  # query/cookie 'key=old'(含 '=' 无 ': ')→ 保键只换值
        fk = find.partition("=")[0]
        return f"{fk.strip()}={value}"
    return value


class ReplayService:
    """重放编排:edit/brute/send 共用 _run_pipeline。"""

    def __init__(
        self,
        store: AuditStore,
        *,
        transport: HttpTransport | None = None,
        timeout_seconds: float = 10.0,
        verify_tls: bool = False,
        allow_mutating: bool = True,
        baseline_repeats: int = 1,
    ) -> None:
        self.store = store
        self.transport = transport or RequestsHttpTransport(allow_mutating=allow_mutating)
        self.timeout_seconds = timeout_seconds
        self.verify_tls = verify_tls
        self.allow_mutating = allow_mutating
        self.baseline_repeats = baseline_repeats

    # ---- repeater:基于任意流量全局 find/replace 重放(链式允许) ----
    def replay_repeater(
        self, traffic_id: str, find: str | None, replace: str | None,
        *, state: RunState | None = None,
    ) -> dict[str, Any]:
        """repeater = 全局 find/replace 改一处重放看响应。traffic_id 可是
        history:<id> 或证据 id(repeater:N/brute:N/send:N 链式重放)。

        ★砍了 with_diff:不再重放原始作 baseline。baseline = 原始流量的**已存响应**
        (history 表 response_json,录制时已采),要 diff 调独立 traffic_diff 工具读两份
        已存响应比。repeater 只发编辑后请求(candidate),落证据,diff 全 false(无 live baseline)。
        """
        base_request = self._get_base_request(traffic_id)
        candidate_request = apply_find_replace(base_request, find, replace)
        result = self._run_pipeline(
            kind="repeater", source_id=traffic_id, base_request=None,
            candidate_request=candidate_request,
            edit={"find": find, "replace": replace}, state=state,
            skip_baseline=True,
        )
        # 返回精简(匹配 note:agent 要 diff 调 traffic_diff;edit 留作改了什么的确认)
        return {"traffic_id": result["traffic_id"], "response": result["response"],
                "edit": result["edit"]}

    # ---- send:从零构造重放(无 baseline,diff 走 traffic_diff) ----
    def replay_send(
        self, request: HttpRequest, *, state: RunState | None = None,
    ) -> dict[str, Any]:
        """send = 从零构造请求重放。★砍了 baseline_id:不再内置 baseline 对照。
        要 diff 原始流量 → 调 traffic_diff(baseline_id=history:N, candidate_id=send:N)
        读两份已存响应比。raw 只发 candidate,落证据,diff 全 false。"""
        result = self._run_pipeline(
            kind="send", source_id="send", base_request=None,
            candidate_request=request,
            edit={"send": True}, state=state,
            skip_baseline=True,
        )
        return {"traffic_id": result["traffic_id"], "response": result["response"]}

    # ---- brute:值表爆破(全局 find/replace;保留 live baseline 比对) ----
    def replay_brute(
        self, traffic_id: str, find: str, values: list[str],
        *, stop_on_change: bool = True, max_attempts: int = 100,
        state: RunState | None = None,
    ) -> dict[str, Any]:
        """brute = 对某 find 跑一串候选值,逐个重放看响应变没变。

        traffic_id 可链式(history 或证据)。brute 保留 live baseline(重放原始一次取基线)——
        其本性就是逐值比对变没变。返回每值一条 brute:N 证据(可 traffic_diff 两两比)。
        find 带键/名(含 = 或 :)→ _brute_replace 拼回保键只换值;find 只值 → 裸替(键在 find 外保留)。
        """
        if not values:
            raise ValueError("values 值表不能为空")
        base_request = self._get_base_request(traffic_id)
        baseline = self.transport.send(
            base_request, timeout_seconds=self.timeout_seconds, verify_tls=self.verify_tls
        )
        attempts = min(len(values), max(1, max_attempts))
        results: list[dict[str, Any]] = []
        hit_change = False
        for i in range(attempts):
            cand_req = apply_find_replace(base_request, find,
                                         _brute_replace(find, values[i]))
            cand = self.transport.send(
                cand_req, timeout_seconds=self.timeout_seconds, verify_tls=self.verify_tls
            )
            diff = compare_snapshots(baseline, cand)
            evidence_id = self.store.save_evidence(
                kind="brute", source_id=traffic_id,
                request=cand_req.to_dict(),
                response=_snap_dict(cand),
                baseline=_snap_dict(baseline),
                edit={"find": find, "replace": values[i], "index": i},
                diff=diff.to_dict(), baseline_stable=True,
            )
            changed = diff.status or diff.body
            results.append({
                "traffic_id": evidence_id,
                "value": values[i],
                "response": {"status": cand.status,
                             "body_preview": cand.body_text[:256]},
                "changed": changed,
            })
            if state is not None:
                state.replays.append({
                    "replay_id": evidence_id, "source_id": traffic_id,
                    "changed": changed,
                })
            if changed:
                hit_change = True
                if stop_on_change:
                    break
        # stopped 原因:命中变化(stop_on_change)|跑完值表|触 max_attempts 上限
        if hit_change and stop_on_change and len(results) < attempts:
            stopped = "change"
        elif len(results) >= attempts and attempts < len(values):
            stopped = "max"
        else:
            stopped = "exhausted"
        top_id = results[0]["traffic_id"] if results else traffic_id
        return {
            "traffic_id": top_id,
            "results": results,
            "attempts": len(results),
            "total_values": len(values),
            "stopped": stopped,
        }

    # ---- 共用 pipeline ----
    def _run_pipeline(
        self, *, kind: str, source_id: str, base_request: HttpRequest | None,
        candidate_request: HttpRequest, edit: dict[str, Any],
        state: RunState | None, skip_baseline: bool = False,
    ) -> dict[str, Any]:
        baseline = None
        baseline_stable = False
        if skip_baseline or base_request is None:
            cand = self.transport.send(
                candidate_request, timeout_seconds=self.timeout_seconds, verify_tls=self.verify_tls
            )
            diff = ResponseDiff(status=False, body=False, time=0)
        else:
            samples = [
                self.transport.send(base_request, timeout_seconds=self.timeout_seconds,
                                    verify_tls=self.verify_tls)
                for _ in range(max(1, self.baseline_repeats))
            ]
            baseline = samples[-1]
            # 稳定性复核:所有样本跟第一个比;repeats<2(单发)无法复核 → False。
            # 原逻辑跟 samples[-1] 比 + 排除 samples[0],samples[0] 从没被比,
            # 且 samples[1:] 含 baseline 自己恒 True → repeats=2 也是恒 True(假复核)。
            if len(samples) < 2:
                baseline_stable = False
            else:
                first = samples[0]
                baseline_stable = all(
                    s.body_text == first.body_text and s.status == first.status
                    for s in samples[1:]
                )
            cand = self.transport.send(
                candidate_request, timeout_seconds=self.timeout_seconds, verify_tls=self.verify_tls
            )
            diff = compare_snapshots(baseline, cand)
        evidence_id = self.store.save_evidence(
            kind=kind, source_id=source_id,
            request=candidate_request.to_dict(),
            response=_snap_dict(cand),
            baseline=_snap_dict(baseline) if baseline else {},
            edit=edit, diff=diff.to_dict(), baseline_stable=baseline_stable,
        )
        if state is not None:
            state.replays.append({
                "replay_id": evidence_id, "source_id": source_id,
                "changed": diff.status or diff.body, "baseline_stable": baseline_stable,
            })
        return {
            "traffic_id": evidence_id, "source_id": source_id,
            "request": candidate_request.to_dict(),
            # inline 只回 32KB 预览(同 traffic_get),大响应不灌上下文;
            # 存储是全量(上面 save_evidence 存 _snap_dict 全文),agent get(id) 翻页读全。
            "response": _cap_snap(_snap_dict(cand)),
            "baseline": _cap_snap(_snap_dict(baseline)) if baseline else {},
            "edit": edit, "diff": diff.to_dict(),
            "baseline_stable": baseline_stable,
        }

    def _get_base_request(self, traffic_id: str) -> HttpRequest:
        # 链式重放:允许证据 id(repeater:/brute:/send:)当 base 再编辑(Burp Repeater tab:
        # 改→发→再改)。get_raw_request 吃 history 与证据两种 id,从两种 request shape 建
        # HttpRequest。send 不再走这(baseline_id 已砍,diff 走 traffic_diff 读已存响应)。
        req = self.store.get_raw_request(traffic_id)
        if req is None:
            raise ValueError(f"流量不存在:{traffic_id}")
        return req


def _snap_dict(snap: ResponseSnapshot) -> dict[str, Any]:
    return snap.to_dict()


def _cap_snap(snap: dict[str, Any]) -> dict[str, Any]:
    """对 snapshot dict 的 body_text 套 32KB inline cap(同 traffic_get 默认)。

    edit/send 的 inline 返回只回前 32KB 预览,大响应不一次性灌上下文;
    agent 调 traffic_get(id) 翻页读全。覆盖 history 时的 body_truncated
    (>256KB 标记)为 inline 截断标记,body_total = 存储全长(agent 据此知是否翻页)。
    """
    body = snap.get("body_text")
    sliced, truncated, total = _paginate_body(body, 0, _DEFAULT_BODY_LIMIT)
    return {**snap, "body_text": sliced, "body_truncated": truncated, "body_total": total}
