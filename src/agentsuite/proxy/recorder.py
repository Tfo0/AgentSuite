"""mitmproxy 流量录制(本仓唯一录制轨)。

mitmproxy 代理层录 request/response body 完整(代理层天然拿全 body,无 FormData
盲点 / response 句柄过期)。CaptureAddon 收 flow → 对齐 record dict(7 点,见
_flow_to_record docstring)→ ProxyStore.dump 写 traffic.sqlite(同 schema 下游
dispatch/verify 零改读)。

mitmproxy 服务由 record stage 起(DumpMaster 后台 asyncio 线程,端口配
settings.mitm_proxy_port;原 Web 前端 lifespan 随 Web 删除,见 ADR-0001/0002)。
浏览器启动时挂 --proxy-server 指向它(命令行 chrome / 系统代理)。代理须在浏览器启动时设。

★ 纯被动(见 docs/decisions/0002-mitm-only-drop-cdp.md):后端不 connect 浏览器、
不接管、不导航、不 dismiss 弹窗——全靠人手操作。后端只:起代理 → 轮询
stop_event/timeout → 收尾取 service.flows_since(start) 增量 → NoiseFilter drop 噪音
→ dump。流量从代理层读,后端不碰浏览器。

★ 为何全局单例 service:mitmproxy 是进程级 HTTP 代理,所有浏览器流量都经。项目
队列串行(全局 asyncio.Lock 一次一个项目全链路),录制开始记 flows 起点 len,结束
取增量 flows[start:]。多项目并发(队列)再加分隔。

★ 证书:chrome `--ignore-certificate-errors`(launch 级 flag,盖所有页)+ mitmproxy
`ssl_insecure=True`(不验上游证书)。本地 PoC 实测自签 HTTPS 站都能录到完整 body,
真实 HTTPS 站只会更顺。不装 mitmproxy CA 到系统信任库即可工作;若遇 HSTS 强拒
(罕见),装 CA(`~/.mitmproxy/mitmproxy-ca-cert.cer` 双击装 Windows 受信任根 CA)是
fallback。

依赖:proxy 纯逻辑。import mitmproxy(第三方)+ 同包 store/filter
+ config(顶层共享,谁都依赖)。不 import playwright(本仓纯被动录制,不驱动浏览器)、
不 import tool。
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import threading
import time
from typing import Any
from urllib.parse import urlparse

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from agentsuite.config import settings
from .store import ProxyStore
from .filter import NoiseFilter
from .filter import drop_noise

# ── body 处理 + stop_event helper(原 network_recorder body 处理内联到此;
# mitm 是唯一消费者)──────────────────────────────────────────

TEXT_CONTENT_MARKERS = (
    "application/json",
    "application/javascript",
    "application/xml",
    "application/x-www-form-urlencoded",
    "text/",
)

# 控制字符(除 \t \n \r——multipart 用 \r\n 分隔、文本常见 \t,保留)。json.dumps 会
# 转义成 \u00XX(6 倍膨胀),二进制 multipart body(文件上传)含大量控制字节 →
# traffic_get JSON 膨胀超 1MB ceiling。替成 U+FFFD(合法 codepoint,JSON 不转义)防膨胀。
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _sanitize_post_bytes(raw: bytes, max_bytes: int) -> tuple[str | None, bool]:
    """bytes body → 安全 str:切字节预算 + 非法 UTF-8 替 U+FFFD + 控制字符替 U+FFFD。

    request post_data + response body_text 共用。控制字符替 U+FFFD 防 traffic_get
    JSON 编码 6 倍膨胀超 1MB(二进制上传 body)。
    """
    if not raw:
        return None, False
    truncated = len(raw) > max_bytes
    decoded = raw[:max_bytes].decode("utf-8", errors="replace")
    return _CONTROL_RE.sub("�", decoded), truncated


def _is_set(stop_event: Any) -> bool:
    """stop_event.is_set(),兼容 asyncio.Event 与 threading.Event(都返 _value bool)。"""
    try:
        return bool(stop_event.is_set())
    except Exception:
        return False

logger = logging.getLogger(__name__)

# body 字节预算(对齐原 recorder 的 _max_post_data_bytes + _should_capture_body
# 的 text body 上限)。request post_data + response body_text 都走 _sanitize_post_bytes。
_MAX_BODY = 256 * 1024


def _should_capture_body(content_type: str) -> bool:
    """对齐点 1:response body 选择性,content-type-only(砍 resource_type conjunct)。

    原 recorder 的 _should_capture_body 靠 resource_type AND content-type marker;
    mitmproxy flow 无 resource_type 概念(DB 也无此列),直接砍 conjunct 只靠 content-type。

    TEXT_CONTENT_MARKERS 已排除 image/css/font/media,故 image/png 等 response body
    返 None 不录——防灌爆 DB(20-100MB/site)+ binary 控制字符 JSON 膨胀撑爆 1MB MCP
    ceiling + has_body SQL 把 captcha/qrcode 当 cluster rep 污染 clean。
    """
    ct = (content_type or "").lower()
    return any(marker in ct for marker in TEXT_CONTENT_MARKERS)


def _decompress_bytes(resp: Any) -> bytes:
    """response.content 可能被 br/gzip/deflate 压缩,解压一份(不改 flow,
    浏览器仍收原压缩响应——纯被动不篡改流量)。mitmproxy 已自动 de-chunk,
    content 是完整压缩 body,只需按 content-encoding 解压。解压失败保留 raw
    (_sanitize_post_bytes 会替 U+FFFD,不崩)。
    """
    raw = resp.content or b""
    ce = (resp.headers.get("content-encoding") or "").lower()
    if not ce or not raw:
        return raw
    try:
        if "br" in ce:
            import brotli
            return brotli.decompress(raw)
        if "gzip" in ce:
            import gzip
            return gzip.decompress(raw)
        if "deflate" in ce:
            import zlib
            return zlib.decompress(raw)
    except Exception:  # noqa: BLE001  解压失败留 raw(不崩)
        pass
    return raw


def _flow_to_record(flow: Any) -> dict[str, Any]:
    """mitmproxy flow → record dict(对齐 ProxyStore.dump 消费格式,7 点)。

    7 点对齐(详见 memory mitmproxy-traffic-capture-poc 字段对齐定论):
    1. response body 选择性:_should_capture_body content-type-only(非 text → None)。
    2. exchange_id = flow.id(UUID,禁 url fallback 碰撞导致 INSERT OR REPLACE 抢 rowid)。
    3. rowid 插入序=flow 到达序(addon response hook 按 flow 到达 append,下游 5 处
       ORDER BY id 依赖时序)。
    4. Cookie/Auth 写 headers dict(dict(flow.request.headers.items()) last-wins;
       mitmproxy 默认暴露 Cookie)。
    5. request post_data 256KB cap + errors=replace + 控制字符替 U+FFFD
       (复用 _sanitize_post_bytes,防二进制 multipart body JSON 6x 膨胀撑爆 1MB)。
    6. 不产归因 phase/action_id/action_kind/target_name(DB 无列,store 消费时丢,
       全 repo WHERE phase=... 零命中)。
    7. 不产 resource_type(DB 无列,list_raw 的 resource_type 参数是死兼容)。
    """
    req = flow.request
    resp = flow.response
    # req.headers 是 MultiDict:HTTP/2 按 RFC 7540 §8.1.2.5 把 Cookie 拆成多个 cookie
    # 字段,MultiDict.items() 把同名多值用 ', ' 拼成一个值——但 HTTP/1.1 Cookie 必须
    # '; ' 分隔。逗号会让重放服务器把整串当单个 cookie 解析(sessionid 等不被识别
    # →replay 401,实测 scm.bytedance.com history:1 存了 47 逗号 0 分号)。故 cookie
    # 单独 get_all + '; '.join 重建;其余 header 多值仍 ', ' join(与原 items() 一致)。
    req_headers: dict[str, str] = {}
    for k in req.headers.keys():  # MultiDict.keys() 去重
        vals = req.headers.get_all(k)
        if k.casefold() == "cookie":
            req_headers[k] = "; ".join(vals)
        else:
            req_headers[k] = vals[0] if len(vals) == 1 else ", ".join(vals)
    pd, pd_trunc = _sanitize_post_bytes(req.content or b"", _MAX_BODY)  # 对齐点 5
    resp_dict: dict[str, Any] | None = None
    if resp is not None:
        resp_headers = {k: v for k, v in resp.headers.items()}
        # 大小写不敏感查 content-type(mitm headers key 是原始大小写 "Content-Type",
        # 普通 dict .get("content-type") 小写查会落空 → _should_capture_body("") 返
        # False → response body 全不采 → 全站流量 response body 丢。casefold 对齐
        # io._header_value。resp_headers dict 保留原始大小写 key 给 DB,不变。
        content_type = next(
            (v for k, v in resp_headers.items() if k.casefold() == "content-type"),
            "",
        )
        if _should_capture_body(content_type):  # 对齐点 1
            rb, rb_trunc = _sanitize_post_bytes(_decompress_bytes(resp), _MAX_BODY)
        else:
            rb, rb_trunc = None, False  # 非 text NULL
        resp_dict = {
            "received_at": "",
            "status": resp.status_code,
            "status_text": resp.reason,
            "headers": resp_headers,
            "content_type": content_type,
            "body_text": rb,
            "body_truncated": rb_trunc,
        }
    return {
        "request_id": flow.id,  # 对齐点 2 UUID
        "request": {
            "method": req.method,
            "url": req.url,
            "headers": req_headers,
            "post_data": pd,
            "post_data_truncated": pd_trunc,
        },
        "response": resp_dict,
        "failure": str(flow.error) if flow.error else None,
    }
    # 对齐点 3 rowid 序由 addon append 顺序保证;对齐点 6/7 不产归因/resource_type


class CaptureAddon:
    """mitmproxy addon:flow 到达(response 完成)→ record dict → 线程安全 list。

    response hook 在 mitmproxy asyncio 线程触发;flows_since/start 在录制 executor
    线程读,Lock 保护。仅收完整 flow(request+response 都就绪),request-only(如 server
    hang)不进——对齐 records 消费语义(下游 store 要 response dict)。
    """

    def __init__(self) -> None:
        self._flows: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def responseheaders(self, flow: Any) -> None:
        """响应头到(体未收):非 text(图/二进制/字体/媒体)开流式,防 mitmproxy
        全量缓体撑爆内存(抖店/字节 CDN 大图 over HTTP/2 实测 OOM)。

        WHY 这里而非 Options:recorder 反正丢非 text body——_should_capture_body 返
        False → _flow_to_record 的 body 走 None 分支,_decompress_bytes 都不调;
        故非 text 流式(响应体不缓、resp.content=None)对存储零行为变化,纯省内存。
        text 响应照常缓体(审计要前 256KB,extract_keys 取键靠 body)。开
        stream_large_bodies 会按体大阈值连 text 一起流式(体大文本也丢 body),错;
        responseheaders 按 content-type 精确只流非 text。纯被动不扰浏览器(客户端照收全量)。
        """
        resp = flow.response
        # casefold 取 content-type:mitm Headers 大小写不一(casefold 同 _flow_to_record)
        ct = next((v for k, v in resp.headers.items()
                   if k.casefold() == "content-type"), "")
        if not any(m in ct.lower() for m in TEXT_CONTENT_MARKERS):
            resp.stream = True

    def response(self, flow: Any) -> None:
        """mitmproxy response hook:flow 响应完成时触发。"""
        try:
            rec = _flow_to_record(flow)
        except Exception:  # noqa: BLE001  单条 flow 转换失败不崩整个代理
            logger.exception("mitmproxy flow→record 转换失败: %s", getattr(flow, "id", "?"))
            return
        with self._lock:
            self._flows.append(rec)  # 对齐点 3 到达序

    def flows_len(self) -> int:
        """当前已收 flow 数(录制开始时记起点用)。"""
        with self._lock:
            return len(self._flows)

    def flows_since(self, start_idx: int) -> list[dict[str, Any]]:
        """取 start_idx 之后的 flow 增量(录制期间产生的)。返回副本。"""
        with self._lock:
            return list(self._flows[start_idx:])

    def reset(self) -> None:
        """清空(测试用;生产单例不清,靠增量分隔)。"""
        with self._lock:
            self._flows.clear()


class MitmProxyService:
    """mitmproxy 代理进程级服务(全局单例,lifespan 起/停)。

    DumpMaster 后台 asyncio 线程(构造在 async _setup 里,Master.__init__ 要 running
    loop)。shutdown() 是 Master 的 sync thread-safe 方法(call_soon_threadsafe
    should_exit.set),run() 的 await should_exit.wait() 返回 → done() → run() 返回 →
    线程 loop run_until_complete 退出。

    ready 检测:起后台线程后 socket connect 探端口可连(超时抛 RuntimeError)。
    """

    def __init__(self) -> None:
        self._master: DumpMaster | None = None
        self._addon: CaptureAddon | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._started = False
        self._host = ""
        self._port = 0

    @property
    def is_running(self) -> bool:
        return self._started and self._master is not None

    @property
    def server(self) -> str:
        """代理 server 地址(给浏览器 launch proxy= / BrowserOption proxies 用)。"""
        return f"http://{self._host}:{self._port}"

    def start(self, *, host: str, port: int, ssl_insecure: bool = True) -> None:
        """起 mitmproxy 代理(后台 asyncio 线程)。已起则跳过。"""
        if self._started:
            return
        self._host = host
        self._port = port
        self._addon = CaptureAddon()
        opts = options.Options(
            listen_host=host,
            listen_port=port,
            ssl_insecure=ssl_insecure,  # 不验上游证书(对齐 PoC,最稳)
        )
        started_event = threading.Event()
        start_error: list[BaseException] = []

        def _run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop

            async def _setup() -> None:
                master = DumpMaster(opts, with_termlog=False, with_dumper=False)
                master.addons.add(self._addon)
                self._master = master
                started_event.set()  # 构造成功,主线程可继续
                await master.run()  # blocking 到 shutdown()

            try:
                loop.run_until_complete(_setup())
            except BaseException as exc:  # noqa: BLE001  记启动/运行期错误
                if not started_event.is_set():
                    start_error.append(exc)
                    started_event.set()
                else:
                    logger.warning("mitmproxy 运行期异常: %s", exc)
            finally:
                try:
                    loop.close()
                except Exception:  # noqa: BLE001
                    pass
                self._started = False
                self._master = None

        self._thread = threading.Thread(
            target=_run, name="mitmproxy-service", daemon=True
        )
        self._thread.start()
        # 等构造完成(DumpMaster 起来)或报错
        if not started_event.wait(timeout=15):
            raise RuntimeError("mitmproxy 启动超时(DumpMaster 未就绪)")
        if start_error:
            raise RuntimeError(f"mitmproxy 启动失败:{start_error[0]}")
        # 端口探活(代理 server 真可连)
        if not self._wait_port(host, port, timeout=8):
            raise RuntimeError(f"mitmproxy 端口 {port} 探活失败,代理未监听")
        self._started = True
        logger.info("mitmproxy 代理服务就绪 %s", self.server)

    def stop(self) -> None:
        """停 mitmproxy(graceful shutdown)。"""
        if not self._started:
            return
        master = self._master
        if master is not None:
            try:
                master.shutdown()  # sync thread-safe: call_soon_threadsafe(should_exit.set)
            except Exception:  # noqa: BLE001
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._started = False
        self._master = None
        self._addon = None
        self._thread = None
        self._loop = None
        logger.info("mitmproxy 代理服务已停止")

    def flows_since(self, start_idx: int) -> list[dict[str, Any]]:
        """取录制期间增量 flow。service 未起返空。"""
        if self._addon is None:
            return []
        return self._addon.flows_since(start_idx)

    def flows_len(self) -> int:
        if self._addon is None:
            return 0
        return self._addon.flows_len()

    @staticmethod
    def _wait_port(host: str, port: int, *, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1):
                    return True
            except OSError:
                time.sleep(0.2)
        return False


# ── 全局单例(record stage 起/停;进程级资源,session 间复用)─────

_service: MitmProxyService | None = None
_service_lock = threading.Lock()


def get_mitm_service() -> MitmProxyService:
    """取全局 mitmproxy 服务单例(可能未起,is_running 判)。"""
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                _service = MitmProxyService()
    return _service


def start_mitm_service() -> None:
    """起全局 mitmproxy 代理(幂等:已起则 no-op)。本仓唯一录制轨,由 record
    stage 调(原 app_server lifespan 随 Web 前端删除,见 ADR-0001/0002)。失败不抛
    (留 _service.is_running=False),由调用方 is_running 门禁兜,返回 failed。"""
    global _service
    if not settings.mitm_proxy_enabled:
        return
    with _service_lock:
        if _service is None:
            _service = MitmProxyService()
        if _service.is_running:
            return
        try:
            _service.start(
                host=settings.mitm_proxy_host,
                port=settings.mitm_proxy_port,
                ssl_insecure=settings.mitm_proxy_ssl_insecure,
            )
        except Exception as exc:  # noqa: BLE001  启动失败不崩进程,留 is_running=False 让 stage 兜
            logger.error("mitmproxy 代理服务启动失败(is_running=False,stage 将返回 failed): %s", exc)
            print(f"[启动] mitmproxy 代理服务启动失败(端口 {settings.mitm_proxy_host}:"
                  f"{settings.mitm_proxy_port} 可能被占):{exc}")
            # _service 保留但 is_running=False,get_mitm_service().is_running 判假


def stop_mitm_service() -> None:
    """lifespan 调:停全局 mitmproxy 代理。"""
    global _service
    if _service is not None:
        _service.stop()


# ── 录制入口(本仓唯一轨:mitmproxy 代理,纯被动)──────────────────────


# flow 终端行(Burp 式:# METHOD HOST PATH TYPE CODE RESP)。录制期增量 emit,替
# mitmproxy 原生 per-flow dumper(已 with_dumper=False 关)。列宽与 record_dry 对齐。
_W_IDX, _W_METHOD, _W_HOST, _W_PATH, _W_TYPE, _W_CODE, _W_RESP = 4, 6, 22, 50, 10, 4, 18


def _req_kind(req: dict) -> str:
    """请求体编码 json/form/multipart/-(派生自 request content-type,casefold 查)。"""
    headers = req.get("headers") or {}
    ct = next((v for k, v in headers.items() if k.casefold() == "content-type"), "")
    ct_l = ct.casefold()
    if "json" in ct_l:
        return "json"
    if "multipart" in ct_l:
        return "multipart"
    if "urlencoded" in ct_l:
        return "form"
    return "-"


def _resp_type(resp: dict) -> str:
    """响应 content-type(去 ; 参数):recorder 已 casefold 提取好 content_type 字段。"""
    ct = (resp.get("content_type") or "").split(";")[0].strip()
    return ct or "-"


def _flow_line(idx: int, rec: dict) -> str:
    """flow record → 终端一行:# METHOD HOST PATH TYPE CODE RESP(列对齐)。"""
    req = rec.get("request") or {}
    resp = rec.get("response") or {}
    method = (req.get("method") or "?")[:_W_METHOD]
    url = req.get("url") or ""
    parsed = urlparse(url)
    host = (parsed.hostname or "?")[:_W_HOST]
    path = (parsed.path or "/")[:_W_PATH]
    kind = _req_kind(req)[:_W_TYPE]
    status = resp.get("status") or "-"
    rtype = _resp_type(resp)[:_W_RESP]
    return (
        f"{idx:>{_W_IDX}} {method:<{_W_METHOD}} {host:<{_W_HOST}} {path:<{_W_PATH}} "
        f"{kind:<{_W_TYPE}} {status:>{_W_CODE}} {rtype:<{_W_RESP}}"
    )


def _flow_header() -> str:
    return (
        f"{'#':>{_W_IDX}} {'METHOD':<{_W_METHOD}} {'HOST':<{_W_HOST}} {'PATH':<{_W_PATH}} "
        f"{'TYPE':<{_W_TYPE}} {'CODE':>{_W_CODE}} {'RESP':<{_W_RESP}}"
    )


async def run_record_session_mitm(
    url: str,
    *,
    session_dir: str,
    timeout: int = 3600,
    stop_event: asyncio.Event | Any = None,
    on_event: Any = None,
) -> dict[str, Any]:
    """mitmproxy 代理录制手动操作流量 → 落 traffic.sqlite(history 表,原始流量行)。

    纯被动:后端起 mitmproxy 代理(全局 MitmProxyService),浏览器启动时挂
    --proxy-server 指向它(命令行 chrome / 系统代理)+ 装 mitmproxy CA 过 HTTPS,
    人手操作触发流量;后端轮询 stop_event/timeout,收尾取 service.flows_since(start)
    增量 → NoiseFilter drop 噪音 → ProxyStore.dump 落盘。后端不 connect 浏览器、
    不接管、不导航、不 dismiss 弹窗——全靠人手操作(见 docs/decisions/0002-mitm-only-drop-cdp.md)。url 仅作目标
    元数据(后端不导航,人手自己开页)。

    前提:浏览器启动时已挂 proxy 指向 mitm service + 装 CA(--ignore-certificate-errors
    或装 mitmproxy CA)。否则流量不经代理 / HTTPS 解不开,flows_since 拿空。
    mitm service 未起(is_running=False)→ raise RuntimeError。
    """
    if stop_event is None:
        stop_event = asyncio.Event()
    service = get_mitm_service()
    if not service.is_running:
        raise RuntimeError(
            "mitmproxy 代理服务未运行,无法录制。请确认 settings.mitm_proxy_enabled "
            "=True 且后端启动时 lifespan 起服务成功。"
        )
    start_idx = service.flows_len()  # 录制起点(增量分隔,项目串行不混)
    emit = on_event or (lambda _msg: None)
    emit(f"[record] mitmproxy 纯被动录制中(浏览器挂代理 "
         f"{settings.mitm_proxy_host}:{settings.mitm_proxy_port},手动操作后点'停止'结束,"
         f"超时 {timeout}s 兜底)")
    emit(_flow_header())  # flow 列表列头(Burp 式,录制期每条流量一行)
    deadline = time.monotonic() + timeout
    seen = 0  # 本 session 已 emit 的 flow 数(相对序,1 起)
    try:
        while True:
            # 增量打 flow 行:每轮取自上次起的新 flow,逐条 emit(替 mitmproxy 原生 dumper)
            new_flows = service.flows_since(start_idx + seen)
            for i, f in enumerate(new_flows):
                emit(_flow_line(seen + 1 + i, f))
            seen += len(new_flows)
            if _is_set(stop_event):
                emit("[record] 收到停止信号,结束录制")
                break
            if time.monotonic() >= deadline:
                emit(f"[record] 超时 {timeout}s 兜底,自动结束录制")
                break
            await asyncio.sleep(0.5)
    finally:
        # 收尾 dump 必跑:Ctrl+C / task cancel 在 await asyncio.sleep 抛 CancelledError
        # (BaseException,except Exception 捕不到)会跳过 while 后的同步收尾 → 流量在
        # CaptureAddon 内存没落盘,被下游 stop_mitm 清丢(_addon=None → flows_since 返空)。
        # 移进 finally 保 dump 必跑(flows_since/drop_noise/dump 全同步不 await,不被再 cancel)。
        records = service.flows_since(start_idx)
        noise = NoiseFilter.load()
        records, skipped_noise = drop_noise(records, noise)
        written = 0
        try:
            written, _ids = ProxyStore(session_dir).dump(records)
            msg = f"[record] 流量落地 {written} 条(mitmproxy)"
            if skipped_noise:
                msg += f"(已过滤 {skipped_noise} 噪音)"
            emit(msg)
        except Exception as exc:  # noqa: BLE001
            emit(f"[record] 流量落地失败:{type(exc).__name__}: {exc}")
    return {"url": url, "traffic_records": written, "source": "mitmproxy"}
