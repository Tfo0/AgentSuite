"""traffic 能力的领域模型。纯数据 dataclass,零业务方法、零存储知识。

HTTP 交换 DTO(HttpHeader/Body/Request/Response/Exchange)在 proxy/http.py,
proxy 和 traffic 共用、互不依赖。这里放 traffic 私有的:
  - ResponseSnapshot / ResponseDiff:重放响应快照与差异比对(减法后极简版)
  - ReplayRecord:一条重放证据(repeater 表的领域对象)
  - RunState:traffic_agent 的运行态数据对象
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ResponseSnapshot:
    """重放响应快照。极简:只留客观事实,语义判断归 LLM。
    砍了 body_hash/json_shape/business_signature/normalized_body_hash/content_type/content_length——
    这些是"替 LLM 判断语义",产生假阳性(login 实测)。"""

    status: int
    body_text: str
    elapsed_ms: int
    body_truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ResponseDiff:
    """响应差异。极简三维度:status/body/time。只报客观变化,意义归 LLM。
    砍了 content_type/json_shape/business/normalized/length_delta。"""

    status: bool   # 状态码变没变
    body: bool     # body 字节变没变
    time: int      # 耗时差(ms,candidate - baseline)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReplayRecord:
    """一条重放证据(evidence 表存,source 列区分 repeater/brute/send)。

    kind=repeater/brute/send(重放产物,evidence.source 列 + source_seq 各 source 内自增)。
    request/response 存 evidence.request_json/response_json;baseline/edit/diff/
    baseline_stable/source_id 存 evidence 的证据元数据列(history 行无这些列)。"""

    id: str          # <source>:<source_seq>(repeater:N / brute:N / send:N)
    kind: str        # repeater/brute/send(= evidence.source)
    source_id: str   # 原始流量 id(history:<id>;repeater/brute/send 都基于某原始流量,send 无则空)
    request: dict[str, Any]
    response: dict[str, Any]
    baseline: dict[str, Any]   # 无 baseline 时为空 dict
    edit: dict[str, Any]       # 改了什么(find/replace 或 raw 请求)
    diff: dict[str, Any]
    baseline_stable: bool


@dataclass
class RunState:
    """本次验证的运行态。replay_service 写 replays,report_service 写 findings(逐条),
    dispatch_service 写 dispatched(dispatch agent 打包的模块明细),runner 的 Stop hook 读
    findings/dispatched 判断门禁。纯字段,无行为方法。

    dispatched 每条 = 一个**模块** {module_id, traffic_ids, skills, keys, notes, status}
    (一次 dispatch_send = 1 模块,捆 1+ traffic_ids + 1+ skills;LLM 判断把相关流量打成
    一包)。dispatch stop hook 据此判覆盖率(每 batch_rid ∈ ⋃ module.traffic_ids 才放行),
    runner _resolve 据此填每条 DispatchResult(有非 noise 模块覆盖→hit;仅 noise→skip;
    未覆盖→inconclusive)。"""

    replays: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    dispatched: list[dict[str, Any]] = field(default_factory=list)
    # verify 模块化模式:当前模块允许的根 history id 集({"history:N", ...})。
    # evidence 门禁归属校验用——引用证据的 source_id 须链回这些 history 之一,否则拒
    # (防 agent 跨模块复用同一条 repeater:N 交差)。None=不限(全量扫描)。
    expected_traffic_ids: set[str] | None = None
    # 当前模块的输入 skill 集(verify stop 门禁覆盖率用——每个 skill 须有 ≥1 条
    # verdict 覆盖,没测的标 inconclusive 不能当没洞)。None=不限(全量扫描/novel)。
    expected_skills: set[str] | None = None
