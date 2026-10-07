"""proxy:录制→过滤→clean 产出(无 LLM、无编排,输入→输出,自带 io 落盘)。

recorder:mitmproxy 代理录制流量(本仓唯一轨)→ traffic.sqlite(history 表,
schema 对齐 tool store,下游 dispatch/verify 零改读)。filter:落盘前噪音 drop
(NoiseFilter own 在 filter.py,filter.yaml 加载也在那)。

不 import tool/agent;共用 HTTP 类型(HttpBody/HttpExchange)走本包 http.py。
pipeline.stages 的 run_record_stage 直接调本包(无 LLM 的纯逻辑不套 agent)。
"""
from __future__ import annotations

from .recorder import (
    run_record_session_mitm,
    get_mitm_service,
    start_mitm_service,
    stop_mitm_service,
)

__all__ = [
    "run_record_session_mitm",
    "get_mitm_service",
    "start_mitm_service",
    "stop_mitm_service",
]
