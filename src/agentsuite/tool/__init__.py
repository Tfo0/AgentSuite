"""traffic MCP server:HTTP 流量编辑重放能力(8 工具),可被多个 agent 复用。

mcp 是能力插件,agent 是配置。
8 工具:get/search/repeater/send/brute/diff/dispatch_send/verify_report;skill 访问走 agent 原生 Read/Edit。
per-agent 子集由 build_traffic_mcp_server 的 tool_subset 硬门禁(替掉 allowed/disallowed 双机制)。
"""
from __future__ import annotations
from .models import RunState
from .runner import build_traffic_services, make_stop_hook
from .server import TRAFFIC_TOOL_NAMES, build_traffic_mcp_server
from .service.query_service import load_common_params

__all__ = [
    "RunState",
    "TRAFFIC_TOOL_NAMES",
    "build_traffic_mcp_server",
    "build_traffic_services",
    "load_common_params",
    "make_stop_hook",
]
