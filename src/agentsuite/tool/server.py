"""traffic MCP server:纯能力,可被多个 agent 复用。

只建 server + tool 工厂,不含 prompt/options/hooks。
工具(8):get 读流量;search 全文搜 history(upstream-tracing:不可遍历 id 追溯上游流量);
repeater/send/brute 改造发;diff 对比;dispatch_send 分发(dispatch 用);verify_report 收尾(verify 注册)。
skill 访问走 agent 原生 Read/Edit(skill/*.md),不挂 MCP——
skill 是静态 .md,无压缩缝、无 round-trip id 空间(见 mcp-compression-seam-rationale 评估)。

per-agent 子集(硬门禁):build_traffic_mcp_server 接 tool_subset,只注册该 agent 该有的工具。
没注册=调不了,替掉 allowed_tools(advisory)+ disallowed_tools 双机制——bypassPermissions 下
前者只是"免提示"不挡事,disallowed 才真拒;现由 server 注册子集直接硬门禁。
"""
from __future__ import annotations
from typing import Any
from claude_agent_sdk import create_sdk_mcp_server
from .models import RunState
from .service.query_service import QueryService
from .service.replay_service import ReplayService
from .service.report_service import ReportService
from .service.dispatch_service import DispatchService
from .tool_use.traffic_get import make_traffic_get
from .tool_use.traffic_search import make_traffic_search
from .tool_use.traffic_repeater import make_traffic_repeater
from .tool_use.traffic_send import make_traffic_send
from .tool_use.traffic_brute import make_traffic_brute
from .tool_use.traffic_diff import make_traffic_diff
from .tool_use.dispatch_send import make_dispatch_send
from .tool_use.report import make_report

# 顺序:get/search(读) → repeater/send/brute(改造发) → diff(对比) → dispatch_send(分发) → verify_report(收尾)
TRAFFIC_TOOL_NAMES = [
    "mcp__traffic__traffic_get",
    "mcp__traffic__traffic_search",
    "mcp__traffic__traffic_repeater",
    "mcp__traffic__traffic_send",
    "mcp__traffic__traffic_brute",
    "mcp__traffic__traffic_diff",
    "mcp__traffic__dispatch_send",
    "mcp__traffic__verify_report",
]


def build_traffic_mcp_server(
    query_service: QueryService,
    replay_service: ReplayService,
    report_service: ReportService,
    dispatch_service: DispatchService,
    state: RunState,
    *,
    tool_subset: list[str] | None = None,
) -> Any:
    """建 traffic MCP server:按 tool_subset 注册工具子集(硬门禁)。

    tool_subset=None=全 8 工具(测试/通用);传 list=只注册命中的(该 agent 该有的)。
    非 TRAFFIC_TOOL_NAMES 的名字(如 Bash)自动忽略——传 allowed_tools(MCP 名 + 可能含 Bash)
    当 tool_subset,Bash 不在 TRAFFIC_TOOL_NAMES 里自然滤掉。dispatch_service 由
    build_traffic_services 一起建好注入(dispatch 才用,其他 agent 的 tool_subset 不含
    dispatch_send 即不注册该工具)。
    """
    all_tools = [
        ("mcp__traffic__traffic_get", make_traffic_get(query_service)),
        ("mcp__traffic__traffic_search", make_traffic_search(query_service)),
        ("mcp__traffic__traffic_repeater", make_traffic_repeater(replay_service, state)),
        ("mcp__traffic__traffic_send", make_traffic_send(replay_service, state)),
        ("mcp__traffic__traffic_brute", make_traffic_brute(replay_service, state)),
        ("mcp__traffic__traffic_diff", make_traffic_diff(query_service)),
        ("mcp__traffic__dispatch_send", make_dispatch_send(dispatch_service, state)),
        ("mcp__traffic__verify_report", make_report(report_service, state, name="verify_report", stage="verify")),
    ]
    subset = set(tool_subset) if tool_subset is not None else None
    tools = [t for name, t in all_tools if subset is None or name in subset]
    return create_sdk_mcp_server("traffic", "2.0.0", tools=tools)
