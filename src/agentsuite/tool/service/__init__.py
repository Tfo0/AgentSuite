"""traffic 能力的 service 层。

- edit_engine:全局 find/replace 编辑内核(find 唯一命中才替,歧义护栏)
- replay_service:重放编排 + 简版 diff(status/body/time)+ repeater/brute/send 入口
- query_service:list/get 查询 + traffic_diff(两已存响应比对)
- report_service:结论门禁(confirmed 须客观变化证据)
- dispatch_service:dispatch 分发工作单(写 dispatch_queue 表,替 dispatch 的旧 report)
"""
from .edit_engine import apply_find_replace
from .replay_service import ReplayService, RequestsHttpTransport, ResponseSnapshot, compare_snapshots
from .query_service import QueryService
from .report_service import ReportService
from .dispatch_service import DispatchService

__all__ = [
    "apply_find_replace", "ReplayService", "RequestsHttpTransport",
    "ResponseSnapshot", "compare_snapshots", "QueryService", "ReportService",
    "DispatchService",
]
