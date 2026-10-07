"""响应体分页工具(leaf,无依赖)。

replay_service 和 query_service 都要用,放这里避免 replay→query 的循环 import
(query_service 又 import replay_service 里的 HttpTransport——循环会 partial-init 炸)。
"""
from __future__ import annotations

from typing import Any


# traffic_get 的 response.body_text 默认返回上限(字符)。镜像 harness Read 的 limit:
# 默认只回前 32KB,大响应体不一次性灌进上下文;agent 看 body_truncated/body_total 翻页。
# 32KB ≈ 8K token,单次调用可控;login/list JSON 多在 50B-50KB 够看全,HTML 页不够再 offset 翻。
_DEFAULT_BODY_LIMIT = 32768


def _paginate_body(text: Any, offset: int, limit: int) -> tuple[str, bool, int]:
    """对 response.body_text 做 Read 式 offset/limit 分页。

    返回 (切片, 是否被截断, 总长)。truncated=True 表示 offset+limit 之后还有内容,
    agent 调 offset+=limit 翻页。limit<=0 或 offset<0 → 不分页(全量返回),给 agent
    一个"我要看全部"的逃生口(0/负 = 全量)。body_text 为 None → ("", False, 0)。
    """
    if text is None:
        return "", False, 0
    if not isinstance(text, str):
        text = str(text)
    total = len(text)
    if limit <= 0 or offset < 0:
        return text, False, total
    sliced = text[offset:offset + limit]
    return sliced, (offset + limit) < total, total
