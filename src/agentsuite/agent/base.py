from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Protocol, runtime_checkable

# emit:node 往 SSE 推进度字符串的回调。
Emit = Callable[[str], None]


@dataclass
class RunContext:
    """session_dir 唯一坐标;stage 间经 DB/files 解耦不经 ctx 传产物(只带配置+全局信号量)。"""
    project_id: str
    session_dir: str
    url: str = ""
    provider: str = "local"
    headless: bool = True
    record_enabled: bool = True         # False=跳过录制,复用现有 traffic.sqlite
    traffic_max_turns: int = 30
    traffic_allow_mutating: bool = True
    traffic_timeout: int = 600
    dispatch_enabled: bool = True
    verify_enabled: bool = True
    report_enabled: bool = True
    dispatch_max_turns: int = 12
    dispatch_timeout: int = 300
    report_max_turns: int = 80
    report_timeout: int = 3600
    disabled_tools: list[str] = field(default_factory=list)
    record_traffic: bool = True  # forced-loop 场景必录
    stop_event: Any = None  # 只 record 读;None=无 stop 通道(等超时兜底)
    record_timeout: int = 3600
    glm_sem: Any = None        # dispatch+verify 共用(glm cooldown 限并发);None=standalone 单跑
    dispatch_done: Any = None  # Event:dispatch 产完→set;verify 据此判流式终止


NodeRun = Callable[[RunContext, Emit], Awaitable[dict[str, Any]]]


@dataclass
class NodeManifest:
    """node 自描述:pipeline 据此做依赖咬合校验。"""
    name: str
    category: str
    requires: list[str]
    produces: list[str]
    optional_config: list[str]


@runtime_checkable
class Node(Protocol):
    """node 协议:一个 manifest + 一个 run。具体实现在各 node 目录,这里只定契约。"""
    manifest: NodeManifest
    run: NodeRun


class BaseRunner:
    """agent 运行层基类:_emit/超时配置/drive 调用样板共用;子类只覆写数据注入 + 结果映射。

    max_turns/session_timeout_s 默认 None(子类无参实例化兼容,如测试 DispatchRunner());
    生产路径 run_<x> 显式传值。allow_mutating 默认 True(report 不用,其 build_options 硬编码 False)。"""

    def __init__(self, *, max_turns: int | None = None,
                 session_timeout_s: int | None = None,
                 allow_mutating: bool = True, on_event: Any = None) -> None:
        self.max_turns = max_turns
        self.session_timeout_s = session_timeout_s
        self.allow_mutating = allow_mutating
        self._on_event = on_event

    def _emit(self, msg: str) -> None:
        if self._on_event is not None:
            try:
                self._on_event(msg)
            except Exception:
                pass

    async def _drive(self, *, build_options_fn, user_prompt: str, tag: str):
        """缝合 drive_with_resume:子类传 build_options_fn(接 resume_id)+ user_prompt + tag,
        本方法注入 resume_prompt/on_message/emit 样板。返 (result_text, structured, state)。"""
        from .engine import (
            DEFAULT_RESUME_PROMPT, drive_with_resume, render_sdk_message)
        return await drive_with_resume(
            build_options_fn=build_options_fn, prompt=user_prompt,
            resume_prompt=DEFAULT_RESUME_PROMPT,
            on_message=lambda m: render_sdk_message(self._emit, m),
            emit=self._emit, tag=tag)
