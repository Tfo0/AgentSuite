from __future__ import annotations

import importlib

from agentsuite.agent.base import Node


# 懒注册:首次 get_node 时 import 对应 node 包触发 register,避免启动时强依赖全部 node。
_REGISTRY: dict[str, Node] = {}


def register(node: Node) -> None:
    """node 包把自己的 node 实例注册进来。重复注册覆盖(开发期 reload 友好)。"""
    name = node.manifest.name
    _REGISTRY[name] = node


def get_node(name: str) -> Node | None:
    """从注册表拿 node。没注册返回 None(不抛,调用方自己处理 404)。"""
    if name not in _REGISTRY:
        _lazy_load(name)
    return _REGISTRY.get(name)


def _lazy_load(name: str) -> None:
    """首次访问某 node 时 import 它的包,触发 register。import 失败静默(留待 get 时报错)。"""
    try:
        importlib.import_module(f"agentsuite.agent.{name}")  # noqa: F401
    except Exception:
        pass
