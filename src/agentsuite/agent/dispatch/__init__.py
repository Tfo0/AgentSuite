from __future__ import annotations

from .runner import DispatchRunner, run_dispatch, NODE
from agentsuite.agent import registry

registry.register(NODE)

__all__ = ["DispatchRunner", "run_dispatch", "NODE"]
