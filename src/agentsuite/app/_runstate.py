"""as run 的活跃 run 状态文件(全局单活跃:同时只一个 as run 在录)。

state 文件是 cli 自己的事(记 session/mode 给启动查陈旧)。
全局位置 project/active_run.json(仓库内,.gitignore 已 ignore,不依赖 session_dir)。

0→1 session-based:session_dir 是唯一坐标。
"""
from __future__ import annotations

import json

from agentsuite.config import settings

STATE_FILE = settings.project_path / "active_run.json"


def write_state(*, session_dir: str, mode: str) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({
        "session_dir": session_dir, "mode": mode,
    }, ensure_ascii=False), encoding="utf-8")


def read_state() -> dict | None:
    if not STATE_FILE.is_file():
        return None
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def clear_state() -> None:
    try:
        STATE_FILE.unlink()
    except FileNotFoundError:
        pass
