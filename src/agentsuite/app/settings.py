""".env 文件读取:把 KEY=VALUE 灌进 os.environ(不覆盖已有的,除非 override=True)。

只做解析,不校验字段名。.env 不在版本库(gitignore),用于本地放
API key / token / webhook URL 等敏感配置(VISION_API_KEY / PACKY_API_KEY /
AGENTSUITE_PLANNER_API_KEY / AGENTSUITE_WEBHOOK_* 等)。
"""
from __future__ import annotations

import os
from pathlib import Path


def load_env_file(
    path: str | Path = '.env',
    *,
    override: bool = False,
) -> dict[str, str]:
    env_path = Path(path)
    if not env_path.is_file():
        return {}

    loaded: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding='utf-8-sig').splitlines():
        parsed = _parse_line(raw_line)
        if parsed is None:
            continue
        key, value = parsed
        if not value:
            continue
        if override or key not in os.environ:
            os.environ[key] = value
        loaded[key] = value
    return loaded


def _parse_line(raw_line: str) -> tuple[str, str] | None:
    line = raw_line.strip()
    if not line or line.startswith('#'):
        return None
    if line.startswith('export '):
        line = line[7:].strip()
    if '=' not in line:
        return None
    key, value = line.split('=', 1)
    key = key.strip()
    if not key:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in (chr(34), chr(39)):
        value = value[1:-1]
    return key, value
