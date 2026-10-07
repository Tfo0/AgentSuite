"""CLI bootstrap:读 .env + 配日志。所有 as 命令入口前先调一次。"""
from __future__ import annotations

import logging

from .settings import load_env_file


def bootstrap_cli() -> None:
    load_env_file()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # SDK/asyncio 噪声降到 WARNING(INFO 刷不掉的真问题仍上浮)
    for _n in ("asyncio", "claude_agent_sdk"):
        logging.getLogger(_n).setLevel(logging.WARNING)
    # mitmproxy 连接级日志(client/server disconnect 等)是录制期终端噪音主体——
    # per-flow 行已在 recorder DumpMaster(with_termlog/dumper=False)关掉,但连接级 INFO
    # 经 root handler 渗进终端。压 mitmproxy 命名空间到 WARNING:连接噪音消失,真出错
    # (端口占用/证书问题)仍冒 WARNING+。
    logging.getLogger("mitmproxy").setLevel(logging.WARNING)
