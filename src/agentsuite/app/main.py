"""as 命令行入口:bootstrap + run 子命令。

console_script `as = agentsuite.app.main:main` 指向这里。
forced-loop 链路:as run(mitm 录制 → 按回车停 → dispatch→verify→report),不依赖 Web。
"""
from __future__ import annotations

import argparse

from agentsuite.app import bootstrap_cli


def build_parser() -> argparse.ArgumentParser:
    from . import run

    parser = argparse.ArgumentParser(
        prog="as",
        description="AgentSuite forced-loop 黑盒流量审计命令行工具(as run 录制 → 审计 → 报告)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    run.register(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    bootstrap_cli()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.command_handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
