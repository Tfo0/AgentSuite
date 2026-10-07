"""app:命令行入口 + bootstrap。

bootstrap.py 装配日志 + 读 .env;main.py 是 `as` console_script 入口,
注册 run 子命令(平级文件,非子目录)。
"""
from .bootstrap import bootstrap_cli
from .settings import load_env_file

__all__ = ["bootstrap_cli", "load_env_file"]
