"""全局配置:project_root / mitm 代理,集中。

顶层独立,谁都用。pipeline/proxy/agent 都从这里拿 settings。
0→1 session-based:无全局 sqlite,只留路径 + mitm 配置。
"""
from __future__ import annotations

from pathlib import Path


class Settings:
    """全局配置。CLI 单进程,进程内单例即可。"""

    project_root: str = "project"

    # mitmproxy 流量录制代理(CLI as run 起/停全局单例,本仓唯一录制轨)。
    # 开:浏览器启动时挂 --proxy-server 指向它,流量经代理录(request/response body
    # 完整,代理层天然拿全 body)。
    # 关:无录制(mitm 关了就没流量入口)。
    # ssl_insecure=True:mitmproxy 不验上游证书(自签 HTTPS 站也能录,真实站更顺)。
    # 客户端证书靠 chrome --ignore-certificate-errors flag(在 launch 级设,盖所有页)。
    mitm_proxy_enabled: bool = True
    mitm_proxy_host: str = "127.0.0.1"
    mitm_proxy_port: int = 8082
    mitm_proxy_ssl_insecure: bool = True

    @property
    def project_path(self) -> Path:
        p = Path(self.project_root).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()
