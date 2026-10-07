"""traffic mcp 的运行支撑:service 构建 + Stop 门禁。

agent 层调 build_traffic_services + make_stop_hook。prompt/options 组装在 agent 层,不在这里。
"""
from __future__ import annotations
from pathlib import Path
from typing import Any

from .data.store import AuditStore
from .models import RunState
from .service.query_service import QueryService
from .service.replay_service import ReplayService
from .service.report_service import ReportService
from .service.dispatch_service import DispatchService


def _resolve_traffic_dir(session_dir: str | Path) -> Path:
    """解析真正的 traffic.sqlite 所在目录。

    page agent 的 dump 写 session_dir/pipeline/proxy/traffic.sqlite(pipeline/proxy/ 子目录下)。
    传入目录本身不一定是已存在目录,判断的是「子目录是否存在」。
    """
    root = Path(session_dir).resolve()
    subdir = root / "pipeline" / "proxy"
    if subdir.is_dir():
        return subdir
    if root.name == "proxy":
        return root
    return subdir


def build_traffic_services(
    session_dir: str | Path | None = None,
    *,
    allow_mutating: bool = True,
) -> tuple[QueryService, ReplayService, ReportService, DispatchService, RunState]:
    """装配 service + state。

    session_dir 是会话根目录(traffic_node 传 ctx.session_dir,即项目根);
    实际 traffic.sqlite 在其下的 pipeline/proxy/ 子目录里。读 history 表(原始流量) +
    重放证据写回 evidence 表(source 列区分 repeater/brute/send;baseline/edit/diff/baseline_stable/source_id 是证据元数据列,history 行全无)。

    transport(replay 共享同一个发包器)、store(共享同一个 store)
    在这里建一次注入给各 service,避免各 service 各建一份 transport。
    dispatch_service(dispatch 分发可疑到 verify,写 dispatch_queue 表)同 store 注入。
    """
    if session_dir is None:
        raise ValueError("必须提供 session_dir")
    traffic_dir = _resolve_traffic_dir(session_dir)
    db_path = traffic_dir / "traffic.sqlite"
    store = AuditStore(database_path=db_path, session_dir=session_dir)
    from .service.replay_service import RequestsHttpTransport
    transport = RequestsHttpTransport(allow_mutating=allow_mutating)
    # 噪音过滤移至 lib/filter(Phase2);build_clean 在 lib 产 clean.jsonl/noise.jsonl,
    # 不再走 query_service。QueryService 只剩读+打包(list/get/diff/pack_units)。
    query_service = QueryService(store)
    replay_service = ReplayService(store, transport=transport, allow_mutating=allow_mutating,
                                    verify_tls=False, baseline_repeats=2)
    report_service = ReportService(store)
    dispatch_service = DispatchService(store, session_dir=str(session_dir))
    state = RunState()
    return query_service, replay_service, report_service, dispatch_service, state


def make_stop_hook(state: RunState):
    """结束门禁:每个输入 skill 须有 ≥1 条 verdict 覆盖才允许结束(否则 continue_=True 续跑)。

    旧问题:agent 输入 skill=[idor,sqli] 只输出 idor 说没洞,sqli 不提 → 静默漏 skill。
    现逐 skill 查 state.findings 的 skill 字段:全覆盖才放行。没测的 skill 须标 inconclusive
    (prompt 已要求),不能当 rejected 跳过——"没测"≠"没漏洞"。

    - expected_skills=None(全量扫描)或空集(novel):无 skill 清单,只要求 ≥1 finding 兜底。
    - expected_skills={"noise"} 纯噪声模块:dispatch 应已 drop,防御性放行。

    SDK 语义(types.py:524):continue_=True=继续跑/挡停(force 另一轮);continue_=False=允许停。
    与 page make_stop_hook 同模式,曾一起写反(continue_=False 当强制)。

    SDK 的 hook 回调签名是 (hook_input, hook_specific_data, context) 三参,
    三个都要接(后两个这里不用但要占位),否则报 "takes 1 positional arg but 3 were given"。
    """

    async def stop_hook(hook_input: dict[str, Any],
                        _tool_name: str | None = None,
                        _context: Any = None) -> dict[str, Any]:
        findings = state.findings
        if not findings:
            return {
                "continue_": True,
                "stopReason": "尚未提交任何 verdict(漏洞/可疑),必须继续分析或提交一条 inconclusive 收尾",
            }
        expected = state.expected_skills
        # None(全量扫描)或空集(novel):无 skill 清单,≥1 finding 即放行
        if not expected:
            return {"continue_": False}
        # 逐 skill 覆盖率:每个非 noise skill 须有 ≥1 条 verdict
        skills_to_cover = {str(s).strip().casefold()
                           for s in expected if s and str(s).strip().casefold() != "noise"}
        if not skills_to_cover:  # 纯 noise 模块(dispatch 应已 drop,防御放行)
            return {"continue_": False}
        covered = {str(f.get("skill") or "").strip().casefold()
                   for f in findings if isinstance(f, dict)}
        missing = sorted(s for s in skills_to_cover if s not in covered)
        if missing:
            return {
                "continue_": True,
                "stopReason": (
                    f"输入 skill 未覆盖:{'、'.join(missing)}。每个 skill 须 verify_report 提交一条"
                    f" verdict(rejected/inconclusive/confirmed);没测完的标 inconclusive,不能当 rejected 跳过"
                ),
            }
        return {"continue_": False}

    return stop_hook
