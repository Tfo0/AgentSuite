from __future__ import annotations

from typing import Any


def make_pack_stop_hook(state, batch_rids: list[str] | None = None):
    """Stop 门禁:每 batch_rid ∈ ⋃ module.traffic_ids 才放行(noise/novel 模块也算覆盖)。continue_=True=挡停/False=允许停。batch_rids 空→无门禁(state.dispatched 非空即放行)。"""

    async def stop_hook(hook_input: dict[str, Any],
                        _tool_name: str | None = None,
                        _context: Any = None) -> dict[str, Any]:
        covered: set[str] = set()
        for m in (state.dispatched or []):
            if not isinstance(m, dict):
                continue
            for tid in (m.get("traffic_ids") or []):
                covered.add(str(tid))
        if not batch_rids:
            if state.dispatched:
                return {"continue_": False}
            return {
                "continue_": True,
                "stopReason": "dispatch:尚未调任何 dispatch_send。把可疑流量打包成模块后再结束。",
            }
        missing = [r for r in batch_rids if r not in covered]
        if not missing:
            return {"continue_": False}
        preview = ", ".join(missing[:5])
        return {
            "continue_": True,
            "stopReason": (
                f"dispatch:尚有 {len(missing)} 个单元未被任何模块覆盖(如 {preview})。"
                "把每个单元的 traffic_id 至少打进一个模块后再结束:"
                "可疑的相关流量打成一包(skills 填目录表 skill 列的 stem 如 idor-test/upload-test,"
                "keys 填证据指针,notes 写一句话分组理由,不写打法);无 catalog 的新套路 skills=[](novel,notes 写思路草案——这是 notes 唯一可写思路处);"
                "纯静态/OPTIONS/埋点噪音也打成 skills=['noise'] 的模块(标 dropped,也算覆盖)。"
                "一个模块可捆多条相关流量 + 多个攻击面。"
            ),
        }

    return stop_hook
