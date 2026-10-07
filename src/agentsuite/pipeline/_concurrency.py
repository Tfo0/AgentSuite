"""全局并发配置:glm LLM API 并发上界。

dispatch 和 verify 的 agent 调用都吃 glm API,受 cooldown 限并发。_run_stages 建一把
asyncio.Semaphore(N) 注入 ctx.glm_sem,两 stage 共用 → 总并发 ≤ N(跟 stage 无关)。
N 从环境变量 AGENTSUITE_GLM_CONCURRENCY 读,默认 3(glm cooldown 真值)。

非流式直调(测试里 run_verify_stage(ctx, emit) 不经 _run_stages)时,stage 自建本地 sem,
行为退化为单跑——测试不关心 N,只验 wiring。
"""
from __future__ import annotations

import os


def glm_concurrency_size() -> int:
    """glm 并发上界(环境变量 AGENTSUITE_GLM_CONCURRENCY,默认 3,最小 1)。"""
    try:
        n = int(os.environ.get("AGENTSUITE_GLM_CONCURRENCY", "3"))
    except ValueError:
        n = 3
    return max(1, n)
