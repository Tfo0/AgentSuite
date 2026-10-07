"""traffic MCP 7 工具真实 LLM 实测:不真打站点,用 FakeTransport 拦截 HTTP。

挂完整 traffic mcp 给 claude sdk,给模型一条模拟 login 流量(同真实 JSON body
形态),让它依次用全部 7 个工具做常规编辑重放,最后自评体感:
哪个工具不好用、哪个没必要、响应格式是否合适、坐标是否够用。

不发真实 HTTP(FakeTransport 返回模拟 baseline/candidate 响应 + 可预测 diff)。
"""
from __future__ import annotations

import asyncio
import json

from claude_agent_sdk import (
    AssistantMessage, ClaudeAgentOptions, ClaudeSDKClient, HookMatcher,
    ResultMessage, SystemMessage, TextBlock, ToolResultBlock, ToolUseBlock,
)

from agentsuite.tool import (
    TRAFFIC_TOOL_NAMES, build_traffic_mcp_server, make_stop_hook,
)
from agentsuite.tool.data.store import AuditStore
from agentsuite.tool.models import RunState, ResponseSnapshot
from agentsuite.tool.service.replay_service import ReplayService
from agentsuite.tool.service.query_service import QueryService
from agentsuite.tool.service.report_service import ReportService
from agentsuite.tool.service.dispatch_service import DispatchService

MODEL = "claude-opus-4-1"


def _snap(status=200, body='{"code":0,"msg":"ok"}'):
    return ResponseSnapshot(
        status=status, body_text=body, elapsed_ms=10, body_truncated=False,
    )


class FakeTransport:
    """拦真实 HTTP。candidate 按 body 内容制造 diff(改 admin→其他触发 500)。"""

    def send(self, request, *, timeout_seconds=10.0, verify_tls=False):
        body = request.body.text if request.body else ""
        if "admin123" in body or "root" in body or "$ne" in body:
            return _snap(500, '{"code":1,"msg":"系统错误"}')
        return _snap(200, '{"code":0,"msg":"ok"}')


def _build():
    """装配完整 traffic mcp(5 工具),注入 FakeTransport。"""
    # 内存 store + 假 transport(不发真 HTTP)
    store = AuditStore()
    # 灌一条原始流量(模拟 login)到 history 表(page dump 格式:headers list,body HttpBody dict)
    import json as _json
    from urllib.parse import urlsplit as _us
    _u = "https://demo.test/login"
    _p = _us(_u)
    req_json = {
        "method": "POST", "url": _u,
        "headers": [{"name": "Content-Type", "value": "application/json"},
                    {"name": "Cookie", "value": "role=admin"}],
        "body": {"text": '{"username":"admin","password":"x","code":"1234"}',
                 "content_type": "application/json"},
    }
    resp_json = {
        "status": 200, "reason": "", "headers": [],
        "body": {"text": '{"code":0,"msg":"ok"}', "content_type": "application/json"},
    }
    with store._connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO history (exchange_id, method, url, host, "
            "path, request_json, response_json, status_code) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("login_1", "POST", _u, (_p.hostname or "").lower(),
             _p.path or "/", _json.dumps(req_json, ensure_ascii=False),
             _json.dumps(resp_json, ensure_ascii=False), 200),
        )
        conn.commit()
    replay = ReplayService(store, transport=FakeTransport(), allow_mutating=True, baseline_repeats=1)
    q = QueryService(store)
    p = ReportService(store)
    disp = DispatchService(store)
    state = RunState()
    server = build_traffic_mcp_server(q, replay, p, disp, state)
    return server, state


_PROMPT = """你是安全测试 agent,正在测试一套刚开发的 traffic MCP 重放工具。这是一条模拟登录流量 history:1。

你的任务:依次实际调用全部重放工具,做常规的数据包编辑与重放(不要求出洞,只测工具体感):

1. traffic_get(traffic_id=history:1, raw=true):看完整 http_raw 明文(repeater 抄 find 从这)
2. traffic_repeater:用 find/replace 改 username 的值(find="admin",replace="admin123"——抄明文里那段),重放看响应;要对照 diff 调 traffic_diff(baseline_id=history:1, candidate_id=repeater:N)
3. traffic_repeater:改 cookie 的 role(find="role=admin",replace="role=user")
4. traffic_send:从零构造一个 GET 请求(scheme+host+path+query+body{kind,value})
5. traffic_brute:对 username 用值表 ["admin","root","test"] 爆破(find="admin")
6. 最后用 verify_report 提交 inconclusive 结论(只是收尾,不需要真发现漏洞)

**重点**:这是工具体感测试。做完后,用文字详细反馈:
- find/replace 好用吗?多处命中护栏报错加长 find 顺手吗?
- 哪个工具不好用?为什么?
- diff(status/body/time)够用吗?要不要更多维度?语义判断够你读 response 判吗?
- 有没有想改但 find 找不到/匹配不上的情况?
- brute 扫值表顺不顺?find 带键自动保键只换值清楚吗?

工具清单:traffic_get / traffic_search / traffic_repeater / traffic_send / traffic_brute / traffic_diff / verify_report

流量 id 是 history:1。开始吧,一步步实际调用,每步简述结果。"""


async def main() -> int:
    server, state = _build()
    options = ClaudeAgentOptions(
        model=MODEL,
        mcp_servers={"traffic": server},
        strict_mcp_config=True,
        tools=[],
        allowed_tools=list(TRAFFIC_TOOL_NAMES),
        max_turns=40,
        system_prompt="你是安全测试 agent。实际调用工具,每步简述结果,最后详细反馈工具体感。",
        hooks={"Stop": [HookMatcher(hooks=[make_stop_hook(state)])]},
        permission_mode="bypassPermissions",
        setting_sources=[],
        include_partial_messages=True,
    )

    print(f"[test] 模型: {MODEL}")
    print(f"[test] 工具: {len(TRAFFIC_TOOL_NAMES)} 个")
    print("[test] 流量: login_1 (模拟 login,FakeTransport 拦截,不真打站点)")
    print("=" * 70)

    tool_calls: list[str] = []
    feedback_text: list[str] = []
    async with ClaudeSDKClient(options=options) as client:
        await client.query(_PROMPT)
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, ToolUseBlock):
                        args = json.dumps(block.input, ensure_ascii=False)
                        if len(args) > 150:
                            args = args[:150] + "..."
                        print(f"  → {block.name}({args})")
                        tool_calls.append(block.name)
                    elif isinstance(block, TextBlock) and block.text.strip():
                        preview = block.text.strip()
                        if len(preview) > 200:
                            preview = preview[:200] + "..."
                        print(f"  [text] {preview}")
                        feedback_text.append(block.text)
            elif isinstance(message, SystemMessage):
                if message.subtype == "stop" and message.data.get("stop_hook_active"):
                    print("  [stop_hook] 门禁触发,强制续跑")
                elif message.subtype == "init":
                    print(f"  [init] tools={len(message.data.get('tools', []))}")
            elif isinstance(message, ResultMessage):
                print(f"  [result] stop_reason={message.stop_reason} cost=${message.total_cost_usd:.4f}")
            content = getattr(message, "content", None)
            if isinstance(content, (list, tuple)):
                for block in content:
                    if isinstance(block, ToolResultBlock):
                        status = "✗" if block.is_error else "✓"
                        c = block.content
                        preview = ""
                        if isinstance(c, list):
                            for item in c:
                                if isinstance(item, dict) and item.get("type") == "text":
                                    preview = item.get("text", "")[:120]
                                    break
                        elif isinstance(c, str):
                            preview = c[:120]
                        print(f"  {status} result: {preview}")

    print("=" * 70)
    print("[test] 工具调用次数统计:")
    from collections import Counter
    for name, cnt in Counter(tool_calls).most_common():
        print(f"  {name}: {cnt}")
    print(f"[test] 总调用 {len(tool_calls)} 次,涉及 {len(set(tool_calls))} 个工具")
    print(f"[test] state: replays={len(state.replays)} report={'已提交' if state.report else '未提交'}")

    # 反馈完整输出
    print("\n" + "=" * 70)
    print("[test] 模型反馈全文:")
    print("=" * 70)
    print("\n".join(feedback_text))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
