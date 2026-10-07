# AgentSuite

![python](https://img.shields.io/badge/python-3.11%2B-blue)

**将后台业务逻辑漏洞的检测,从 agent 注意力问题变成工程结构问题。**

业务逻辑漏洞没有特征码,是黑盒检测的主要盲区:

- **模板扫描器**——写不出规则
- **手工审查**——流量规模下必然遗漏
- **LLM 自由探索**——注意力主观抽样即终止,漏检不可见且无法量化

AgentSuite:

- 不靠注意力主观挑选,靠队列逐模块遍历至耗尽保证覆盖
- 不靠单一 agent 既发现又验证,靠发现与验证解耦、独立重放证明
- 每条结论附可追溯重放证据,端到端闭环到交付报告

## 核心特性

- 🎥 **登录态后台流量录制**——mitmproxy 被动录制鉴权后的真实业务请求(业务逻辑漏洞的主要承载面),而非爬虫够不到的公开表层。
- 🔁 **强制循环覆盖**——候选入池逐模块遍历至耗尽;agent 可判错单条,不可跳过单条。覆盖从概率问题转为确定性问题。
- 🧬 **clean 语义提取**——纯数据管线(零 LLM)把全量 HTTP 压成最小业务语义单元,有限 token 覆盖完整业务面。
- ⚖️ **发现与验证解耦**——dispatch 发现、verify 独立重放终审,强制每条发现都被重放证明。
- 📌 **证据可追溯**——每条 confirmed finding 附 source_id 链回源流量的重放证据。

## 适用场景

- **单站点全流量深度审计**——对单个 Web 站点录制登录态后台全量流量,逐接口遍历验证(非批量 URL 扫描)
- **业务逻辑漏洞挖掘**——越权、IDOR、参数篡改等无特征码漏洞,模板扫描器的盲区
- **漏洞 PoC 证据落地**——每条发现附可追溯重放证据,直接用于交付报告
- **LLM agent 安全研究**——发现/验证解耦、强制循环等 agent 工程化结构的实践样本

## 架构

```
record      mitmproxy 被动录制,全量流量落 traffic.sqlite
  ↓
clean       纯数据管线(无 LLM):噪音丢弃 → 去重归一 → 公共参数剥离 → 语义提取
            产出 clean.jsonl(最小业务语义单元)
  ↓
dispatch    读 clean + skill 路由表,按攻击面把流量捆成模块入可疑池
  ↓ ↓ ↓ ↓   (模块逐条入池,verify 即取即处理,流式并发)
verify      逐模块改包重放比对,confirmed / rejected / inconclusive,附 evidence(终审)
  ↓
report      读 confirmed findings + evidence,逐条写交付报告 .md
```

record 串行;dispatch 与 verify 流式并发;report 末段汇总。每次运行独立 session_dir,无全局数据库。

## 自动化流水线

启用 `as run` 后,单站点依次执行:

```
1. 浏览器挂代理 + 装 mitm CA → 人工操作目标站点(登录态后台)→ mitmproxy 被动录制全量流量
2. 按回车停录制 → clean 纯数据管线自动执行:噪音丢弃 → 去重归一 → 公共参数剥离 → 语义提取
3. dispatch 读 clean + skill 路由表,按攻击面捆模块入可疑池
4. verify 逐模块改包重放比对(模块入池即启动,与 dispatch 流式并发)→ confirmed/rejected/inconclusive + evidence
5. report 读 confirmed findings + evidence,逐条写交付报告 .md
```

## 核心机制

### 强制循环保证覆盖

覆盖不靠 agent 注意力,靠结构。clean 把全量流量切成最小业务语义单元,dispatch 按攻击面捆成模块入可疑池,verify 逐模块处理至池耗尽——队列空即覆盖完成。agent 可判错单条,但不可跳过单条。覆盖由此从概率问题转为确定性问题。

### clean 语义提取

clean 把全量 HTTP 压缩成最小业务语义单元——每个单元保留 `method` / `host` / `path`、query(剥离公共框架参数)、请求体原值、响应嵌套 key 结构(无值,只留结构)、status。原始 HTTP 体量大、超出上下文预算,压缩后 dispatch/verify 才能在有限 token 内覆盖完整业务面。公共参数剥离判键不判值,避免误剥资源标识符;跨域资源标识符保留,确保可测。

### 发现与验证解耦

dispatch(发现)、verify(验证)、report(报告)三段独立 agent,工具子集经 MCP server 硬门禁隔离:

| agent | 职责 | 工具(traffic MCP 子集) |
|------|------|------|
| **dispatch** | 读 clean,识别并分发可疑模块 | `traffic_get` / `dispatch_send`(无 Bash) |
| **verify** | 改包重放比对,下结论,落 evidence | `repeater` / `send` / `brute` / `diff` / `search` + Bash |
| **report** | 读 confirmed findings 写报告 | `traffic_get` / `diff` / `search`(无 Bash,只读) |

LLM agent 单次交互止步于发现,不做重放验证。解耦后 verify 以独立重放对每条怀疑作终审,发现必被证明,结论由独立重放证明。

### 证据落地

每条 confirmed finding 附重放证据(source_id 链回源流量,可复现)。report 只读 confirmed findings 生成报告,不臆造。

## 快速开始

**前置要求:**
- Python ≥ 3.11
- 一个 ANTHROPIC 兼容的 LLM API key

```bash
git clone https://github.com/Tfo0/AgentSuite.git
cd AgentSuite
python -m venv .venv && .venv/Scripts/activate      # Windows(.venv/bin/activate on unix)
pip install -e ".[dev]"
cp .env.example .env       # 填入 LLM key(见“配置”)
```

CLI 入口 `as`(console_script → `agentsuite.app.main:main`)。

> [!NOTE]
> 录制 HTTPS 流量需先信任 mitmproxy CA,见下方“装 mitmproxy CA 证书”。

### 装 mitmproxy CA 证书

录制 HTTPS 流量需先信任 mitmproxy 的 CA:

1. 启动 `as run -u https://example.com/login`,mitm 代理监听 `127.0.0.1:8082`
2. 浏览器挂代理到 `127.0.0.1:8082`
3. 访问 `http://mitm.it`,下载 mitmproxy 证书(`.cer` / `.pem`)
4. 导入“受信任的根证书颁发机构”:
   - **Windows**:双击 `.cer` → 安装证书 → 本地计算机 → 受信任的根证书颁发机构 → 完成
   - **macOS**:钥匙串访问导入 → 系统 → 设为始终信任
   - **Linux**:`certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n mitmproxy -i cert.cer`

## 用法

### `as run` —— 录制并验证

启动 mitm 录制;浏览器挂代理并装好 CA 后人工操作目标站点录制流量;回终端按回车停录制,自动执行 clean → dispatch → verify → report,输出 findings 概览并在 `report/` 下生成交付报告。

```bash
# 单目标(挂代理登录目标站点后操作后台,录登录态业务流量)
as run -u https://example.com/login
```

## 配置

后端为 claude-agent-sdk,读 `ANTHROPIC_*` 环境变量(`.env`,复制自 `.env.example`,已 gitignore):

| 变量 | 示例 | 说明 |
|------|------|------|
| `ANTHROPIC_BASE_URL` | `https://test.com/anthropic` | anthropic 兼容端点 |
| `ANTHROPIC_API_KEY` | `sk-******` | API key |

模型在各 agent 的 `src/agentsuite/agent/<role>/agent.yaml` 内 `model:` 字段配置(运行时覆盖 `.env`,优先级最高)。改模型直接编辑对应 `agent.yaml`。

## 输出

输出落 `project/sessions/<ts>-<host>/`(`project/` 已 gitignore):

```
session_dir/
  pipeline/proxy/traffic.sqlite    全量流量 + 重放证据
  pipeline/proxy/clean.jsonl       clean 产出(业务语义单元)
  pipeline/proxy/noise.jsonl       框架参数集(供 dispatch/verify prompt 使用)
  pipeline/agent/findings.jsonl    verify 终审 findings
  pipeline/history/                evidence 存储(重放 / 比对产物)
  report/                          交付报告(总览 + 每漏洞一份 .md)
```

## 安全与限制

> [!WARNING]
> **仅限授权使用。** 本工具重放真实流量、改包探测边界,可能产生真实副作用(下单 / 扣款 / 触发风控)。仅在已获书面授权的目标与隔离环境中使用;未经授权测试在多数司法辖区属违法,使用者自行承担全部法律责任。

- **凭据隔离**:仅从环境变量读,不进源码与日志。
- **工具授权**:`agent.yaml` 声明各 agent 的 mcp / allowed_tools / sdk_tools / max_turns / model;dispatch 与 report 禁 Bash,verify 开 Bash 执行 PoC。
- **职责隔离**:verify 终审(重放 + 结论 + evidence);report 只读 confirmed 生成报告。
- **增量落盘**:每个单元完成即写入,不等全部完成;CLI 实时输出中间结果。
