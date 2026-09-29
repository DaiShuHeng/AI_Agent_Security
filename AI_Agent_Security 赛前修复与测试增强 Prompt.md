# AI_Agent_Security 赛前修复与测试增强 Prompt

你现在正在维护项目：

```text
DaiShuHeng/AI_Agent_Security
```

这是“中国电子杯”赛题 9：

**智能体驱动的 AI 安全知识情报系统**

当前项目已经可以运行，已有较完整功能，包括：

- AI 安全漏洞情报采集
- NVD / OSV / CISA KEV / GitHub Advisory 等连接器
- SQLite + FTS5
- 漏洞归一化
- CVE / GHSA 关联
- 版本影响判断
- 本地资产匹配
- Agent 问答
- GLM-5.3 可选增强
- RAG / 证据引用
- Agent 安全自检
- Web Dashboard
- 运行轨迹
- Prometheus Metrics
- 84 个单元测试

项目启动命令：

```bash
python3 -m app.server --no-scheduler
```

浏览器：

```text
http://127.0.0.1:8765
```

---

# 一、最重要原则

这次任务不是重新设计项目，也不是重写架构。

你的目标是：

> 在不破坏现有功能的前提下，修复当前已经发现的问题，并建立真正覆盖 HTTP API 和浏览器端的自动化测试体系。

严格遵守：

1. 不要大规模重构。
2. 不要替换现有技术栈。
3. 不要把原生 Python HTTP Server 改成 FastAPI/Flask，除非发现当前架构无法解决明确问题。
4. 不要重写数据库。
5. 不要重写 QA Agent。
6. 不要删除当前已有测试。
7. 不要为了“代码更优雅”修改与本任务无关的文件。
8. 所有改动必须有回归测试。
9. 修改前先确认问题能够复现。
10. 修改后必须运行完整测试。
11. 当前已有功能优先于架构“高级感”。
12. 禁止修改测试来掩盖 Bug。
13. 禁止通过删除失败测试让 CI 变绿。
14. 禁止把开发测试结果宣传成官方比赛准确率。
15. 所有修改保持现有安全边界。

---

# 二、第一步：先检查当前仓库状态

首先不要改代码。

执行：

```bash
git status
git log -1 --oneline
python3 --version
```

然后运行：

```bash
python3 -m compileall -q app scripts tests
python3 -m unittest discover -s tests -v
python3 scripts/evaluate.py --json
```

记录：

```text
1. unittest 总数
2. unittest 通过数量
3. evaluate.py 是否通过
4. evaluate.py 失败项目
5. 当前 CI 对应问题
```

已知此前 GitHub CI 情况为：

```text
84 tests
OK
```

但：

```bash
python scripts/evaluate.py --json
```

返回退出码：

```text
1
```

请先独立验证，不要直接相信旧结论。

---

# 三、P0：修复 Agent Concept Router 抢占证据检索的问题

重点检查：

```text
app/concepts.py
app/qa.py
data/eval_gold.json
tests/test_answer_modes.py
tests/test_qa_quality.py
```

已知高风险问题：

问题：

```text
AgentDojo 相关的提示词注入论文是什么？
```

本应属于：

```text
paper / knowledge retrieval
```

应该检索本地：

```text
AgentDojo
arXiv
提示词注入论文
```

但当前 Concept Router 可能因为同时识别到：

```text
提示词注入
+
是什么
```

而错误进入：

```text
_answer_concept()
```

在 CI 没有配置 GLM 时可能最终拒答。

---

# 四、正确路由原则

建立明确的路由优先级。

具体证据查询必须高于通用概念解释。

推荐原则：

```text
Explicit CVE / GHSA
        ↓
具体产品 / 版本
        ↓
论文 / 标准 / 政策 / 公告 / 报告 / 来源查询
        ↓
具体安全情报查询
        ↓
纯概念解释
```

也就是说：

下面的问题不能仅因为存在“是什么”就被 Concept Router 抢走：

```text
AgentDojo 的论文是什么？
ISO/IEC 42001 是什么标准？
这篇安全报告是什么？
某厂商公告是什么？
这项政策是什么？
某论文研究了什么？
```

而：

```text
提示词注入是什么？
什么是 AI 安全？
CVSS 是什么意思？
RAG 有什么安全风险？
```

才适合进入 Concept Router。

---

# 五、修复方式要求

优先采用：

> evidence-seeking intent 优先于 concept intent

不要简单堆很多 if/else 后让路由越来越不可维护。

可以增加类似：

```text
evidence_intent
```

或：

```text
knowledge_intent
```

对：

```text
paper
standard
policy
report
advisory
source
citation
```

这类问题优先检索。

但要保持当前：

```text
concept_question()
```

职责清晰。

如果只需要小改即可解决，不要重新实现 Router。

---

# 六、必须新增 Concept Router 回归测试

至少增加：

```python
def test_paper_question_is_not_hijacked_by_concept_router(self):
    answer = self.qa.ask(
        "AgentDojo 相关的提示词注入论文是什么？"
    )

    self.assertFalse(answer["abstained"])

    self.assertIn("AgentDojo", answer["answer"])

    self.assertTrue(
        any(
            citation["source_id"] == "arxiv"
            for citation in answer["citations"]
        )
    )
```

还应增加至少以下几组边界：

## 应进入 Concept

```text
提示词注入是什么？
AI 安全是什么？
CVSS 是什么意思？
```

## 不应进入 Concept

```text
AgentDojo 相关的提示词注入论文是什么？
有哪些关于提示词注入的论文？
ISO/IEC 42001 是什么标准？
有哪些 AI 安全政策？
CVE-2099-99999 是什么？
最新提示词注入事件有哪些？
```

最后要求：

```bash
python3 scripts/evaluate.py --json
```

重新恢复全部通过。

---

# 七、P1：修复 POST /api/assets 缺字段返回 500

检查：

```text
app/db.py
app/server.py
```

当前类似：

```python
name = str(asset["name"]).strip()
product = str(asset["product"]).strip().lower()
version = str(asset["version"]).strip()
```

如果用户 POST：

```json
{
  "name": "test"
}
```

可能抛：

```text
KeyError
```

然后服务器进入：

```text
HTTP 500
```

这是错误行为。

应该返回：

```text
HTTP 400
```

例如：

```json
{
  "error": "资产名称、产品与版本不能为空"
}
```

---

# 八、资产参数校验要求

至少验证：

```text
name
product
version
criticality
exposure
owner
```

要求：

### name

不能为空。

### product

不能为空。

### version

不能为空。

### criticality

只能：

```text
1–5
```

### exposure

只能：

```text
internet
internal
isolated
```

未知额外字段可以忽略，不需要为了这个任务设计复杂 Schema。

---

# 九、P1：建立真正的 HTTP API Integration Test

这是本轮非常重要的任务。

目前已有大量：

```text
函数级 / 单元测试
```

但还需要：

```text
真实 HTTP Server
↓
HTTP 请求
↓
路由
↓
数据库
↓
AnswerEngine
↓
JSON Response
```

这一整条路径。

新增：

```text
tests/test_api.py
```

测试过程中：

1. 使用临时 SQLite 数据库。
2. 使用随机空闲端口。
3. 在后台线程启动 `ThreadingHTTPServer`。
4. 测试完成后正确 shutdown。
5. 不访问真实互联网。
6. 不依赖 API Key。
7. 不污染项目默认数据库。
8. 不残留后台线程。

---

# 十、HTTP API 至少覆盖以下测试

## 基础 GET

```text
GET /
GET /index.html
GET /api/health
GET /api/dashboard
GET /api/documents
GET /api/vulnerabilities
GET /api/sources
GET /api/runs
GET /api/assets
GET /api/security-selfcheck
GET /metrics
```

---

## 漏洞详情

测试：

```text
GET /api/vulnerabilities/CVE-2024-37032
```

要求：

```text
200
documents 非空
claims 非空
```

测试不存在：

```text
GET /api/vulnerabilities/CVE-2099-99999
```

要求：

```text
404
```

---

## ASK

正常：

```http
POST /api/ask
Content-Type: application/json
```

Body：

```json
{
  "question": "CVE-2024-37032 的修复版本是什么？"
}
```

要求：

```text
HTTP 200
abstained = false
citations 非空
```

未知 CVE：

```json
{
  "question": "CVE-2099-99999 的修复版本是什么？"
}
```

要求：

```text
200
abstained = true
citations = []
```

空问题：

```json
{
  "question": ""
}
```

要求：

```text
400
```

---

# 十一、测试 HTTP 非法输入

必须覆盖：

## 无 Content-Type

```text
POST
```

但不带：

```text
Content-Type: application/json
```

要求：

```text
400
```

---

## 非法 JSON

例如：

```text
{bad json
```

要求：

```text
400
```

---

## JSON Array

例如：

```json
[]
```

要求：

```text
400
```

---

## 请求体超过 1 MB

要求：

```text
400
```

而不是服务器崩溃。

---

## Cross Origin POST

模拟：

```text
Origin: http://evil.example
Host: 127.0.0.1
```

要求：

```text
400
```

---

# 十二、测试静态文件安全

测试：

```text
/../../etc/passwd
```

或 URL 编码后的路径穿越。

要求：

```text
404
```

且不能读取项目目录外文件。

---

# 十三、P1：修复 Live Collection 的 queued 状态语义

当前：

```text
POST /api/collect
mode=live
```

后端启动线程后马上返回：

```text
202 queued
```

这是合理方向。

但存在两个问题：

## 问题 1

如果 Pipeline 已经有采集任务：

当前可能：

```text
HTTP 先返回 queued
↓
后台线程才发现已有任务
↓
后台失败
```

这会误导用户。

---

## 问题 2

前端收到 queued 后：

只在：

```text
3 秒
12 秒
```

刷新。

之后便恢复按钮。

如果实际任务需要：

```text
40 秒
```

页面不会实时显示最终状态。

---

# 十四、Live Collection 修改目标

不要求引入 Celery、Redis、RabbitMQ。

保持简单。

推荐：

在真正启动后台线程之前，先判断：

```text
Pipeline 是否正在运行
```

不要让：

```text
202 queued
```

表示一个实际上根本不会运行的任务。

---

# 十五、推荐增加 Pipeline 状态接口

可以给 Pipeline 增加最小状态，例如：

```python
is_running()
```

或者：

```text
current_run_id
```

返回：

```json
{
  "running": true,
  "run_id": 123
}
```

不要暴露线程对象。

---

# 十六、POST /api/collect 推荐行为

空闲时：

```text
POST /api/collect
```

返回：

```http
202
```

例如：

```json
{
  "status": "queued",
  "run_id": 12
}
```

如果已有任务：

优先返回：

```text
409
```

例如：

```json
{
  "error": "已有采集任务正在运行"
}
```

而不是创建一个必然失败的后台线程。

---

# 十七、前端采集状态优化

检查：

```text
web/app.js
```

不要固定：

```text
3 秒
12 秒
```

之后就结束。

应该采用有上限的 polling。

例如：

```text
开始采集
↓
按钮 disabled
↓
每 2–3 秒读取 /api/runs
↓
running
↓
running
↓
success / partial / failed
↓
刷新 dashboard
↓
重新启用按钮
```

设置最大轮询时间，例如：

```text
60–120 秒
```

超时后明确提示：

```text
后台任务可能仍在继续，请前往运行与轨迹页面查看。
```

不要永久轮询。

---

# 十八、前端必须正确展示状态

至少区分：

```text
queued
running
success
partial
failed
```

不要把：

```text
queued
```

展示成：

```text
采集成功
```

---

# 十九、补充 Live Collect API 测试

必须测试：

```text
第一次 live collect
→ 202
```

立即再次请求：

```text
第二次 live collect
→ 409
```

不要真正访问互联网。

通过 Mock：

```text
pipeline.run_live
```

或可控的阻塞 fixture 模拟运行中状态。

---

# 二十、P1：增加 Server Smoke Test

测试真实服务启动。

至少验证：

```text
server thread 能启动
↓
GET /api/health
↓
200
↓
shutdown
↓
线程退出
```

确保：

```text
python3 -m app.server --no-scheduler
```

的核心 Server 逻辑不是只靠静态代码推断。

---

# 二十一、P2：增加浏览器 E2E

如果当前环境允许安装 Playwright，则增加：

```text
tests/e2e/
```

或：

```text
tests/test_e2e.py
```

但：

> 如果增加 Playwright 会大幅增加项目复杂度或导致离线环境难以运行，不要把它设为默认 unittest 强制依赖。

可以设置单独的：

```text
E2E workflow
```

---

# 二十二、浏览器 E2E 最少流程

启动：

```text
python3 -m app.server --no-scheduler
```

然后浏览器访问：

```text
/
```

测试：

```text
首页加载
↓
Dashboard 数据出现
↓
切换“漏洞情报”
↓
看到 CVE 卡片
↓
点击 CVE-2024-37032
↓
侧边栏显示漏洞详情
↓
切换 Agent 页面
↓
输入：
CVE-2024-37032 的修复版本是什么？
↓
收到回答
↓
引用出现
↓
点击“新建会话”
↓
Session 被清空
```

还可以验证：

```text
控制台无 JS Error
```

---

# 二十三、P2：改进 GitHub Actions

检查：

```text
.github/workflows/ci.yml
```

保留：

```bash
python -m compileall -q app scripts tests
python -m unittest discover -s tests -v
python scripts/evaluate.py --json
```

新增：

```bash
node --check web/app.js
```

如果环境中 Node 可用。

---

# 二十四、CI 必须保存 evaluate 结果

当前：

```bash
python scripts/evaluate.py --json > /tmp/zhidun-evaluation.json
```

如果失败，输出被重定向后 CI 日志几乎看不到为什么失败。

请改进。

目标：

即使 evaluate 返回失败：

CI 日志仍然可以看到：

```text
failed_ids
具体失败题目
```

例如：

```bash
python scripts/evaluate.py --json | tee /tmp/zhidun-evaluation.json
```

注意：

必须保持正确的 exit code。

不要因为 `tee` 导致失败被吞掉。

在 bash 中可使用：

```bash
set -o pipefail
```

---

# 二十五、CI 可选增加 Docker Build

如果成本很低：

```bash
docker build -t zhidun-test .
```

用于验证 Dockerfile 至少能够构建。

但：

不要在 CI 里进行真实公网采集。

---

# 二十六、GitHub Advisory 403

检查：

```text
app/connectors.py
config/sources.json
README.md
```

确认：

```text
GITHUB_TOKEN
```

配置方式正确。

不要硬编码 Token。

不要把 Token 写进：

```text
README
config
Git
log
```

如果没有 Token：

允许：

```text
GitHub Advisory 返回 403
```

但：

1. 页面必须诚实显示失败。
2. 不能算作 healthy。
3. 不应该导致其他来源停止采集。
4. OSV 可作为补充来源，但不要声称完全替代 GitHub Advisory。

---

# 二十七、CISA RSS 403

不要为了让页面全绿而伪造成功。

如果：

```text
CISA CERT RSS
```

持续不可用：

可以：

```text
保留但标记 unavailable
```

或者：

```text
换成稳定公开官方来源
```

但必须：

- 合法
- HTTPS
- 与赛题相关
- 确实能采到数据

禁止写死假数据伪装在线采集。

---

# 二十八、Metrics API 测试

测试：

```text
GET /metrics
```

必须：

```text
HTTP 200
Content-Type text/plain
```

内容至少包含：

```text
zhidun_documents
zhidun_vulnerabilities
zhidun_claims
zhidun_sources_healthy
```

同时保证：

缺少 latency sample 时：

不能生成：

```text
NaN
```

或错误数据。

---

# 二十九、安全边界不得退化

本轮修改后必须保持以下测试全部正常。

## Prompt Injection

外部文档中的：

```text
Ignore previous instructions
```

仍然必须只作为：

```text
data
```

而不是：

```text
instruction
```

---

## URL

仍然拒绝：

```text
file://
javascript:
localhost
127.0.0.1
内网危险目标
```

如果这些链接属于需要执行访问的外部输入。

---

## XML

DTD / XXE 防护不能退化。

---

## Session

不同：

```text
session_id
```

不能互相泄漏上下文。

---

## LLM

API Key 不能进入：

```text
Prompt
Response
Log
Frontend
```

---

## Asset

私有资产不能发送给外部 LLM 进行 Evidence Synthesis。

---

# 三十、不要展示 Chain of Thought

当前：

```text
trace
```

应该表示：

```text
工具调用
证据关联
数据路径
```

例如：

```text
CVE
→ affects_product
→ Ollama
```

这是可以的。

但不要新增：

```text
模型私有推理过程
一步一步内部思维
```

UI 应继续展示可审计事件，而不是 Chain of Thought。

---

# 三十一、完整回归测试

完成修复后执行：

```bash
python3 -m compileall -q app scripts tests
python3 -m unittest discover -s tests -v
python3 scripts/evaluate.py --json
node --check web/app.js
```

如果有 API 测试：

必须包含在：

```bash
python3 -m unittest discover -s tests -v
```

中自动执行。

---

# 三十二、验收要求

最终必须做到：

```text
所有 unittest 通过
+
evaluate.py 通过
+
Concept Router 回归问题消失
+
HTTP API integration tests 通过
+
缺失资产字段返回 400
+
重复 live collect 不再假 queued
+
前端能跟踪 live collect 最终状态
+
GitHub CI 变绿
```

---

# 三十三、禁止通过以下方式解决

禁止：

```text
删除 B03
修改 B03 让它变简单
取消 evaluate 的失败退出码
在 CI 里加 || true
skip failing test
删除 Concept Router
关闭 Agent 功能
写死 AgentDojo 答案
写死 CVE 答案
为了 CI 绕过真实逻辑
```

必须修真正的业务逻辑。

---

# 三十四、最后生成修改报告

所有修改完成后输出：

# 《AI_Agent_Security 本轮整改报告》

包括：

## 1. 修改前状态

```text
commit
unittest
evaluate
CI
```

## 2. 本轮发现的问题

按照：

```text
P0
P1
P2
```

列出。

## 3. 每个问题的根因

不能只写：

```text
已修复
```

要说明：

```text
为什么会发生
```

## 4. 修改文件

例如：

```text
app/concepts.py
app/qa.py
app/db.py
app/server.py
web/app.js
tests/test_api.py
...
```

## 5. 新增测试

逐项列出。

## 6. 测试结果

必须给出真实结果：

```text
xx tests passed
evaluate xx/xx passed
```

## 7. 未解决问题

例如：

```text
GitHub API 网络限制
真实在线来源稳定性
独立问答准确率评测
高并发
```

不要隐藏。

## 8. 是否建议比赛现场使用

分别判断：

```text
离线 Demo
在线采集
GLM 模型
Docker
```

哪些已经适合现场演示。

---

# 三十五、执行策略

请按以下顺序执行：

```text
Step 1
复现当前失败

↓

Step 2
修 Concept Router

↓

Step 3
让 evaluate.py 恢复全绿

↓

Step 4
修 /api/assets 400/500

↓

Step 5
新增 HTTP API Integration Test

↓

Step 6
修 live collection queued 状态

↓

Step 7
修改前端 polling

↓

Step 8
补相关测试

↓

Step 9
改 CI 输出

↓

Step 10
跑完整回归

↓

Step 11
输出整改报告
```

不要一开始同时修改所有模块。

每解决一个问题：

```text
修改
→ 测试
→ 确认没有回归
→ 再进行下一项
```

---

# 最终目标

不是增加更多代码。

最终目标是让当前项目从：

```text
“功能很多、单测很多的比赛原型”
```

提升为：

```text
“CI 全绿、API 可验证、Agent 路由稳定、
前后端闭环有自动化测试、比赛现场不容易翻车的系统”
```

现在请从：

```text
Step 1：复现当前 GitHub CI / evaluate.py 失败
```

开始。

先分析和复现。

在确认根因之前，不要大规模修改代码。