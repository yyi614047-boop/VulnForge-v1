# VulnForge

**面向本地靶场的漏洞复现实验平台** · Python 3.11+ / LangGraph / Docker Compose

给定一个漏洞编号（CVE），VulnForge 将环境准备、任务执行和证据验证串成一次实验。读者可以从报告中的结论回到当时的工具输出，查看判断依据。

## 🚀 最小运行示例

### 准备

安装 Python 3.11+、Docker 和 Docker Compose，并准备本机 Vulhub 仓库、可用的 Metasploit RPC 容器和模型服务。然后安装项目依赖：

```shell
python -m pip install -e ".[metasploit]"
cp .env.example .env
```

按 `.env.example` 填写本机配置。模型 API 密钥、Metasploit RPC 密码等敏感信息只保存在本机 `.env` 中，不要提交到仓库。下面的 `/path/to/vulhub` 请替换为实际的 Vulhub 根目录。

### 运行一个 CVE

以 ActiveMQ 的 `CVE-2022-41678` 为例：

```shell
python -m app run --cve CVE-2022-41678 --lang zh
```

也可以在 `.env` 中设置 `VULNFORGE_VULHUB_ROOT`，直接运行：

```shell
python -m app run --cve CVE-2022-41678
```

命令会依次完成环境准备、资料整理、研究、计划、Metasploit 执行、必要的独立 Python PoC 回退，以及证据验证。真正执行漏洞利用前会显示授权信息；只在已授权的本地隔离靶场中继续。

运行结束后，查看终端输出的 `report.md` 和 `result.json` 路径。工具任务完成或创建 Session 不等于复现成功，最终结论以独立采集的证据为准。

### 批量运行 RCE CVE

Batch 入口为 `vulnforge-batch-rce`，也可以直接用 `python -m app.batch` 调用。它从 Vulhub 的 `environments.toml` 中发现标记为 `RCE` 且包含 CVE 的环境，默认只预览，不执行。

先预览将要运行的 CVE：

```shell
python -m app.batch --vulhub-root /path/to/vulhub --dry-run
```

只预览一个指定 CVE：

```shell
python -m app.batch --vulhub-root /path/to/vulhub --cve CVE-2022-41678 --dry-run
```

确认列表后，添加 `--execute` 逐个运行：

```shell
python -m app.batch --vulhub-root /path/to/vulhub \
  --cve CVE-2022-41678 \
  --execute
```

每个目标都会单独请求授权，并按顺序执行。如需运行多个 CVE，可重复传入 `--cve`，但每个编号都必须是本机 Vulhub 清单中实际存在且标记为 RCE 的环境。默认在首个目标失败后继续后续目标；如需失败即停止，可添加 `--stop-on-error`；如需限制数量，可添加 `--limit 2`。

如果只想确认 Python 入口和参数可用，不启动容器或执行实验：

```shell
python -m app --help
python -m app.batch --help
```

## 🎯 当前复现重点与能力边界

**当前重点是优先使用 Metasploit 完成本地 Vulhub 复现。** 工作流会优先寻找精确引用目标 CVE 的 exploit 模块，尽量使用模块默认配置，只在缺少必要参数时补充配置，并把技术兼容性判断交给 Metasploit 本身。目标地址、端口和执行授权属于安全边界，不允许模型或脚本任意覆盖。

没有候选模块、模块执行失败或不支持当前目标时，工作流会尝试进入独立 Python PoC 模式。该模式由模型生成完整脚本，经程序静态检查后在隔离容器中执行，并允许有限的“生成 → 运行 → 根据报错修改”循环。它是回退能力，不等价于已经准备好所有漏洞的可靠利用链。

以下情况可能导致复现失败或无法得出结论：

- **模块缺失或不适用**：公开模块未覆盖该 CVE、引用信息不准确、模块与目标版本或运行环境不兼容。
- **目标状态与文档不一致**：镜像版本、补丁状态、服务配置、启动参数或部署路径不同，导致默认参数与利用前提不成立。
- **脚本回退失败**：模型未能生成正确利用链，脚本被安全检查拒绝，或请求超时、载荷投递和回连未成功。自动修改次数有限，不保证修复所有问题。
- **证据采集能力不足**：目标没有产生可识别的命令输出、HTTP 特征、回调、文件或数据库变化。此时结论可能是“证据不足”或“暂不支持验证”，不能直接解释为漏洞不存在。
- **批次范围有限**：Batch 当前只发现清单中标记为 RCE 的 CVE；未标记、缺少环境文件或重复出现的条目可能被跳过。

遇到失败时，应先看 `failed_stage`、错误列表和 `report.md`，区分计划阻塞、模块执行失败、脚本失败和证据验证失败，再决定是否需要调整本地靶场或人工分析。

## 🧭 实验流程

1. **准备环境**。平台读取 Vulhub 提供的实验环境配置，用 Docker Compose 为本次实验启动相关服务。
2. **整理资料并制定计划**。不同的 Agent 分别负责阅读漏洞文档、整理研究资料和制定实验计划。LangGraph 负责安排这些步骤，并把上一步的结果交给下一步。
3. **执行并记录**。执行器通过 Metasploit 的远程调用接口（RPC）提交任务，跟踪任务状态，记录工具返回的结果和错误信息。
4. **检查证据**。验证模块把实际观察到的现象与预期结果对照，给出验证结论。工作流结束后，平台清理本次实验的环境。

## 🧰 现有能力

| 能力 | 在项目中的用途 |
| --- | --- |
| 管理实验环境 | 按任务创建 Docker Compose 项目和内部网络，采集指定服务的容器日志，结束时回收资源。 |
| 跟踪工具任务 | 记录任务编号、执行状态及错误信息，对比执行前后的会话列表，区分已有会话和本轮新增会话。 |
| 核对实验证据 | 验证规则涵盖会话、命令输出、HTTP 响应、外部回调、文件、数据库结果和状态变化。具体实验能得出什么结论，取决于该环境能采集到哪些证据。 |
| 保存运行记录 | 每次实验使用独立目录，分别保存供人阅读的报告和供程序分析的结果。 |

## ⚙️ 配置说明

`pyproject.toml` 声明 Python 版本（3.11 或更高）、项目依赖和可选依赖。`.env.example` 列出运行配置的字段；本地使用的实际值放在 `.env` 中。公开仓库只需提供示例，API 密钥和服务密码应留在本机。

| 配置项 | 含义 |
| --- | --- |
| 模型服务 | `VULNFORGE_MODEL` 指定模型名称，`VULNFORGE_MODEL_BASE_URL` 指定服务地址。优先读取 `VULNFORGE_MODEL_API_KEY`，缺省时读取 `OPENAI_API_KEY`。 |
| 模型请求 | `VULNFORGE_MODEL_TIMEOUT` 和 `VULNFORGE_MODEL_MAX_RETRIES` 分别控制请求超时和重试次数。 |
| 实验环境 | `VULNFORGE_VULHUB_ROOT` 指向本机的 Vulhub 环境目录。 |
| 工具连接 | `MSF_CONTAINER_NAME` 标识工具容器；`MSFRPC_*` 字段描述连接方式、地址、端口、认证信息和超时。 |
| 结果目录 | `VULNFORGE_RUNS_ROOT` 指定实验记录的保存位置，默认是 `runs/`。此项由运行时代码读取。 |

**哪些信息需要自己准备？** 模型名称和 API 地址向模型服务提供方确认，密钥填写在本机。靶场目录填写本机存放 Vulhub 的实际路径。工具连接使用自己的 RPC 用户名和密码，容器名及端口与本机部署保持一致。超时、重试次数和结果目录可先沿用示例或程序默认值。

## 📑 如何阅读结果

例如，安全工具可能显示“任务已完成”，但这只说明工具结束了运行。要判断漏洞是否复现，还要看目标服务有没有出现预期变化，例如 HTTP 响应中是否出现了实验要检查的内容。

验证模块区分四种情况：**成功、失败、证据不足、暂不支持验证**。因此，阅读一次实验时，可以先看结论，再回到对应的工具输出、服务日志或状态变化，了解这个结论是怎么得出的。

默认在 `runs/<运行编号>/` 下查看以下文件：

| 文件 | 什么时候看 |
| --- | --- |
| `report.md` | 先读这份中文或英文报告，了解本次实验的过程和结论。 |
| `result.json` | 需要查看结构化字段或用程序分析结果时读取。 |
| `evidence/evidence-bundle.json` | 有证据包时生成，用于核对支撑结论的具体记录。 |

## 源码导览

| 想了解的问题 | 代码位置 |
| --- | --- |
| 一次实验如何从准备环境走到验证结果？ | `app/workflow.py` |
| Docker 环境如何启动和清理？ | `app/targets/vulhub/runtime.py` |
| Agent 和工具执行器各负责什么？ | `app/agents/` · `app/agents/metasploit_executor.py` |
| 平台依据什么判断实验结果？ | `app/verification/engine.py` · `app/verification/rules/` |
| 这些组件的预期行为有哪些测试？ | `tests/` |
