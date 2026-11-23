# VulnForge 重构 Step 1：旧项目审计与规划

## 审计范围

审计对象为用户提供的 `yyi614047-boop/VulnForge`，本地旧仓库位于 `F:/codex-workspace/VulnForge`。审计时 HEAD 为 `33786e8dbdf555942d06259364e36485d99d3227`，工作树已有未提交改动。本文写入新重写目录 `F:/codex-workspace/VulnForge-v1`。结论基于静态阅读，未执行测试或 Docker 操作。

## 1. 当前架构及调用关系

- **入口：** `pyproject.toml` 将 console script 指向 `app.cli:main`，`app/__main__.py` 也导入该入口。`app/cli.py` 分发研究、规划、目标检查和运行等多种动作，超出 V1 的单一 run 命令。
- **工作流和状态：** `app/workflows/reproduction/graph.py::Pipeline` 构造 LangGraph StateGraph，编排 planner、deployer、Metasploit/reproducer、verifier、cleanup，支持多种执行顺序并处理计时、异常清理和报告。`state.py::PipelineState` 所有字段可选。`runtime/context.py::state_boundary` 声明节点读写字段，但状态也保存在 Pipeline 实例和 Executor 报告。
- **Agent 和模型：** `agents/researcher.py::Researcher`、`agents/planner.py::StructuredPlanner`、`vulhub_research.py`、`vulhub_spec.py` 负责资料和计划，另有 verifier router 和 recovery agent。`runtime/models.py::configured_model` 创建模型，`runtime/context.py` 提供隔离调用、结构化输出回退和 State 边界。
- **Vulhub/Docker：** `targets/vulhub/loader.py::VulhubTargetLoader` 唯一匹配本地 CVE 目录，读取 README/Compose 并记录来源摘要。`catalog.py::TargetCatalog` 转换配方。`environments/docker/manager.py::DockerLab` 管理 Compose、端点识别及网络检查。
- **Metasploit：** `discovery/metasploit.py::MetasploitDiscovery` 搜索并检查模块。`workflows/reproduction/metasploit.py::MetasploitCandidateRunner` 衔接运行。`execution/metasploit_rpc.py` 实现传输、客户端与执行适配器。Docker 网络接入和恢复位于 `DockerLab.prepare_metasploit_container`、`restore_metasploit_container`。
- **验证和报告：** 授权在 `domain/policies.py::ExecutionPolicy`、`domain/auto_policy.py`。确定性断言在 `execution/verifier.py::EvidenceVerifier`，采集器和其他策略在 `execution/verifiers.py`。执行与证据记录在 `execution/executor.py::StepExecutor`。轨迹由 `runtime/tracing.py::TraceRecorder` 写入，Pipeline 原子写 JSON，`runtime/reporting.py::write_run_summary` 写 Markdown。

## 2. 应保留的能力行为

保留行为契约，不要求原样复用实现。

- **Metasploit RPC：** 鉴权、容器内传输、消息编码、模块/参数绑定、作业完成判断、超时处置和错误追踪。审阅 `app/execution/metasploit_rpc.py`，既有回归覆盖在 `tests/test_metasploit_rpc.py`。
- **Metasploit 容器：** 网络切换前检查容器运行状态、网络和 RPC 端口发布情况，调整后等待监听就绪，运行结束恢复网络。`prepare_metasploit_container` 假设容器已经运行，可能重启它，静态代码未发现创建容器的流程。需要明确容器归属。
- **Vulhub 目标：** 保留 `VulhubTargetLoader.resolve_cve/context` 的唯一匹配、路径限制、资料预算和来源摘要，以及 Compose、端口和网络校验。
- **安全授权：** 保留 `ExecutionPolicy` 对目标范围、资料/候选绑定、参数及动作预算的检查。模型输出与本地资料不得自行授予权限。
- **日志与证据：** 保留运行 ID、事件顺序、凭据脱敏、原子结果写入、清理错误记录。验证结论须引用目标侧且关联本次运行的独立证据。

## 3. 重写或删除建议

| 建议 | 依据及可能影响 |
| --- | --- |
| 收敛 `app/cli.py` | 多动作和多种运行模式超过 V1。旧 CLI 脚本需迁移；保留双语、阶段进度、执行前确认及运行后环境选择。 |
| 合并 Agent 调用封装 | `runtime/context.py` 同时承担隔离历史、结构化输出回退和节点边界。移除前搜索 `current_agent_context` 调用方；保留显式输入、schema 校验和调用错误记录。 |
| 精简 PipelineState 与报告写入 | LangGraph、Pipeline、Executor 报告重复记录状态，异常时可能不一致。旧报告消费者需迁移；每字段指定唯一写入方。 |
| 删除 Recovery 和旧 reproducer 路由 | `agents/recovery.py`、`execution/recovery.py` 与图路由服务于 V1 不需要的重试/替代路径。相关测试和配置失效；保留取消处理、失败报告和安全清理。 |
| 删除 LLM Verifier 和额外验证策略 | `VerifierRouter`、广泛的 `verifiers.py` 策略超出 V1 两类 RCE 证据。旧策略消费者需迁移；保留独立采证、证据归属检查、固定规则和缺证判定。 |
| 合并配置并收缩工具注册层 | 模型、RPC、discovery 分别读取配置。`ToolRegistry`/文件工具需先检查调用点；保留路径约束、凭据隔离、超时和参数验证。 |
| 简化目标和配方模型 | `TargetSpec`、`ReproductionSpec`、`TargetCatalog` 和 planner 输入准备有交叠。旧配方需迁移；保留目标识别、来源摘要和执行前检查。 |

## 4. 建议的新目录

```text
app/
  cli.py
  agents/       # AgentRunner 与四类 Agent
  workflow.py   # LangGraph 与共享状态
  runtime/      # 配置、运行上下文、事件和报告
  target/       # Vulhub、Compose、目标识别
  metasploit/   # 容器、RPC、模块操作
  verification.py
tests/
  unit/
  integration/
docs/refactor/
```

Agent 负责模型输入输出；Workflow 负责阶段和状态；Runtime 负责运行事件与产物；Target 负责本地资料和 Compose；Metasploit 封装容器及 RPC；Verification 按固定规则评估证据。只在出现明确复用时引入额外抽象。

## 5. 分阶段重构

1. 固定安全契约和离线测试基线，先明确 Metasploit 容器归属。
2. 定义最小 PipelineState、单次运行上下文和 Agent schemas，接入本地资料处理。
3. 迁移目标定位、Compose 校验、部署和目标端点识别，用 Docker runner 替身覆盖失败路径。
4. 迁移 Metasploit 网络/RPC 行为和执行前确认，接入预先固定的确定性验证。
5. 完成双语 CLI、阶段与实时事件、目标环境选择及四类运行产物，再删除新路径不再调用的旧代码。

## 6. 风险、测试与验收

### 风险

- RPC 依赖已运行的容器、容器内 Ruby 和 listener。端口可连通不代表认证与协议可用；重启共享容器会影响其他使用方。
- 容器名或 Compose project 名不足以证明资源归属。清理前后应核对容器 ID、labels、网络身份和本次运行记录。
- job 完成、session、命令输出和漏洞成立是不同事实。旧 session、跨运行输出或无目标关联证据不可判成功。
- State 在图、Pipeline 和 Executor 间重复存储，可能产生覆盖和遗漏。
- `tests/test_docker_isolation_integration.py`、`test_metasploit_live_integration.py`、`test_real_cve_e2e.py` 有条件跳过。本次没有运行这些测试。

### 测试策略

RPC 单测覆盖认证、协议、方法/参数限制、脱敏、错误、超时作业处置和结果归属。Docker 替身测试覆盖容器身份、网络、RPC 端口、部分准备失败、并发、保留环境和清理错误。Target 单测覆盖重复/缺失 CVE、越界路径、符号链接和 Compose 约束。验证单测覆盖目标与 run ID 绑定、旧/跨运行证据、空输出、缺失关联及规则冻结。Workflow/CLI 测试覆盖阶段门控、状态所有权、拒绝确认后无副作用、中断清理和双语。集成测试须显式启用，在隔离本地环境使用无害目标或模拟服务。

### 验收条件

- 唯一入口为 `vulnforge run --cve CVE-...`，默认中文，`--lang en` 英文。
- Document Agent 处理本地 README 和可选本地图片；Research 不进行网络资料检索。
- 阶段显示进度，Execution 事件实时可见，执行前请求确认。
- 无适用模块返回 Unsupported，不生成 PoC、不使用其他攻击回退、不做 Retry/Replan/自动恢复。
- 验证规则执行前冻结，只接受目标与本次运行关联的两类 RCE 证据。
- 每次运行生成 `report.md`、`result.json`、`execution.log`、`evidence/`，并按用户选择关闭或保留目标。
- 失败、中断和部分清理只触及本次运行拥有的资源，结果准确记录清理状态。

## 7. Step 2 前需决策的问题

1. **Metasploit 容器归属：** 旧实现假定容器预先运行，网络调整时可能重启。请决定接入共享容器还是由 V1 管理专用容器，否则无法界定生命周期和安全清理。
2. **Research 离线范围：** `configured_model` 使用 OpenAI 兼容模型客户端。请决定离线要求是否只限制资料检索，还是也限制模型推理。若要求本地推理，需指定端点和模型。
