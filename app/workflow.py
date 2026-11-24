"""LangGraph orchestration for the single-run local Vulhub pipeline."""
from __future__ import annotations

import os
import re
import uuid
from threading import RLock
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from langgraph.graph import END, START, StateGraph

from app.agents.document import DocumentAgent
from app.agents.execution import ExecutionAgent, ExecutionAuthorizationRequest, ExecutionResult
from app.agents.metasploit_executor import MetasploitExecutor
from app.agents.metasploit_rpc import MetasploitRpc
from app.agents.module_catalog import MetasploitSearch
from app.agents.planner import PlannerAgent
from app.agents.research import ResearchAgent
from app.agents.runner import AgentRunner
from app.agents.script_agent import IsolatedPythonRunner, ScriptAgent
from app.runtime.config import RunContext, Settings
from app.runtime.model import create_model
from app.state import PipelineState
from app.targets.material import TargetMaterial
from app.targets.vulhub.config import VulhubSettings
from app.targets.vulhub.loader import load_target
from app.targets.vulhub.runtime import VulhubDockerRuntime
from app.verification.collector import EvidenceCollector
from app.verification.engine import VerificationEngine
from app.verification.http_collector import HttpResponseCollector
from app.verification.models import VerificationResult
from app.verification.oob_collector import OobCallbackCollector


EventSink = Callable[[dict], None]


class WorkflowConfigurationError(ValueError):
    pass


def _declared_tcp_ports(target: TargetMaterial, service: str) -> set[int]:
    services = target.attributes.get("compose", {}).get("services", {})
    config = services.get(service, {}) if isinstance(services, dict) else {}
    ports = set()
    for entry in config.get("ports", []) if isinstance(config, dict) else []:
        value = str(entry).rsplit(":", 1)[-1].split("/", 1)[0]
        if value.isdigit():
            ports.add(int(value))
    for entry in config.get("expose", []) if isinstance(config, dict) else []:
        value = str(entry).split("/", 1)[0]
        if value.isdigit():
            ports.add(int(value))
    return ports


def _select_target_port(*, target: TargetMaterial, service: str, document: str,
                       research) -> int:
    declared = _declared_tcp_ports(target, service)
    research_text = " ".join(
        list(research.prerequisites) + list(research.trigger_conditions)
        if hasattr(research, "prerequisites") else []
    )
    text = document + "\n" + research_text
    documented = {
        int(value) for value in re.findall(
            r"(?i)(?:https?://[^\s/`'\"]+|(?:localhost|your-ip|127\.0\.0\.1)):(\d{1,5})", text,
        )
    }
    documented.update(
        int(value) for value in re.findall(r"(?<!\d)(\d{1,5})\s*端口", text)
    )
    candidates = declared & documented
    if len(candidates) == 1:
        return next(iter(candidates))
    if not documented and len(declared) == 1:
        return next(iter(declared))
    details = ", ".join(str(port) for port in sorted(declared)) or "无"
    raise ValueError(
        "无法唯一确定目标端口，请在执行前明确服务端口。"
        f"Compose 声明端口：{details}；文档候选端口："
        + (", ".join(str(port) for port in sorted(candidates)) or "无")
        + " (Cannot bind one target port from the local material.)"
    )


class VulnForgeWorkflow:
    """A small dependency-injected graph; only data models enter PipelineState."""
    def __init__(self, *, target_root: Path, target_runtime, document_agent,
                 research_agent, planner_agent, execution_agent,
                 script_agent=None, evidence_collector=None, verification_engine=None,
                 http_response_collector=None, oob_callback_collector=None,
                 event_sink: EventSink | None = None, language: str = "zh",
                 run_context: RunContext | None = None):
        if language not in {"zh", "en"}:
            raise ValueError("language must be 'zh' or 'en'")
        self.target_root = target_root.resolve()
        self.target_runtime = target_runtime
        self.document_agent = document_agent
        self.research_agent = research_agent
        self.planner_agent = planner_agent
        self.execution_agent = execution_agent
        self.script_agent = script_agent
        self.verification_engine = verification_engine or VerificationEngine()
        self.http_response_collector = http_response_collector or HttpResponseCollector()
        self.oob_callback_collector = oob_callback_collector or OobCallbackCollector()
        self.run_context = run_context
        self.evidence_collector = evidence_collector or EvidenceCollector(
            run_context.evidence_dir if run_context else None
        )
        self.event_sink = event_sink or (lambda event: None)
        self.language = language
        self._authorization_callback = None
        self._run_lock = RLock()
        self.graph = self._compile()

    @classmethod
    def from_environment(cls, *, run_context: RunContext, event_sink=None, language="zh"):
        vulhub = VulhubSettings.from_environment()
        settings = Settings.from_environment()
        runner = AgentRunner(create_model(settings))
        container = os.getenv("MSF_CONTAINER_NAME", "vulnforge-metasploit").strip()
        if not container:
            container = "vulnforge-metasploit"
        sink = event_sink or (lambda event: None)
        execution = ExecutionAgent(
            MetasploitSearch.from_env(),
            MetasploitExecutor(MetasploitRpc.from_env()),
            runner=runner,
            event_sink=sink,
            evidence_dir=run_context.evidence_dir,
            max_attempts=1,
        )
        script = ScriptAgent(
            runner, IsolatedPythonRunner(), max_attempts=3, event_sink=sink,
            evidence_dir=run_context.evidence_dir,
        )
        return cls(
            target_root=vulhub.root,
            target_runtime=VulhubDockerRuntime(
                run_context.targets_dir, metasploit_container=container,
                rpc_user=os.getenv("MSFRPC_USER", "msf"),
                rpc_password=os.getenv("MSFRPC_PASS", ""),
                rpc_port=int(os.getenv("MSFRPC_CONTAINER_PORT", "55553")),
            ),
            document_agent=DocumentAgent(runner),
            research_agent=ResearchAgent(runner),
            planner_agent=PlannerAgent(runner),
            execution_agent=execution,
            script_agent=script,
            event_sink=sink, language=language,
            run_context=run_context,
        )

    def _event(self, kind: str, **fields):
        self.event_sink({"type": kind, "timestamp": datetime.now(timezone.utc).isoformat(), **fields})

    def _stage(self, name: str, operation):
        def node(state: PipelineState):
            self._event("stage_started", run_id=state["run_id"], stage=name)
            try:
                updates = operation(state)
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                self._event("stage_failed", run_id=state["run_id"], stage=name,
                            error_type=type(exc).__name__, error=str(exc))
                return {"status": "failed", "failed_stage": name,
                        "errors": [*state.get("errors", []), message]}
            terminal_status = updates.get("status", state.get("status", "running"))
            if name == "research" and updates.get("research_result"):
                research = updates["research_result"]
                self._event("research_summary", run_id=state["run_id"],
                            summary=research.model_dump(mode="json"))
            if name == "planner" and updates.get("reproduction_plan"):
                plan = updates["reproduction_plan"]
                self._event("plan_summary", run_id=state["run_id"],
                            summary=plan.model_dump(mode="json"))
            if updates.get("failed_stage"):
                self._event("stage_failed", run_id=state["run_id"], stage=name,
                            status=terminal_status, errors=updates.get("errors", []))
            else:
                details = {}
                if name == "execution" and updates.get("execution_result"):
                    details["execution_status"] = updates["execution_result"].status
                    details["execution_errors"] = list(updates["execution_result"].errors)
                self._event("stage_completed", run_id=state["run_id"], stage=name,
                            status=terminal_status, **details)
            return updates
        return node

    @staticmethod
    def _next(state: PipelineState, next_node: str):
        return next_node if state.get("status") == "running" else END

    def _compile(self):
        graph = StateGraph(PipelineState)

        def target_prepare(state):
            target = load_target(self.target_root, state["cve_id"])
            self._event("target_selected", run_id=state["run_id"], cve_id=state["cve_id"],
                        environment=str(target.environment))
            runtime_info = self.target_runtime.start(target=target, run_id=state["run_id"])
            self.target_runtime.prepare_metasploit(run_id=state["run_id"])
            return {"target": target, "runtime_target": runtime_info, "status": "running"}

        def document(state):
            material: TargetMaterial = state["target"]
            return {"document_markdown": self.document_agent.run(
                material, language=self.language, runtime_info=state.get("runtime_target"))}

        def research(state):
            result = self.research_agent.run(cve_id=state["cve_id"],
                                             document_markdown=state["document_markdown"],
                                             target=state["target"], language=self.language)
            return {"research_result": result}

        def planner(state):
            plan = self.planner_agent.run(cve_id=state["cve_id"], research=state["research_result"],
                                          target=state["target"],
                                          document_markdown=state["document_markdown"],
                                          language=self.language)
            if not plan.executable or plan.status != "ready":
                status = "unsupported" if plan.status == "unsupported" else "plan_blocked"
                return {"reproduction_plan": plan, "status": status,
                        "failed_stage": "plan_validation", "errors": list(plan.validation_errors)}
            try:
                port = _select_target_port(
                    target=state["target"], service=plan.target_service,
                    document=state["document_markdown"], research=plan.research_context,
                )
            except ValueError as exc:
                self._event("target_port_binding_failed", run_id=state["run_id"],
                            service=plan.target_service, error=str(exc))
                return {"reproduction_plan": plan, "status": "plan_blocked",
                        "failed_stage": "target_port_binding", "errors": [str(exc)]}
            baselines = {}
            inspector = getattr(self.target_runtime, "inspect_file_artifact", None)
            if plan.verification_contract and inspector:
                for expectation in plan.verification_contract.file_artifacts:
                    try:
                        baselines[expectation.path_pattern] = inspector(
                            run_id=state["run_id"], service=plan.target_service,
                            path_pattern=expectation.path_pattern)
                    except Exception as exc:
                        baselines[expectation.path_pattern] = {
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                        self._event("file_baseline_unavailable", run_id=state["run_id"],
                                    path_pattern=expectation.path_pattern,
                                    error_type=type(exc).__name__, error=str(exc))
            oob_binding = {}
            if plan.verification_contract and plan.verification_contract.oob_expectations:
                try:
                    oob_binding = self.oob_callback_collector.start(
                        run_id=state["run_id"],
                        network_name=state["runtime_target"]["network_name"],
                        expectation=plan.verification_contract.oob_expectations[0],
                    )
                    self._event("oob_collector_started", run_id=state["run_id"],
                                callback_url=oob_binding["callback_url"])
                except Exception as exc:
                    self._event("oob_collector_failed", run_id=state["run_id"],
                                error_type=type(exc).__name__, error=str(exc))
            target_binding = resolve_target(state, plan, port)
            self._event("target_bound", run_id=state["run_id"],
                        host=target_binding.host, port=target_binding.port)
            return {"reproduction_plan": plan, "target_binding": target_binding.model_dump(mode="json"),
                    "file_baselines": baselines, "oob_binding": oob_binding}

        def resolve_target(state, plan, port=None):
            resolved = self.target_runtime.resolve_target(
                run_id=state["run_id"], service=plan.target_service, port=port,
            )
            binding = state.get("oob_binding") or {}
            if binding:
                resolved = resolved.model_copy(update={
                    "oob_callback_host": binding["callback_host"],
                    "oob_callback_port": binding["callback_port"],
                    "oob_token": binding["token"],
                })
            return resolved

        def authorize(state, plan, runtime_state):
            def callback(request: ExecutionAuthorizationRequest):
                runtime_target = runtime_state.get("target")
                self._event("execution_authorization_requested", run_id=state["run_id"],
                            target_id=request.target_id, module_name=request.module_name,
                            configuration=request.configuration_summary,
                            verification_policy_id=request.verification_policy_id,
                            verification_contract=(plan.verification_contract.model_dump(mode="json")
                                                   if plan.verification_contract else None),
                            runtime_target=runtime_target.model_dump(mode="json") if runtime_target else {},
                            reproduction_plan=plan.model_dump(mode="json"))
                try:
                    grant = self._authorization_callback(request) if self._authorization_callback else None
                except Exception as exc:
                    self._event("execution_authorization_received", run_id=state["run_id"],
                                approved=False, error_type=type(exc).__name__, error=str(exc))
                    return None
                if grant is not None:
                    self._event("execution_authorization_received", run_id=state["run_id"],
                                approved=grant.approved,
                                request_matches=(grant.model_dump(exclude={"approved"})
                                                 == request.model_dump()))
                return grant
            return callback

        def execution(state):
            plan = state["reproduction_plan"]
            runtime_state = {}

            def resolver(port):
                binding = state["target_binding"]
                resolved = resolve_target(state, plan, binding["port"])
                runtime_state["target"] = resolved
                return resolved

            result = self.execution_agent.run(
                plan=plan, target=state["target"], target_resolver=resolver,
                run_id=state["run_id"], authorized=False,
                authorization_callback=authorize(state, plan, runtime_state),
                diagnostics_callback=lambda: (
                    self.target_runtime.collect_target_logs(
                        run_id=state["run_id"], service=plan.target_service)
                    if hasattr(self.target_runtime, "collect_target_logs") else {}
                ),
                file_artifact_inspector=(
                    lambda pattern: self.target_runtime.inspect_file_artifact(
                        run_id=state["run_id"], service=plan.target_service, path_pattern=pattern)
                ) if hasattr(self.target_runtime, "inspect_file_artifact") else None,
                document_markdown=state["document_markdown"],
            )
            runtime_target = runtime_state.get("target")
            updates = {"runtime_target": runtime_target.model_dump(mode="json") if runtime_target else result.target,
                       "execution_result": result, "status": "running"}
            if result.status == "rejected":
                return {**updates, "status": "execution_unauthorized", "failed_stage": "authorization",
                        "errors": list(result.errors)}
            return updates

        def script(state):
            if self.script_agent is None:
                return {"status": "execution_failed", "failed_stage": "metasploit_execution",
                        "errors": list(state["execution_result"].errors)}
            plan = state["reproduction_plan"]
            runtime_target = resolve_target(state, plan, state["target_binding"]["port"])
            self._event("script_target_bound", run_id=state["run_id"],
                        host=runtime_target.host, port=runtime_target.port)
            result = self.script_agent.run(
                plan=plan, target=state["target"], runtime_target=runtime_target,
                run_id=state["run_id"], document_markdown=state["document_markdown"],
                authorization_callback=authorize(state, plan, {"target": runtime_target}),
                work_dir=(self.run_context.run_dir if self.run_context else
                          Path("runs") / state["run_id"]),
            )
            updates = {"runtime_target": runtime_target.model_dump(mode="json"),
                       "execution_result": result, "script_result": result, "status": "running"}
            if result.status == "rejected":
                return {**updates, "status": "execution_unauthorized", "failed_stage": "authorization",
                        "errors": list(result.errors)}
            return updates

        def evidence(state):
            result = state["execution_result"]
            plan = state["reproduction_plan"]
            contract = plan.verification_contract
            if contract and contract.oob_expectations:
                expectation = contract.oob_expectations[0]
                oob_rows = self.oob_callback_collector.collect(
                    run_id=state["run_id"], execution=result, expectation=expectation,
                    target_host=result.target.get("host", ""),
                )
                result = result.model_copy(update={
                    "oob_callback_evidence": [*result.oob_callback_evidence, *oob_rows],
                })
                self.oob_callback_collector.stop(run_id=state["run_id"])
                self._event("oob_callback_collected", run_id=state["run_id"],
                            evidence_count=len(oob_rows))
            http_probes = tuple(contract.http_expectations) + tuple(
                item.probe for item in contract.database_results
            ) if contract else ()
            if http_probes:
                http_rows = self.http_response_collector.collect(result, http_probes)
                result = result.model_copy(update={
                    "http_response_evidence": [*result.http_response_evidence, *http_rows],
                })
                self._event("http_response_collected", run_id=state["run_id"],
                            evidence_count=len(http_rows))
            if (contract and result.file_artifact_evidence == []
                    and hasattr(self.target_runtime, "inspect_file_artifact")):
                rows = []
                for expectation in contract.file_artifacts:
                    try:
                        after = self.target_runtime.inspect_file_artifact(
                            run_id=state["run_id"], service=plan.target_service,
                            path_pattern=expectation.path_pattern)
                    except Exception as exc:
                        self._event("file_artifact_inspection_failed", run_id=state["run_id"],
                                    path_pattern=expectation.path_pattern,
                                    error_type=type(exc).__name__, error=str(exc))
                        continue
                    baseline = state.get("file_baselines", {}).get(expectation.path_pattern, {})
                    baseline_paths = {item.get("path") for item in baseline.get("matches", [])
                                      if isinstance(item, dict)}
                    new_files = [item for item in after.get("matches", [])
                                 if isinstance(item, dict) and item.get("path") not in baseline_paths]
                    rows.append({"source": "vulhub_runtime_file_artifact",
                                 "execution_id": result.execution_id, "target_id": result.target_id,
                                 "path_pattern": expectation.path_pattern,
                                 "existed_before": bool(baseline_paths),
                                 "exists_after": bool(after.get("matches")), "new_files": new_files})
                result = result.model_copy(update={"file_artifact_evidence": rows})
            bundle = self.evidence_collector.collect(result)
            self._event("evidence_collected", run_id=state["run_id"],
                        evidence_count=len(bundle.evidence))
            updates = {"execution_result": result, "evidence": bundle}
            if result.verification_policy is None:
                verification = VerificationResult(
                    run_id=state["run_id"], target_id=result.target_id,
                    vulnerability_type=plan.vulnerability_type,
                    result_label=contract.result_label if contract else "not_verified",
                    status="verification_unsupported",
                    reason="No pre-execution verification policy was frozen.",
                )
                self._event("verification_completed", run_id=state["run_id"],
                            status=verification.status, result_label=verification.result_label,
                            matched_rule_names=[], matched_evidence_ids=[])
                return {**updates, "verification_result": verification,
                        "status": "verification_unsupported"}
            verification = self.verification_engine.verify(
                policy=result.verification_policy, execution=result, evidence=bundle)
            self._event("verification_completed", run_id=state["run_id"], status=verification.status,
                        result_label=verification.result_label,
                        matched_rule_names=list(verification.matched_rule_names),
                        matched_evidence_ids=list(verification.matched_evidence_ids))
            status = {"success": "completed", "failed": "verification_failed",
                      "inconclusive": "inconclusive",
                      "verification_unsupported": "verification_unsupported"}[verification.status]
            return {**updates, "verification_policy": result.verification_policy,
                    "verification_result": verification, "status": status,
                    **({"failed_stage": "evidence_verification", "errors": [verification.reason]}
                       if status == "verification_failed" else {})}

        graph.add_node("target_preparation", self._stage("target_preparation", target_prepare))
        graph.add_node("document", self._stage("document", document))
        graph.add_node("research", self._stage("research", research))
        graph.add_node("planner", self._stage("planner", planner))
        graph.add_node("execution", self._stage("execution", execution))
        graph.add_node("script", self._stage("script", script))
        graph.add_node("evidence", self._stage("evidence", evidence))
        graph.add_edge(START, "target_preparation")
        graph.add_conditional_edges("target_preparation", lambda s: self._next(s, "document"))
        graph.add_conditional_edges("document", lambda s: self._next(s, "research"))
        graph.add_conditional_edges("research", lambda s: self._next(s, "planner"))
        def after_execution(state):
            result = state["execution_result"]
            if result.status == "completed":
                self._event("stage_skipped", run_id=state["run_id"], stage="script",
                            reason="metasploit_execution_completed")
                return self._next(state, "evidence")
            if result.status in {"failed", "unsupported"} and self.script_agent is not None:
                return self._next(state, "script")
            return self._next(state, "evidence")

        graph.add_conditional_edges("planner", lambda s: self._next(s, "execution"))
        graph.add_conditional_edges("execution", after_execution)
        graph.add_conditional_edges("script", lambda s: self._next(s, "evidence"))
        graph.add_edge("evidence", END)
        return graph.compile()

    def _cleanup_resources(self, run_id: str) -> list[str]:
        errors = []
        target_cleaned = False
        try:
            self.oob_callback_collector.stop(run_id=run_id)
        except Exception as exc:
            errors.append(f"OOB collector cleanup: {type(exc).__name__}: {exc}")
        try:
            self.target_runtime.restore_metasploit(run_id=run_id)
        except Exception as exc:
            errors.append(f"Metasploit network restore: {type(exc).__name__}: {exc}")
        try:
            result = self.target_runtime.cleanup_target(run_id=run_id)
            target_cleaned = isinstance(result, dict) and bool(result.get("cleaned"))
        except Exception as exc:
            errors.append(f"Vulhub target cleanup: {type(exc).__name__}: {exc}")
        if errors:
            self._event("resource_cleanup_failed", run_id=run_id, errors=errors)
        else:
            self._event("resource_cleanup_completed", run_id=run_id,
                        target_cleaned=target_cleaned)
        return errors

    def run(self, cve_id: str, *, authorization_callback=None,
            run_id: str | None = None) -> PipelineState:
        with self._run_lock:
            self._authorization_callback = authorization_callback
            initial: PipelineState = {"run_id": run_id or str(uuid.uuid4()),
                                      "cve_id": cve_id.upper(), "status": "running", "errors": []}
            final = initial
            try:
                final = self.graph.invoke(initial)
            except KeyboardInterrupt:
                final = {**initial, "status": "cancelled", "failed_stage": "user_cancelled",
                         "errors": ["User interrupted"]}
            except Exception as exc:
                final = {**initial, "status": "failed", "failed_stage": "workflow",
                         "errors": [f"{type(exc).__name__}: {exc}"]}
            finally:
                cleanup_errors = self._cleanup_resources(initial["run_id"])
                if cleanup_errors:
                    status = final.get("status", "failed")
                    final = {**final, "errors": [*final.get("errors", []), *cleanup_errors],
                             "status": "failed" if status in {"success", "completed"} else status}
            self._event("workflow_completed", run_id=final["run_id"], status=final.get("status", "failed"))
            return final
