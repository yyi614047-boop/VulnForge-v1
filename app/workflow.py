"""LangGraph orchestration for the single-run local Vulhub pipeline."""
from __future__ import annotations

import os
import uuid
from threading import RLock
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from langgraph.graph import END, START, StateGraph

from app.agents.document import DocumentAgent
from app.agents.execution import (ExecutionAgent, ExecutionAuthorization,
                                  ExecutionAuthorizationRequest, MetasploitExecutor,
                                  MetasploitRpc, MetasploitSearch)
from app.agents.planner import PlannerAgent
from app.agents.research import ResearchAgent
from app.agents.runner import AgentRunner
from app.runtime.config import ConfigurationError, Settings
from app.runtime.model import create_model
from app.state import PipelineState
from app.targets.material import TargetMaterial
from app.targets.vulhub.config import VulhubSettings
from app.targets.vulhub.loader import load_target
from app.targets.vulhub.runtime import VulhubDockerRuntime
from app.verification.collector import EvidenceCollector
from app.verification.engine import VerificationEngine


EventSink = Callable[[dict], None]


class WorkflowConfigurationError(ValueError):
    pass


class VulnForgeWorkflow:
    """A small dependency-injected graph; only data models enter PipelineState."""
    def __init__(self, *, target_root: Path, target_runtime, document_agent,
                 research_agent, planner_agent, execution_agent,
                 evidence_collector=None, verification_engine=None,
                 event_sink: EventSink | None = None, language: str = "zh"):
        if language not in {"zh", "en"}:
            raise ValueError("language must be 'zh' or 'en'")
        self.target_root = target_root.resolve()
        self.target_runtime = target_runtime
        self.document_agent = document_agent
        self.research_agent = research_agent
        self.planner_agent = planner_agent
        self.execution_agent = execution_agent
        self.evidence_collector = evidence_collector or EvidenceCollector()
        self.verification_engine = verification_engine or VerificationEngine()
        self.event_sink = event_sink or (lambda event: None)
        self.language = language
        self._cleanup_target = False
        self._authorization_callback = None
        self._verification_expectations = ()
        self._run_lock = RLock()
        self.graph = self._compile()

    @classmethod
    def from_environment(cls, *, event_sink=None, language="zh"):
        vulhub = VulhubSettings.from_environment()
        settings = Settings.from_environment()
        runner_model = create_model(settings)
        container = os.getenv("MSF_CONTAINER_NAME", "vulnforge-metasploit").strip()
        if not container:
            container = "vulnforge-metasploit"
        workspace = Path(os.getenv("VULNFORGE_RUNS_ROOT", ".vulnforge-runs"))
        sink = event_sink or (lambda event: None)
        execution = ExecutionAgent(
            MetasploitSearch.from_env(),
            MetasploitExecutor(MetasploitRpc.from_env()),
            runner=AgentRunner(runner_model),
            event_sink=sink,
            evidence_dir=workspace / "evidence",
        )
        return cls(
            target_root=vulhub.root,
            target_runtime=VulhubDockerRuntime(
                workspace / "targets", metasploit_container=container,
                rpc_user=os.getenv("MSFRPC_USER", "msf"),
                rpc_password=os.getenv("MSFRPC_PASS", ""),
                rpc_port=int(os.getenv("MSFRPC_CONTAINER_PORT", "55553")),
            ),
            document_agent=DocumentAgent.from_environment(),
            research_agent=ResearchAgent.from_environment(),
            planner_agent=PlannerAgent.from_environment(),
            execution_agent=execution,
            evidence_collector=EvidenceCollector(workspace / "evidence"),
            event_sink=sink, language=language,
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
                self._event("stage_completed", run_id=state["run_id"], stage=name,
                            status=terminal_status)
            return updates
        return node

    @staticmethod
    def _next(state: PipelineState, next_node: str):
        return next_node if state.get("status") == "running" else "resource_cleanup"

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
            return {"document_markdown": self.document_agent.run(material, language=self.language)}

        def research(state):
            result = self.research_agent.run(cve_id=state["cve_id"],
                                             document_markdown=state["document_markdown"],
                                             target=state["target"], language=self.language)
            return {"research_result": result}

        def planner(state):
            plan = self.planner_agent.run(cve_id=state["cve_id"], research=state["research_result"],
                                          target=state["target"], document_markdown=state["document_markdown"],
                                          language=self.language)
            if not plan.executable or plan.status != "ready":
                status = "unsupported" if plan.status == "unsupported" else "plan_blocked"
                return {"reproduction_plan": plan, "status": status,
                        "failed_stage": "plan_validation", "errors": list(plan.validation_errors)}
            return {"reproduction_plan": plan}

        def execution(state):
            plan = state["reproduction_plan"]
            run_id = state["run_id"]
            runtime_state = {}

            def resolve_target(port: int):
                resolved = self.target_runtime.resolve_target(run_id=run_id, service=plan.target_service, port=port)
                runtime_state["target"] = resolved
                return resolved

            def authorize(request: ExecutionAuthorizationRequest):
                runtime_target = runtime_state.get("target")
                self._event("execution_authorization_requested", run_id=run_id,
                            target_id=request.target_id, module_name=request.module_name,
                            configuration=request.configuration_summary,
                            verification_policy_id=request.verification_policy_id,
                            runtime_target=runtime_target.model_dump(mode="json") if runtime_target else {},
                            reproduction_plan=plan.model_dump(mode="json"))
                callback = self._authorization_callback
                try:
                    grant = callback(request) if callback else None
                except Exception as exc:
                    self._event("execution_authorization_received", run_id=run_id,
                                approved=False, error_type=type(exc).__name__, error=str(exc))
                    return None
                if grant is not None:
                    self._event("execution_authorization_received", run_id=run_id,
                                approved=grant.approved,
                                request_matches=(grant.model_dump(exclude={"approved"})
                                                 == request.model_dump()))
                return grant

            def collect_diagnostics():
                collector = getattr(self.target_runtime, "collect_target_logs", None)
                if collector is None:
                    return {}
                return collector(run_id=run_id, service=plan.target_service)

            result = self.execution_agent.run(
                plan=plan, target=state["target"], target_resolver=resolve_target,
                run_id=run_id, authorized=False, authorization_callback=authorize,
                verification_expectations=self._verification_expectations,
                diagnostics_callback=collect_diagnostics,
            )
            runtime_target = runtime_state.get("target")
            state_runtime = (runtime_target.model_dump(mode="json")
                             if runtime_target else result.target)
            updates = {"runtime_target": state_runtime, "execution_result": result,
                       "verification_policy": result.verification_policy}
            if result.status == "unsupported":
                return {**updates, "status": "unsupported", "failed_stage": "module_selection",
                        "errors": list(result.errors)}
            if result.status == "rejected":
                return {**updates, "status": "execution_unauthorized", "failed_stage": "authorization",
                        "errors": list(result.errors)}
            if result.status == "failed":
                return {**updates, "status": "execution_failed", "failed_stage": "metasploit_execution",
                        "errors": list(result.errors)}
            return updates

        def evidence_and_verify(state):
            bundle = self.evidence_collector.collect(state["execution_result"])
            self._event("verification_started", run_id=state["run_id"],
                        policy_id=state["verification_policy"].policy_id)
            result = self.verification_engine.verify(policy=state["verification_policy"],
                                                      execution=state["execution_result"],
                                                      evidence=bundle)
            self._event("verification_completed", run_id=state["run_id"], status=result.status)
            return {"evidence": bundle, "verification_result": result, "status": result.status}

        def cleanup(state):
            run_id = state["run_id"]
            cleanup_errors = []
            try:
                self.target_runtime.restore_metasploit(run_id=run_id)
            except Exception as exc:
                cleanup_errors.append(f"Metasploit network restore: {type(exc).__name__}: {exc}")
            if self._cleanup_target:
                try:
                    self.target_runtime.cleanup_target(run_id=run_id)
                except Exception as exc:
                    cleanup_errors.append(f"Vulhub target cleanup: {type(exc).__name__}: {exc}")
            if cleanup_errors:
                status = state.get("status", "failed")
                self._event("resource_cleanup_failed", run_id=run_id, errors=cleanup_errors)
                return {"errors": [*state.get("errors", []), *cleanup_errors],
                        "status": "failed" if status == "success" else status}
            self._event("resource_cleanup_completed", run_id=run_id,
                        target_cleaned=self._cleanup_target)
            return {}

        graph.add_node("target_preparation", self._stage("target_preparation", target_prepare))
        graph.add_node("document", self._stage("document", document))
        graph.add_node("research", self._stage("research", research))
        graph.add_node("planner", self._stage("planner", planner))
        graph.add_node("execution", self._stage("execution", execution))
        graph.add_node("evidence_verification", self._stage("evidence_verification", evidence_and_verify))
        graph.add_node("resource_cleanup", cleanup)
        graph.add_edge(START, "target_preparation")
        graph.add_conditional_edges("target_preparation", lambda s: self._next(s, "document"))
        graph.add_conditional_edges("document", lambda s: self._next(s, "research"))
        graph.add_conditional_edges("research", lambda s: self._next(s, "planner"))
        graph.add_conditional_edges("planner", lambda s: self._next(s, "execution"))
        graph.add_conditional_edges("execution", lambda s: self._next(s, "evidence_verification"))
        graph.add_edge("evidence_verification", "resource_cleanup")
        graph.add_edge("resource_cleanup", END)
        return graph.compile()

    def run(self, cve_id: str, *, authorization_callback=None, cleanup_target: bool = False,
            verification_expectations=(), run_id: str | None = None) -> PipelineState:
        with self._run_lock:
            self._cleanup_target = cleanup_target
            self._authorization_callback = authorization_callback
            self._verification_expectations = tuple(verification_expectations)
            initial: PipelineState = {"run_id": run_id or str(uuid.uuid4()),
                                      "cve_id": cve_id.upper(), "status": "running", "errors": []}
            final = self.graph.invoke(initial)
            self._event("workflow_completed", run_id=final["run_id"], status=final.get("status", "failed"))
            return final
