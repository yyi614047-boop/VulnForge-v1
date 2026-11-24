from pathlib import Path

import pytest

from app.agents.execution import (ExecutionAuthorization,
                                  ExecutionAuthorizationRequest, ExecutionResult, RuntimeTarget)
from app.agents.planner import ReproductionPlan
from app.agents.research import ResearchResult
from app.runtime.config import RunContext
from app.targets.material import TargetMaterial
import app.workflow as workflow_module
from app.workflow import VulnForgeWorkflow
from app.targets.vulhub.runtime import VulhubDockerRuntime, VulhubRuntimeError
from app.verification.contracts import EvidenceRequirement, FileArtifactExpectation, HttpExpectation, OobExpectation, VerificationContract
from app.verification.models import CommandExpectation
from app.verification.policy import build_verification_policy

CVE = "CVE-2017-5638"
SESSION_CONTRACT = VerificationContract(
    evidence_requirements=(EvidenceRequirement(
        kind="session", rule_name="session_established", description="A new shell session is observed.",
    ),),
    result_label="session_access",
)
COMMAND_CONTRACT = VerificationContract(
    evidence_requirements=(EvidenceRequirement(
        kind="command_output", rule_name="command_output_match",
        description="Target-bound output matches the fixed POSIX id expectation.",
    ),),
    result_label="remote_command_execution",
)


def setup_vulhub(root):
    env = root / "struts" / CVE
    env.mkdir(parents=True, exist_ok=True)
    if not (env / "docker-compose.yml").exists():
        (env / "docker-compose.yml").write_text(
            "services:\n  web:\n    image: example/web:1\n    ports:\n      - '127.0.0.1:8080:80'\n",
            encoding="utf-8")
    return root


def make_plan(research, contract=None):
    return ReproductionPlan(cve_id=CVE, vulnerability_type=research.vulnerability_type,
                            reproduction_goal="test", target_service="web", prerequisites=[],
                            execution_guidance="Metasploit", verification_goal="RCE evidence",
                            limitations=[], research_context=research,
                            verification_contract=contract or SESSION_CONTRACT, status="ready")


class FakeRuntime:
    def __init__(self, fail=None):
        self.fail = fail
        self.calls = []
        self.target = None
    def start(self, *, target, run_id):
        self.calls.append(("start", run_id))
        if self.fail == "start": raise RuntimeError("docker start failed")
        self.target = target
        return {"project": "lab-" + run_id[:8], "network_name": "run_internal", "started": True}
    def prepare_metasploit(self, *, run_id):
        self.calls.append(("prepare_metasploit", run_id))
        if self.fail == "metasploit_network": raise RuntimeError("network setup failed")
    def resolve_target(self, *, run_id, service, port=None):
        self.calls.append(("resolve", service, port))
        return RuntimeTarget.from_vulhub(target=self.target, run_id=run_id, service=service, port=port or 80,
                                         host="172.22.0.4", project="lab-run1", container_id="a" * 64,
                                         network_name="run_internal", network_id="b" * 64)
    def restore_metasploit(self, *, run_id):
        self.calls.append(("restore_metasploit", run_id))
        if self.fail == "restore": raise RuntimeError("network restore failed")
    def cleanup_target(self, *, run_id):
        self.calls.append(("cleanup_target", run_id))
        if self.fail == "cleanup": raise RuntimeError("target cleanup failed")
        return {"cleaned": True}


class FakeDocument:
    def __init__(self, fail=False): self.fail, self.calls, self.runtime_info = fail, 0, None
    def run(self, target, *, language, runtime_info=None):
        self.calls += 1
        self.runtime_info = runtime_info
        if self.fail: raise RuntimeError("document failure")
        return "Locally grounded document"


class FakeResearch:
    def __init__(self, fail=False, result=None): self.fail, self.result, self.calls = fail, result, 0
    def run(self, **kwargs):
        self.calls += 1
        if self.fail: raise RuntimeError("research failure")
        return self.result


class FakePlanner:
    def __init__(self, plan=None, fail=False): self.plan, self.fail, self.calls = plan, fail, 0
    def run(self, **kwargs):
        self.calls += 1
        if self.fail: raise RuntimeError("planner failure")
        return self.plan


class FakeExecution:
    def __init__(self, mode="success", *, session_capable=True):
        self.mode, self.session_capable, self.calls = mode, session_capable, 0
    def run(self, *, plan, target, runtime_target=None, run_id, authorized,
            target_resolver=None, authorization_callback, document_markdown=None,
            diagnostics_callback=None, file_artifact_inspector=None):
        self.calls += 1
        if runtime_target is None:
            runtime_target = target_resolver(80)
        module = "exploit/multi/http/example"
        contract = plan.verification_contract
        policy = build_verification_policy(
            run_id=run_id, target_id=runtime_target.container_id,
            vulnerability_type=plan.vulnerability_type, contract=contract,
            module_type="exploit", module_name=module, session_capable=self.session_capable,
            command_output_supported=self.mode == "command_success",
            command_expectations=(CommandExpectation(
                pattern="uid=0(root)", source="test.posix-id"),) if self.mode == "command_success" else (),
            oob_callback_supported=runtime_target.oob_callback_host is not None,
        ) if contract else None
        request = ExecutionAuthorizationRequest(run_id=run_id, target_id=runtime_target.container_id,
                                                target_fingerprint="target-fp", plan_fingerprint="plan-fp",
                                                module_name=module, module_fingerprint="module-fp",
                                                configuration_fingerprint="config-fp", configuration_summary={},
                                                verification_policy_id=policy.policy_id if policy else "verification-disabled")
        grant = authorization_callback(request) if authorization_callback else None
        matched = grant is not None and grant.approved and all(
            getattr(grant, key) == value for key, value in request.model_dump().items())
        status = "rejected" if not matched else ("failed" if self.mode == "execution_failed" else "unsupported" if self.mode == "module_unsupported" else "completed")
        sessions = ([{"session_id": "4", "type": "shell", "target_host": runtime_target.host,
                      "via_exploit": "multi/http/example", "exploit_uuid": "job-1"}]
                    if self.mode == "success" else [])
        return ExecutionResult(run_id=run_id, execution_id="exec-1", target_id=runtime_target.container_id,
                               cve_id=plan.cve_id, module_name=module, target=runtime_target.model_dump(),
                               status=status, job_id=1 if status == "completed" else None,
                               job_uuid="job-1" if status == "completed" else None,
                               job_status="completed" if status == "completed" else None,
                               session_baseline=[], session_after=sessions,
                               rpc_session_snapshot_collected=status == "completed",
                               rpc_job_result_collected=status == "completed",
                               command_output_evidence=([{
                                   "source": "metasploit_rpc_command_output", "execution_id": "exec-1",
                                   "target_id": runtime_target.container_id,
                                   "output": "uid=0(root) gid=0(root) groups=0(root)",
                               }] if self.mode == "command_success" else []),
                               errors=["mock execution failed"] if status == "failed" else [],
                               verification_policy=policy)


def research_result(category="RCE"):
    return ResearchResult(cve_id=CVE, vulnerability_type=category, affected_component="web",
                          vulnerability_summary="summary", vulnerability_mechanism="mechanism",
                          trigger_conditions=["trigger"])


def authorize(request):
    return ExecutionAuthorization(**request.model_dump(), approved=True)


def make_workflow(tmp_path, *, docker=None, document=None, research=None, planner=None,
                  execution=None, script=None, events=None, http_collector=None, oob_collector=None):
    root = setup_vulhub(tmp_path / "vulhub")
    result = research_result()
    plan = make_plan(result)
    return VulnForgeWorkflow(target_root=root, target_runtime=docker or FakeRuntime(),
                             document_agent=document or FakeDocument(),
                             research_agent=research or FakeResearch(result=result),
                             planner_agent=planner or FakePlanner(plan),
                             execution_agent=execution or FakeExecution(),
                             script_agent=script,
                             http_response_collector=http_collector,
                             oob_callback_collector=oob_collector,
                             event_sink=(events if events is not None else []).append)


class FakeScript:
    def __init__(self):
        self.calls = 0
        self.document = None

    def run(self, *, plan, target, runtime_target, run_id, document_markdown,
            authorization_callback, work_dir):
        self.calls += 1
        self.document = document_markdown
        policy = build_verification_policy(
            run_id=run_id, target_id=runtime_target.container_id,
            vulnerability_type=plan.vulnerability_type, contract=plan.verification_contract,
            module_type="script", module_name="script/python/poc",
            command_output_supported=True,
            command_expectations=(CommandExpectation(pattern="uid=0(root)", source="test.posix-id"),),
        )
        request = ExecutionAuthorizationRequest(
            run_id=run_id, target_id=runtime_target.container_id,
            target_fingerprint="target", plan_fingerprint="plan",
            module_name="script/python/poc", module_fingerprint="program",
            configuration_fingerprint="program", configuration_summary={},
            verification_policy_id=policy.policy_id)
        grant = authorization_callback(request)
        if grant is None or not grant.approved:
            raise PermissionError("denied")
        return ExecutionResult(
            run_id=run_id, execution_id="script-exec", target_id=runtime_target.container_id,
            cve_id=plan.cve_id, target=runtime_target.model_dump(), status="completed",
            module_name="script/python/poc", success_basis="none", verification_policy=policy,
            command_output_evidence=[{"source": "script_command_output",
                "execution_id": "script-exec", "target_id": runtime_target.container_id,
                "output": "uid=0(root) gid=0(root)"}])


def test_metasploit_failure_routes_readable_document_to_script_and_verifies_evidence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    plan = make_plan(research_result(), COMMAND_CONTRACT)
    script = FakeScript()
    events = []
    docker = FakeRuntime()
    state = make_workflow(tmp_path, planner=FakePlanner(plan), docker=docker,
                          execution=FakeExecution("execution_failed", session_capable=False),
                          script=script, events=events).run(CVE, authorization_callback=authorize)
    assert state["status"] == "completed"
    assert state["script_result"].module_name == "script/python/poc"
    assert state["verification_result"].status == "success"
    assert script.calls == 1 and script.document == "Locally grounded document"
    assert state["target_binding"]["port"] == 80
    assert state["execution_result"].target["port"] == 80
    assert [call for call in docker.calls if call[0] == "resolve"] == [
        ("resolve", "web", 80), ("resolve", "web", 80), ("resolve", "web", 80)]
    assert len([event for event in events if event["type"] == "execution_authorization_requested"]) == 2
    assert "evidence_collected" in [event["type"] for event in events]
    assert "stage_skipped" not in [event["type"] for event in events]


def test_target_port_is_bound_during_planning_from_documented_service(tmp_path):
    compose = tmp_path / "vulhub" / "struts" / CVE / "docker-compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text(
        "services:\n  activemq:\n    image: vulhub/activemq:5.17.3\n"
        "    ports:\n      - '61616:61616'\n      - '8161:8161'\n      - '5005:5005'\n",
        encoding="utf-8")
    research = research_result()
    research.affected_component = "ActiveMQ"
    plan = make_plan(research)
    plan.target_service = "activemq"
    docker = FakeRuntime()
    events = []
    class ActiveMqDocument:
        def run(self, target, *, language, runtime_info=None):
            return "The ActiveMQ web console is available at http://localhost:8161/admin/."
    state = make_workflow(tmp_path, planner=FakePlanner(plan), docker=docker, events=events,
                          document=ActiveMqDocument(), execution=FakeExecution("execution_failed"),
                          script=FakeScript()).run(CVE, authorization_callback=authorize)
    assert state["target_binding"]["port"] == 8161
    assert state["script_result"].target["port"] == 8161
    bound = next(event for event in events if event["type"] == "target_bound")
    execution_started = next(event for event in events
                             if event["type"] == "stage_started" and event["stage"] == "execution")
    assert events.index(bound) < events.index(execution_started)


def test_ambiguous_target_port_blocks_before_execution_and_script(tmp_path):
    compose = tmp_path / "vulhub" / "struts" / CVE / "docker-compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text(
        "services:\n  web:\n    image: example/web:1\n"
        "    ports:\n      - '8080:80'\n      - '8443:443'\n", encoding="utf-8")
    execution, script, events = FakeExecution(), FakeScript(), []
    state = make_workflow(tmp_path, execution=execution, script=script, events=events).run(
        CVE, authorization_callback=authorize)
    assert state["status"] == "plan_blocked"
    assert state["failed_stage"] == "target_port_binding"
    assert "execution_result" not in state and "script_result" not in state
    assert execution.calls == 0 and script.calls == 0
    assert any(event["type"] == "target_port_binding_failed" for event in events)


class FakeHttpCollector:
    def __init__(self):
        self.calls = 0

    def collect(self, execution, expectations):
        self.calls += 1
        return [{"source": "vulnforge_http_probe", "execution_id": execution.execution_id,
                 "target_id": execution.target_id, "expectation": expectations[0].model_dump(mode="json"),
                 "status": expectations[0].expected_status, "headers": [], "body": "root:x:0:0",
                 "truncated": False, "error": None}]


def test_http_contract_is_independently_probed_and_verified(tmp_path):
    research = research_result("File Read")
    expectation = HttpExpectation(path="/icons/.%2e/etc/passwd", expected_status=200,
                                  body_contains="root:x:0:0", source="README")
    contract = VerificationContract(
        evidence_requirements=(EvidenceRequirement(
            kind="http_response", rule_name="http_response_observed",
            description="The passwd content is returned.",
        ),), result_label="file_read_confirmed", http_expectations=(expectation,),
    )
    collector = FakeHttpCollector()
    events = []
    state = make_workflow(tmp_path, research=FakeResearch(result=research),
                          planner=FakePlanner(make_plan(research, contract)),
                          http_collector=collector, events=events).run(
                              CVE, authorization_callback=authorize)
    assert state["status"] == "completed"
    assert state["verification_result"].status == "success"
    assert collector.calls == 1
    assert any(item.evidence_type == "http_response" for item in state["evidence"].evidence)
    assert "http_response_collected" in [event["type"] for event in events]


class FakeOobCollector:
    def __init__(self):
        self.started = 0
        self.stopped = 0

    def start(self, *, run_id, network_name, expectation):
        self.started += 1
        return {"callback_host": "172.22.0.5", "callback_port": 8000,
                "callback_url": f"http://172.22.0.5:8000{expectation.path}",
                "token": expectation.token, "path": expectation.path}

    def collect(self, *, run_id, execution, expectation, target_host):
        return [{"source": "vulnforge_oob_collector", "execution_id": execution.execution_id,
                 "target_id": execution.target_id, "target_host": target_host,
                 "expectation": expectation.model_dump(mode="json"), "token": expectation.token,
                 "path": expectation.path, "method": "GET",
                 "remote_host": target_host, "remote_port": 43210}]

    def stop(self, *, run_id):
        self.stopped += 1


def test_oob_contract_starts_collector_before_execution_and_verifies_callback(tmp_path):
    research = research_result("SSRF")
    probe = OobExpectation(token="workflow_oob_token_123456", path="/oob/workflow_oob_token_123456",
                           source="README")
    contract = VerificationContract(
        evidence_requirements=(EvidenceRequirement(
            kind="oob_callback", rule_name="oob_callback_observed",
            description="The target calls the frozen URL.",
        ),), result_label="ssrf_confirmed", oob_expectations=(probe,),
    )
    collector = FakeOobCollector()
    events = []
    state = make_workflow(tmp_path, research=FakeResearch(result=research),
                          planner=FakePlanner(make_plan(research, contract)),
                          oob_collector=collector, events=events).run(
                              CVE, authorization_callback=authorize)
    assert state["status"] == "completed"
    assert state["verification_result"].status == "success"
    assert collector.started == 1 and collector.stopped >= 1
    assert state["runtime_target"]["oob_callback_host"] == "172.22.0.5"
    assert "oob_collector_started" in [event["type"] for event in events]
    assert "oob_callback_collected" in [event["type"] for event in events]


def test_planner_file_baseline_failure_degrades_to_verification_unsupported(tmp_path):
    research = research_result("File Write")
    contract = VerificationContract(
        evidence_requirements=(EvidenceRequirement(
            kind="file_artifact", rule_name="file_artifact_observed",
            description="A webshell is written.",
        ),), result_label="file_write_confirmed",
        file_artifacts=(FileArtifactExpectation(path_pattern="/admin/shell.jsp", source="README"),),
    )
    runtime = FakeRuntime()
    runtime.inspect_file_artifact = lambda **kwargs: (_ for _ in ()).throw(
        RuntimeError("File artifact root is outside the allowed local target paths"))
    execution = FakeExecution()
    events = []
    state = make_workflow(tmp_path, docker=runtime, research=FakeResearch(result=research),
                          planner=FakePlanner(make_plan(research, contract)),
                          execution=execution, events=events).run(CVE, authorization_callback=authorize)
    assert execution.calls == 1
    assert state["status"] == "verification_unsupported"
    assert "file_baseline_unavailable" in [event["type"] for event in events]
    assert "file_artifact_inspection_failed" in [event["type"] for event in events]


def test_normal_graph_state_events_authorization_and_success(tmp_path):
    events = []
    runtime = FakeRuntime()
    execution = FakeExecution()
    document = FakeDocument()
    wf = make_workflow(tmp_path, docker=runtime, execution=execution, document=document, events=events)
    state = wf.run(CVE, run_id="run123456", authorization_callback=authorize)
    assert state["status"] == "completed"
    assert state["target"].identifier == CVE and state["document_markdown"]
    assert document.runtime_info["project"] == "lab-run12345"
    assert state["research_result"].cve_id == CVE and state["reproduction_plan"].executable
    assert state["verification_result"].status == "success"
    assert state["verification_policy"] == state["execution_result"].verification_policy
    assert state["execution_result"].run_id == state["evidence"].run_id == state["run_id"]
    kinds = [x["type"] for x in events]
    assert "stage_started" in kinds and "execution_authorization_requested" in kinds
    assert "evidence_collected" in kinds and "workflow_completed" in kinds
    assert "verification_completed" in kinds
    skipped = next(event for event in events if event["type"] == "stage_skipped")
    assert skipped["stage"] == "script" and skipped["reason"] == "metasploit_execution_completed"
    assert kinds.index("stage_skipped") < kinds.index("evidence_collected")
    authorization = next(event for event in events if event["type"] == "execution_authorization_requested")
    assert authorization["verification_contract"] == SESSION_CONTRACT.model_dump(mode="json")
    assert authorization["verification_policy_id"] != "verification-disabled"
    assert execution.calls == 1
    assert runtime.calls[-2:] == [
        ("restore_metasploit", "run123456"),
        ("cleanup_target", "run123456"),
    ]


def test_target_preparation_failure_terminates(tmp_path):
    runtime = FakeRuntime(fail="start")
    document = FakeDocument()
    state = make_workflow(tmp_path, docker=runtime, document=document).run(CVE, authorization_callback=authorize)
    assert state["status"] == "failed" and state["failed_stage"] == "target_preparation"
    assert document.calls == 0
    assert ("cleanup_target", state["run_id"]) in runtime.calls


def test_document_and_research_failures_stop_later_nodes(tmp_path):
    planner = FakePlanner(make_plan(research_result()))
    state = make_workflow(tmp_path, document=FakeDocument(fail=True), planner=planner).run(CVE)
    assert state["failed_stage"] == "document" and planner.calls == 0
    research = FakeResearch(fail=True)
    state = make_workflow(tmp_path / "other", research=research).run(CVE)
    assert state["failed_stage"] == "research" and state["status"] == "failed"


def test_unexecutable_plan_stops_before_metaspploit(tmp_path):
    result = research_result()
    plan = make_plan(result).model_copy(update={"status": "blocked", "validation_errors": ["missing information"]})
    execution = FakeExecution()
    state = make_workflow(tmp_path, planner=FakePlanner(plan), execution=execution).run(CVE)
    assert state["status"] == "plan_blocked" and execution.calls == 0


def test_command_evidence_verifies_without_session(tmp_path):
    plan = make_plan(research_result(), COMMAND_CONTRACT)
    execution = FakeExecution("command_success", session_capable=False)
    events = []
    state = make_workflow(tmp_path, planner=FakePlanner(plan), execution=execution,
                          events=events).run(CVE, authorization_callback=authorize)
    assert state["status"] == "completed"
    assert state["execution_result"].session_after == []
    assert state["execution_result"].command_output_evidence
    assert state["verification_result"].status == "success"
    authorization = next(event for event in events if event["type"] == "execution_authorization_requested")
    assert authorization["verification_contract"] == COMMAND_CONTRACT.model_dump(mode="json")


def test_unsupported_verification_reason_does_not_block_execution(tmp_path):
    research = research_result("SQLi")
    contract = VerificationContract(
        evidence_requirements=(EvidenceRequirement(
            kind="command_output", rule_name="command_output_match",
            description="Command output is not allowed for SQLi verification.",
        ),),
        result_label="sql_injection_confirmed",
    )
    plan = make_plan(research, contract).model_copy(update={
        "status": "ready", "unsupported_reason": "No trusted database result collector is implemented.",
    })
    execution = FakeExecution()
    state = make_workflow(tmp_path, research=FakeResearch(result=research),
                          planner=FakePlanner(plan), execution=execution).run(CVE, authorization_callback=authorize)
    assert state["status"] == "verification_unsupported"
    assert execution.calls == 1
    assert state["verification_result"].status == "verification_unsupported"


def test_missing_module_is_distinct_unsupported(tmp_path):
    execution = FakeExecution("module_unsupported")
    state = make_workflow(tmp_path, execution=execution).run(CVE, authorization_callback=authorize)
    assert state["status"] == "verification_unsupported"
    assert state["verification_result"].status == "verification_unsupported"
    assert "evidence" in state


def test_completed_job_without_evidence_is_inconclusive(tmp_path):
    execution = FakeExecution("no_verification")
    state = make_workflow(tmp_path, execution=execution).run(CVE, authorization_callback=authorize)
    assert state["status"] == "inconclusive"
    assert state["verification_result"].status == "inconclusive"
    assert state["verification_policy"] is not None


@pytest.mark.parametrize("callback", [None, lambda request: None,
                                       lambda request: ExecutionAuthorization(**request.model_dump(), approved=False),
                                       lambda request: ExecutionAuthorization(**{**request.model_dump(), "run_id": "other"}, approved=True),
                                       lambda request: ExecutionAuthorization(**{**request.model_dump(), "verification_policy_id": "stale-policy"}, approved=True)])
def test_missing_denied_or_mismatched_authorization_never_executes(tmp_path, callback):
    execution = FakeExecution()
    state = make_workflow(tmp_path, execution=execution).run(CVE, authorization_callback=callback)
    assert state["status"] == "execution_unauthorized"
    assert state["execution_result"].status == "rejected"
    assert state.get("evidence") is None and state.get("verification_result") is None


def test_metasploit_failure_still_collects_execution_evidence(tmp_path):
    execution = FakeExecution("execution_failed")
    state = make_workflow(tmp_path, execution=execution).run(CVE, authorization_callback=authorize)
    assert state["status"] == "inconclusive"
    assert state["execution_result"].status == "failed"
    assert "evidence" in state and state["verification_result"].status == "inconclusive"


def test_completed_execution_without_session_keeps_evidence_and_does_not_retry_or_replan(tmp_path):
    execution = FakeExecution("no_session")
    planner = FakePlanner(make_plan(research_result()))
    state = make_workflow(tmp_path, execution=execution, planner=planner).run(CVE, authorization_callback=authorize)
    assert state["status"] == "inconclusive"
    assert state["execution_result"].session_after == []
    assert state["verification_result"].status == "inconclusive"
    assert "evidence" in state
    assert execution.calls == planner.calls == 1


def test_cleanup_runs_automatically_for_the_current_run(tmp_path):
    runtime = FakeRuntime()
    state = make_workflow(tmp_path, docker=runtime).run(CVE, authorization_callback=authorize)
    assert runtime.calls[-2:] == [
        ("restore_metasploit", state["run_id"]),
        ("cleanup_target", state["run_id"]),
    ]


def test_cleanup_runs_after_keyboard_interrupt(tmp_path):
    runtime = FakeRuntime()
    document = FakeDocument()
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt
    document.run = interrupt
    state = make_workflow(tmp_path, docker=runtime, document=document).run(CVE)
    assert state["status"] == "cancelled" and state["failed_stage"] == "user_cancelled"
    assert runtime.calls[-1] == ("cleanup_target", state["run_id"])


def test_cleanup_failure_is_reported_without_skipping_target_cleanup(tmp_path):
    runtime = FakeRuntime(fail="restore")
    state = make_workflow(tmp_path, docker=runtime).run(CVE, authorization_callback=authorize)
    assert state["status"] == "failed"
    assert runtime.calls[-1] == ("cleanup_target", state["run_id"])
    assert any("Metasploit network restore" in error for error in state["errors"])


def test_environment_assembly_creates_one_shared_model(monkeypatch, tmp_path):
    vulhub = tmp_path / "vulhub"
    vulhub.mkdir()
    monkeypatch.setenv("VULNFORGE_VULHUB_ROOT", str(vulhub))
    monkeypatch.setenv("VULNFORGE_RUNS_ROOT", str(tmp_path / "runs"))
    monkeypatch.setenv("MSFRPC_USER", "msf")
    monkeypatch.setenv("MSFRPC_PASS", "test-password")
    context = RunContext.create(CVE)
    created = []
    monkeypatch.setattr(workflow_module, "create_model",
                        lambda settings: created.append(settings) or object())
    workflow = VulnForgeWorkflow.from_environment(run_context=context)
    assert len(created) == 1
    assert workflow.document_agent.runner is workflow.research_agent.runner
    assert workflow.research_agent.runner is workflow.planner_agent.runner
    assert workflow.planner_agent.runner is workflow.execution_agent.runner
    assert workflow.run_context is context
    assert workflow.evidence_collector.evidence_dir == context.evidence_dir
    assert workflow.target_runtime.workspace == context.targets_dir.resolve()


def test_docker_runtime_starts_isolated_project_and_restores_only_metasploit_network(tmp_path):
    material = __import__("app.targets.vulhub.loader", fromlist=["load_target"]).load_target(
        setup_vulhub(tmp_path / "source"), CVE)
    calls = []
    network_name = "lab-run1_vulnforge_internal"
    msf_id = "d" * 64
    target_id = "e" * 64
    network_id = "f" * 64
    original_ids = {"bridge": "a" * 64, "shared_services": "b" * 64}
    msf_state = {"networks": {
        "bridge": {"NetworkID": original_ids["bridge"], "Aliases": ["vulnforge-msf"]},
        "shared_services": {"NetworkID": original_ids["shared_services"], "Aliases": ["msf-rpc"]},
    }, "running": True}

    def runner(argv, **kwargs):
        calls.append(list(argv))
        output = ""
        if argv[:3] == ["docker", "compose", "--project-name"]:
            if "ps" in argv:
                output = target_id + "\n"
        elif argv[:3] == ["docker", "container", "ls"]:
            output = "msf\n"
        elif argv[:3] == ["docker", "network", "inspect"]:
            inspected_name = argv[3]
            inspected_id = network_id if inspected_name == network_name else original_ids[inspected_name]
            internal = "true" if inspected_name == network_name else "false"
            output = '[{"Id":"' + inspected_id + '","Name":"' + inspected_name + '","Internal":' + internal + '}]'
        elif argv[:2] == ["docker", "inspect"]:
            identifier = argv[-1]
            if identifier in {"msf", msf_id}:
                output = __import__("json").dumps([{"Id": msf_id,
                    "Config": {"Image": VulhubDockerRuntime.METASPLOIT_IMAGE},
                    "State": {"Running": True}, "NetworkSettings": {"Networks": msf_state["networks"]}}])
            else:
                output = __import__("json").dumps([{"Id": target_id, "Image": target_id,
                    "State": {"Running": True},
                    "NetworkSettings": {"Networks": {network_name: {"NetworkID": network_id,
                                                                     "IPAddress": "172.22.0.4"}}}}])
        elif argv[:3] == ["docker", "image", "inspect"]:
            output = '[{"Os":"linux","Architecture":"amd64"}]'
        elif argv[:3] == ["docker", "network", "disconnect"]:
            msf_state["networks"].pop(argv[3], None)
        elif argv[:3] == ["docker", "network", "connect"]:
            connect_index = 3
            aliases = []
            ipam = {}
            while connect_index < len(argv) and argv[connect_index].startswith("--"):
                option = argv[connect_index]; value = argv[connect_index + 1]; connect_index += 2
                if option == "--alias": aliases.append(value)
                elif option == "--ip": ipam["IPv4Address"] = value
                elif option == "--ip6": ipam["IPv6Address"] = value
            name = argv[connect_index]
            msf_state["networks"][name] = {"NetworkID": network_id if name == network_name else original_ids[name],
                                             "Aliases": aliases, "IPAMConfig": ipam,
                                             "IPAddress": "172.22.0.3" if name == network_name else ""}
        return type("Result", (), {"returncode": 0, "stdout": output, "stderr": ""})()

    runtime = VulhubDockerRuntime(tmp_path / "workspace", metasploit_container="msf",
                                  rpc_password="test-password", runner=runner)
    started = runtime.start(target=material, run_id="run1")
    assert started["project"] == "lab-run1"
    sanitized_path = Path(runtime._runs["run1"]["prefix"][runtime._runs["run1"]["prefix"].index("--file") + 1])
    sanitized_compose = __import__("yaml").safe_load(sanitized_path.read_text(encoding="utf-8"))
    assert "ports" not in sanitized_compose["services"]["web"]
    assert sanitized_compose["services"]["web"]["expose"] == ["80"]
    runtime.prepare_metasploit(run_id="run1")
    endpoint = runtime.resolve_target(run_id="run1", service="web")
    assert endpoint.host == "172.22.0.4" and endpoint.port == 80
    assert endpoint.os == "linux" and endpoint.architecture == "amd64"
    runtime.restore_metasploit(run_id="run1")
    runtime.cleanup_target(run_id="run1")
    assert set(msf_state["networks"]) == set(original_ids)
    assert {name: detail["NetworkID"] for name, detail in msf_state["networks"].items()} == original_ids
    assert msf_state["networks"]["bridge"]["Aliases"] == ["vulnforge-msf"]
    assert msf_state["networks"]["shared_services"]["Aliases"] == ["msf-rpc"]
    assert not any(argv[1] == "stop" or argv[1] == "rm" for argv in calls if argv[0] == "docker")
    down = next(argv for argv in calls if argv[:2] == ["docker", "compose"] and "down" in argv)
    assert down[down.index("--project-name") + 1] == "lab-run1"
    assert all(argv[-1] == msf_id for argv in calls if argv[:2] == ["docker", "restart"])


def test_authorization_callback_exception_is_denial(tmp_path):
    execution = FakeExecution()
    def fail_auth(request): raise RuntimeError("authorization unavailable")
    state = make_workflow(tmp_path, execution=execution).run(CVE, authorization_callback=fail_auth)
    assert state["status"] == "execution_unauthorized"
    assert execution.calls == 1


def test_docker_runtime_collects_target_logs_and_http_status(tmp_path):
    material = __import__("app.targets.vulhub.loader", fromlist=["load_target"]).load_target(
        setup_vulhub(tmp_path / "source"), CVE)
    target_id = "e" * 64

    def runner(argv, **kwargs):
        output = ""
        if argv[:3] == ["docker", "compose", "--project-name"]:
            if "ps" in argv:
                output = target_id + "\n"
        elif argv[:2] == ["docker", "inspect"]:
            output = __import__("json").dumps([{"Id": target_id, "State": {"Running": True}}])
        return type("Result", (), {
            "returncode": 0, "stdout": output,
            "stderr": "[WARNING] Header is too large >8192\n[WARNING] badMessage: 413",
        })()

    runtime = VulhubDockerRuntime(tmp_path / "workspace", metasploit_container="msf", runner=runner)
    runtime.start(target=material, run_id="run-diagnostics")
    diagnostics = runtime.collect_target_logs(run_id="run-diagnostics", service="web")
    assert diagnostics["http_status"] == 413
    assert "Header is too large" in diagnostics["target_log_tail"]


def test_docker_runtime_strips_host_port_publication(tmp_path):
    root = setup_vulhub(tmp_path / "source")
    compose = root / "struts" / CVE / "docker-compose.yml"
    compose.write_text("services:\n  web:\n    image: example/web:1\n    ports:\n      - '61616:61616'\n      - '8161:8161'\n", encoding="utf-8")
    material = __import__("app.targets.vulhub.loader", fromlist=["load_target"]).load_target(root, CVE)
    calls = []
    target_id = "e" * 64
    def runner(argv, **kwargs):
        calls.append(list(argv))
        output = ""
        if argv[:3] == ["docker", "compose", "--project-name"] and "ps" in argv:
            output = target_id + "\n"
        elif argv[:2] == ["docker", "inspect"]:
            output = __import__("json").dumps([{"Id": target_id, "State": {"Running": True}}])
        return type("Result", (), {"returncode": 0, "stdout": output, "stderr": ""})()
    runtime = VulhubDockerRuntime(tmp_path / "workspace", metasploit_container="msf", runner=runner)
    runtime.start(target=material, run_id="run-safe-ports")
    run = runtime._runs["run-safe-ports"]
    sanitized_path = Path(run["prefix"][run["prefix"].index("--file") + 1])
    sanitized = __import__("yaml").safe_load(sanitized_path.read_text(encoding="utf-8"))
    service = sanitized["services"]["web"]
    assert "ports" not in service
    assert service["expose"] == ["61616", "8161"]
    assert calls and str(sanitized_path) in calls[0] and str(compose) not in calls[0]


def test_docker_runtime_normalizes_project_relative_short_bind_as_read_only(tmp_path):
    root = setup_vulhub(tmp_path / "source")
    environment = root / "struts" / CVE
    (environment / "struts.xml").write_text("<struts/>", encoding="utf-8")
    (environment / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: example/web:1\n    volumes:\n"
        "      - ./struts.xml:/usr/local/tomcat/conf/struts.xml\n",
        encoding="utf-8",
    )
    material = __import__("app.targets.vulhub.loader", fromlist=["load_target"]).load_target(root, CVE)

    def runner(argv, **kwargs):
        output = ""
        if argv[:3] == ["docker", "compose", "--project-name"] and "ps" in argv:
            output = "e" * 64 + "\n"
        elif argv[:2] == ["docker", "inspect"]:
            output = __import__("json").dumps([{"Id": "e" * 64, "State": {"Running": True}}])
        return type("Result", (), {"returncode": 0, "stdout": output, "stderr": ""})()

    runtime = VulhubDockerRuntime(tmp_path / "workspace", metasploit_container="msf", runner=runner)
    runtime.start(target=material, run_id="run-short-bind")
    run = runtime._runs["run-short-bind"]
    sanitized_path = Path(run["prefix"][run["prefix"].index("--file") + 1])
    sanitized = __import__("yaml").safe_load(sanitized_path.read_text(encoding="utf-8"))
    assert sanitized["services"]["web"]["volumes"] == [{
        "type": "bind", "source": "./struts.xml",
        "target": "/usr/local/tomcat/conf/struts.xml", "read_only": True,
    }]


def test_docker_runtime_rejects_unsafe_or_writable_short_bind_mounts(tmp_path):
    root = setup_vulhub(tmp_path / "source")
    environment = root / "struts" / CVE
    (environment / "struts.xml").write_text("<struts/>", encoding="utf-8")
    runtime = VulhubDockerRuntime(tmp_path / "workspace", metasploit_container="msf")
    for declaration in (
        "/tmp/struts.xml:/usr/local/tomcat/conf/struts.xml:ro",
        "../outside.xml:/usr/local/tomcat/conf/struts.xml:ro",
        "named-volume:/usr/local/tomcat/conf/struts.xml",
        "./struts.xml:/usr/local/tomcat/conf/struts.xml:rw",
    ):
        (environment / "docker-compose.yml").write_text(
            "services:\n  web:\n    image: example/web:1\n    volumes:\n"
            f"      - {declaration}\n",
            encoding="utf-8",
        )
        material = __import__("app.targets.vulhub.loader", fromlist=["load_target"]).load_target(root, CVE)
        with pytest.raises(VulhubRuntimeError, match="bind mounts|Short bind mounts"):
            runtime._validate_compose(material)


def test_docker_runtime_live_progress_preserves_stderr_for_failures(tmp_path):
    calls = []

    def runner(argv, **kwargs):
        calls.append(kwargs)
        if "up" in argv:
            return type("Result", (), {"returncode": 1, "stdout": None, "stderr": "compose failed"})()
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    runtime = VulhubDockerRuntime(tmp_path / "workspace", metasploit_container="msf", runner=runner)
    with pytest.raises(VulhubRuntimeError, match="compose failed"):
        runtime._call(["docker", "compose", "up"], live_progress=True)
    assert calls == [{"stderr": __import__("subprocess").PIPE, "text": True,
                      "encoding": "utf-8", "errors": "replace",
                      "timeout": runtime.timeout, "shell": False, "cwd": None}]
    assert runtime._call(["docker", "compose", "ps"]) == ""
    assert calls[1]["capture_output"] is True
