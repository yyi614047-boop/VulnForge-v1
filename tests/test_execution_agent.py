from pathlib import Path

import pytest

from app.agents.execution import (
    ExecutionAgent, ExecutionAuthorization, MetasploitExecutor, ModuleMetadata, ModuleOption, RuntimeTarget,
)
from app.agents.planner import ReproductionPlan
from app.agents.research import ResearchResult
from app.targets.material import TargetMaterial

CVE = "CVE-2017-5638"


def fixtures(host="172.22.0.4", required=()):
    compose = {"services": {"web": {"image": "example/web:1", "ports": ["8080:80"]}}}
    target = TargetMaterial(CVE, Path("/vulhub"), Path(f"/vulhub/struts/{CVE}"), None, (), {"compose": compose})
    research = ResearchResult(cve_id=CVE, vulnerability_type="RCE", affected_component="web",
                              vulnerability_summary="RCE", vulnerability_mechanism="RCE",
                              trigger_conditions=["request"], prerequisites=[])
    plan = ReproductionPlan(cve_id=CVE, vulnerability_type="RCE", reproduction_goal="test",
                            target_service="web", prerequisites=[], execution_guidance="Metasploit",
                            verification_goal="verify separately", limitations=[], research_context=research,
                            status="ready")
    endpoint = RuntimeTarget.from_vulhub(target=target, run_id="run-1", service="web", port=80,
                                         host=host, project="lab-run1", container_id="a" * 64,
                                         network_name="lab-net", network_id="b" * 64)
    module = ModuleMetadata(module_name="exploit/multi/http/example", module_type="exploit",
                            name="Example", description="HTTP RCE", references=[CVE], raw_output="raw module info",
                            options=[ModuleOption(name="RHOSTS", required=True),
                                     ModuleOption(name="RPORT", required=True),
                                     ModuleOption(name="PAYLOAD", required=False)] + list(required),
                            session_capable=True)
    return target, plan, endpoint, module


class Search:
    def __init__(self, module=None, names=None, fail=None):
        self.module, self.names, self.fail = module, names, fail
        self.inspected = []
    def search(self, cve):
        if self.fail: raise self.fail
        return self.names if self.names is not None else ([self.module.module_name] if self.module else [])
    def inspect(self, cve, name):
        self.inspected.append(name)
        return self.module


class Rpc:
    def __init__(self, fail_execute=False, session=True, fail_connect=False, host="172.22.0.4"):
        self.calls, self.fail_execute = [], fail_execute
        self.session, self.fail_connect = session, fail_connect
        self.host = host
        self.session_reads = 0
    def call(self, method, *args):
        self.calls.append((method, args))
        if self.fail_connect: raise ConnectionError("RPC offline")
        if method == "session.list":
            self.session_reads += 1
            return ({"3": {"via_exploit": "multi/http/example", "target_host": self.host}}
                    if self.session and self.session_reads > 1 else {})
        if method == "module.execute":
            if self.fail_execute: raise RuntimeError("module rejected")
            return {"job_id": 7, "uuid": "job-7"}
        if method == "module.results": return {"status": "completed", "result": {"console": "finished"}}
        return {}


class Selector:
    def __init__(self, selected): self.selected = selected
    def run(self, **kwargs):
        assert kwargs["result_schema"].model_validate({"module_name": self.selected})
        return kwargs["result_schema"](module_name=self.selected)


def agent(module, *, names=None, selected=None, rpc=None, events=None, required=(), evidence_dir=None):
    search = Search(module, names)
    rpc = rpc or Rpc()
    return ExecutionAgent(search, MetasploitExecutor(rpc, poll_interval=0),
                          runner=Selector(selected if selected is not None else (module.module_name if module else None)),
                          event_sink=(events if events is not None else []).append, evidence_dir=evidence_dir), search, rpc


def invoke(execution, module, *, authorized=True, host="172.22.0.4", options=None):
    target, plan, endpoint, _ = fixtures(host, module.options[2:] if module else ())
    return execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                         authorized=authorized, options=options)


def test_search_select_execute_and_real_events(tmp_path):
    _, _, _, module = fixtures()
    events = []
    execution, _, rpc = agent(module, events=events, evidence_dir=tmp_path)
    result = invoke(execution, module)
    assert result.status == "completed" and result.module_name == module.module_name
    assert result.verification_policy.accepted_rules == ("session_established",)
    assert rpc.calls[1][0] == "module.execute"
    assert rpc.calls[1][1][2] == {"RHOSTS": "172.22.0.4", "RPORT": "80"}
    assert {e["type"] for e in events} >= {"module_search_started", "module_candidates_found", "module_selected",
                                           "module_configuration_started", "module_configuration_completed",
                                           "exploit_started", "exploit_completed", "session_detected"}
    assert (tmp_path / "run-1" / "execution-result.json").exists()


def test_empty_search_is_unsupported():
    execution, _, rpc = agent(None)
    result = invoke(execution, None)
    assert result.status == "unsupported" and not rpc.calls


def test_invented_llm_module_rejected_and_single_candidate_only():
    _, _, _, module = fixtures()
    execution, search, rpc = agent(module, selected="exploit/linux/fake")
    result = invoke(execution, module)
    assert result.status == "unsupported" and not rpc.calls
    assert search.inspected == [module.module_name]


def test_inapplicable_candidate_rejected():
    _, _, _, module = fixtures()
    module.references = []
    execution, _, rpc = agent(module)
    assert invoke(execution, module).status == "unsupported"
    assert not rpc.calls


def test_missing_required_parameter_rejected():
    _, _, _, module = fixtures(required=[ModuleOption(name="TARGETURI", required=True)])
    execution, _, rpc = agent(module)
    result = invoke(execution, module)
    assert result.status == "failed" and "TARGETURI" in result.errors[0]
    assert not any(c[0] == "module.execute" for c in rpc.calls)


def test_nonlocal_target_and_missing_authorization_rejected():
    _, _, _, module = fixtures(host="8.8.8.8")
    execution, _, rpc = agent(module)
    assert invoke(execution, module, host="8.8.8.8").status == "rejected"
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module)
    assert invoke(execution, module, authorized=False).status == "rejected"
    assert not any(c[0] == "module.execute" for c in rpc.calls)


def test_rpc_connection_and_execution_failures_are_single_shot():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module, rpc=Rpc(fail_connect=True))
    assert invoke(execution, module).status == "failed"
    assert len(rpc.calls) == 1
    execution, _, rpc = agent(module, rpc=Rpc(fail_execute=True))
    assert invoke(execution, module).status == "failed"
    assert len([c for c in rpc.calls if c[0] == "module.execute"]) == 1


def test_completed_without_session_is_not_a_vulnerability_verdict():
    _, _, _, module = fixtures()
    execution, _, _ = agent(module, rpc=Rpc(session=False))
    result = invoke(execution, module)
    assert result.status == "completed" and result.session_evidence == []
    assert result.job_status == "completed"


def test_target_override_and_payload_options_are_rejected():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module)
    assert invoke(execution, module, options={"RHOSTS": "8.8.8.8"}).status == "rejected"
    assert not rpc.calls


def test_run_bound_authorization_is_checked_after_baseline_before_exploit():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module)
    target, plan, endpoint, _ = fixtures()
    captured = []
    def authorize(request):
        captured.append(request)
        return ExecutionAuthorization(**request.model_dump(), approved=True)
    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorization_callback=authorize)
    assert result.status == "completed"
    assert captured[0].verification_policy_id == result.verification_policy.policy_id
    assert captured[0].session_baseline_ids == ()
    assert rpc.calls[0][0] == "session.list" and rpc.calls[1][0] == "module.execute"

    execution, _, rpc = agent(module)
    def stale(request):
        return ExecutionAuthorization(**{**request.model_dump(), "target_id": "stale"}, approved=True)
    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorization_callback=stale)
    assert result.status == "rejected"
    assert not any(call[0] == "module.execute" for call in rpc.calls)
