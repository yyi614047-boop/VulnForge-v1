from pathlib import Path

import pytest

from app.agents.execution import (
    ExecutionAgent, ExecutionAuthorization, RuntimeTarget,
)
from app.agents.metasploit_executor import MetasploitExecutor
from app.agents.metasploit_rpc import MetasploitRpcError
from app.agents.module_catalog import ModuleMetadata, ModuleOption
from app.agents.planner import ReproductionPlan
from app.agents.research import ResearchResult
from app.targets.material import LocalSource, TargetMaterial
from app.verification.contracts import EvidenceRequirement, VerificationContract

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
FILE_CONTRACT = VerificationContract(
    evidence_requirements=(EvidenceRequirement(
        kind="file_artifact", rule_name="file_artifact_observed",
        description="A new target file is observed.",
    ),),
    result_label="file_write_confirmed",
)


def fixtures(host="172.22.0.4", required=()):
    compose = {"services": {"web": {"image": "example/web:1", "ports": ["8080:80"]}}}
    target = TargetMaterial(CVE, Path("/vulhub"), Path(f"/vulhub/struts/{CVE}"), None, (), {"compose": compose})
    research = ResearchResult(cve_id=CVE, vulnerability_type="RCE", affected_component="web",
                              vulnerability_summary="RCE", vulnerability_mechanism="RCE",
                              trigger_conditions=["request"], prerequisites=[])
    plan = ReproductionPlan(cve_id=CVE, vulnerability_type="RCE", reproduction_goal="test",
                            target_service="web", prerequisites=[], execution_guidance="Metasploit",
                            verification_goal="verify separately", limitations=[], research_context=research,
                            verification_contract=SESSION_CONTRACT, status="ready")
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
    def __init__(self, fail_execute=False, session=True, fail_connect=False, host="172.22.0.4",
                 payloads=None, results_error=None, results=None, session_type="shell",
                 shell_output="uid=0(root) gid=0(root) groups=0(root)\n", fail_shell=False):
        self.calls, self.fail_execute = [], fail_execute
        self.session, self.fail_connect = session, fail_connect
        self.host = host
        self.session_type = session_type
        self.shell_output = shell_output
        self.fail_shell = fail_shell
        self.session_reads = 0
        self.payloads = payloads if payloads is not None else [
            "linux/x64/meterpreter/reverse_tcp", "cmd/unix/reverse", "cmd/unix/reverse_bash"
        ]
        self.results_error = results_error
        self.results = results if results is not None else {"console": "finished"}
    def call(self, method, *args):
        self.calls.append((method, args))
        if self.fail_connect: raise ConnectionError("RPC offline")
        if method == "module.compatible_payloads":
            return {"payloads": self.payloads}
        if method == "session.list":
            self.session_reads += 1
            return ({"3": {"via_exploit": "multi/http/example", "target_host": self.host,
                           "type": self.session_type}}
                    if self.session and self.session_reads > 1 else {})
        if method == "session.shell_write":
            if self.fail_shell:
                raise RuntimeError("shell write failed")
            return {"result": "success"}
        if method == "session.shell_read":
            if self.fail_shell:
                raise RuntimeError("shell read failed")
            return {"result": self.shell_output}
        if method == "module.execute":
            if self.fail_execute: raise RuntimeError("module rejected")
            return {"job_id": 7, "uuid": "job-7"}
        if method == "module.results":
            if self.results_error:
                response = {"status": "errored", "error": True,
                            "error_message": self.results_error}
                raise MetasploitRpcError(self.results_error, method=method, response=response)
            return {"status": "completed", "result": self.results}
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


def target_with_request(content, *, as_document=True):
    source = LocalSource(Path(f"/vulhub/struts/{CVE}/README.md"), content, "0" * 64)
    return TargetMaterial(
        CVE, Path("/vulhub"), Path(f"/vulhub/struts/{CVE}"),
        source if as_document else None, () if as_document else (source,),
        {"compose": {"services": {"web": {"image": "example/web:1", "ports": ["8080:80"]}}}},
    )


def invoke(execution, module, *, authorized=True, host="172.22.0.4", options=None,
           diagnostics_callback=None, target=None, contract=None):
    fixture_target, plan, endpoint, _ = fixtures(host, module.options[2:] if module else ())
    if contract is not None:
        plan = plan.model_copy(update={"verification_contract": contract})
    return execution.run(plan=plan, target=target or fixture_target, runtime_target=endpoint, run_id="run-1",
                         authorized=authorized, options=options,
                         diagnostics_callback=diagnostics_callback)


def execute_options(rpc):
    return next(args[2] for method, args in rpc.calls if method == "module.execute")


def test_search_select_execute_and_real_events(tmp_path):
    _, _, _, module = fixtures()
    events = []
    execution, _, rpc = agent(module, events=events, evidence_dir=tmp_path)
    result = invoke(execution, module)
    assert result.status == "completed" and result.module_name == module.module_name
    assert result.verification_policy.accepted_rules == ("session_established",)
    assert any(method == "module.execute" for method, _ in rpc.calls)
    assert execute_options(rpc) == {"RHOSTS": "172.22.0.4", "RPORT": "80", "LHOST": "172.22.0.4",
                                    "PAYLOAD": "cmd/unix/reverse_bash"}
    assert {e["type"] for e in events} >= {"module_search_started", "module_candidates_found", "module_selected",
                                           "payload_selected", "module_configuration_started",
                                           "module_configuration_completed", "exploit_started",
                                           "exploit_completed", "session_detected"}
    assert (tmp_path / "execution-result.json").exists()


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


def test_target_uri_is_inferred_from_unique_local_request_without_path_llm():
    _, _, _, module = fixtures(required=[ModuleOption(name="TARGETURI", required=True)])
    execution, _, rpc = agent(module)
    target = target_with_request("POST /upload HTTP/1.1\nHost: localhost")
    result = invoke(execution, module, target=target)
    assert result.status == "completed"
    assert execute_options(rpc)["TARGETURI"] == "/upload"


def test_explicit_target_uri_wins_over_local_request():
    _, _, _, module = fixtures(required=[ModuleOption(name="TARGETURI", required=True)])
    execution, _, rpc = agent(module)
    target = target_with_request("POST /from-readme HTTP/1.1")
    result = invoke(execution, module, target=target, options={"TARGETURI": "/explicit"})
    assert result.status == "completed"
    assert execute_options(rpc)["TARGETURI"] == "/explicit"


def test_multiple_request_paths_fall_back_to_module_default():
    _, _, _, module = fixtures(required=[
        ModuleOption(name="TARGETURI", required=True, current_value="/default"),
    ])
    execution, _, rpc = agent(module)
    target = target_with_request("GET /one HTTP/1.1\nPOST /two HTTP/1.1", as_document=False)
    result = invoke(execution, module, target=target)
    assert result.status == "completed"
    assert execute_options(rpc)["TARGETURI"] == "/default"


def test_ambiguous_required_target_uri_without_default_fails_before_execution():
    _, _, _, module = fixtures(required=[ModuleOption(name="TARGETURI", required=True)])
    execution, _, rpc = agent(module)
    target = target_with_request("GET /one HTTP/1.1\nPOST /two HTTP/1.1")
    result = invoke(execution, module, target=target)
    assert result.status == "failed" and "TARGETURI" in result.errors[0]
    assert not any(call[0] == "module.execute" for call in rpc.calls)


def test_unsafe_extracted_target_uri_is_not_used():
    _, _, _, module = fixtures(required=[
        ModuleOption(name="TARGETURI", required=True, current_value="/safe"),
    ])
    execution, _, rpc = agent(module)
    target = target_with_request("POST //external.example/path HTTP/1.1")
    result = invoke(execution, module, target=target)
    assert result.status == "completed"
    assert execute_options(rpc)["TARGETURI"] == "/safe"


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


def test_target_override_is_rejected():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module)
    assert invoke(execution, module, options={"RHOSTS": "8.8.8.8"}).status == "rejected"
    assert not rpc.calls


def test_payload_and_callback_options_are_allowed():
    _, _, _, module = fixtures(required=[
        ModuleOption(name="SRVHOST", required=True, current_value="0.0.0.0"),
        ModuleOption(name="SRVPORT", required=True, current_value="8080"),
    ])
    execution, _, rpc = agent(module)
    result = invoke(execution, module, options={"PAYLOAD": "cmd/unix/reverse_bash"})
    assert result.status == "completed"
    assert not any(method == "module.compatible_payloads" for method, _ in rpc.calls)
    assert rpc.calls[1][1][2]["PAYLOAD"] == "cmd/unix/reverse_bash"
    assert rpc.calls[1][1][2]["SRVHOST"] == "0.0.0.0"
    assert rpc.calls[1][1][2]["SRVPORT"] == "8080"


def test_payload_is_auto_selected_when_absent_from_basic_module_options():
    _, _, _, module = fixtures()
    module.options = [option for option in module.options if option.name != "PAYLOAD"]
    execution, _, rpc = agent(module)
    result = invoke(execution, module)
    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "cmd/unix/reverse_bash"


def test_explicit_payload_is_allowed_when_absent_from_basic_module_options():
    _, _, _, module = fixtures()
    module.options = [option for option in module.options if option.name != "PAYLOAD"]
    execution, _, rpc = agent(module)
    result = invoke(execution, module, options={"PAYLOAD": "cmd/unix/reverse_bash"})
    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "cmd/unix/reverse_bash"
    assert not any(method == "module.compatible_payloads" for method, _ in rpc.calls)


def test_payload_selection_prefers_bash_over_telnet_dependent_double_reverse():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module, rpc=Rpc(payloads=["cmd/unix/reverse", "cmd/unix/reverse_bash"]))
    result = invoke(execution, module)
    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "cmd/unix/reverse_bash"


def test_payload_selection_fails_without_reliable_compatible_payload():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module, rpc=Rpc(payloads=["java/jsp_shell_bind_tcp"]))
    result = invoke(execution, module)
    assert result.status == "failed"
    assert "No reliable reverse-session payload" in result.errors[0]
    assert not any(method == "module.execute" for method, _ in rpc.calls)


def test_meterpreter_is_used_only_as_deterministic_fallback():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module, rpc=Rpc(payloads=["linux/x64/meterpreter/reverse_tcp"]))
    result = invoke(execution, module)
    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "linux/x64/meterpreter/reverse_tcp"


def test_rpc_failure_preserves_structured_diagnostics():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module, rpc=Rpc(results_error="No session created"))
    result = invoke(execution, module, diagnostics_callback=lambda: {
        "http_status": 413,
        "target_log_tail": "Header is too large >8192\nbadMessage: 413",
    })
    assert result.status == "failed" and result.job_id == 7
    assert result.rpc_result["error_message"] == "No session created"
    assert result.diagnostics["rpc"]["method"] == "module.results"
    assert result.diagnostics["http_status"] == 413
    assert "Header is too large" in result.diagnostics["target_log_tail"]
    assert "No session created" in result.errors[0]


def test_module_default_rport_resolves_multi_port_target():
    target, plan, _, module = fixtures()
    target.attributes["compose"]["services"]["web"]["ports"] = ["5005:5005", "61616:61616", "8161:8161"]
    module.options = [
        ModuleOption(name="RHOSTS", required=True),
        ModuleOption(name="RPORT", required=True, current_value="61616"),
        ModuleOption(name="PAYLOAD", required=False),
    ]
    execution, _, rpc = agent(module)
    resolved_ports = []

    def resolver(port):
        resolved_ports.append(port)
        return RuntimeTarget.from_vulhub(target=target, run_id="run-1", service="web", port=port,
                                         host="172.22.0.4", project="lab-run1", container_id="a" * 64,
                                         network_name="lab-net", network_id="b" * 64)

    result = execution.run(plan=plan, target=target, run_id="run-1", target_resolver=resolver, authorized=True)
    assert result.status == "completed"
    assert resolved_ports == [61616]
    assert execute_options(rpc)["RPORT"] == "61616"


def test_unique_tcp_port_is_used_when_module_has_no_default():
    target, plan, _, module = fixtures()
    target.attributes["compose"]["services"]["web"]["ports"] = ["5353:5353/udp", "8080:80"]
    execution, _, rpc = agent(module)
    resolved_ports = []

    def resolver(port):
        resolved_ports.append(port)
        return RuntimeTarget.from_vulhub(target=target, run_id="run-1", service="web", port=port,
                                         host="172.22.0.4", project="lab-run1", container_id="a" * 64,
                                         network_name="lab-net", network_id="b" * 64)

    result = execution.run(plan=plan, target=target, run_id="run-1", target_resolver=resolver, authorized=True)
    assert result.status == "completed"
    assert resolved_ports == [80]


def test_ambiguous_ports_without_module_default_fail_before_execution():
    target, plan, _, module = fixtures()
    target.attributes["compose"]["services"]["web"]["ports"] = ["5005:5005", "61616:61616"]
    execution, _, rpc = agent(module)

    def resolver(port):
        raise AssertionError(f"ambiguous port must not be resolved: {port}")

    result = execution.run(plan=plan, target=target, run_id="run-1", target_resolver=resolver)
    assert result.status == "failed"
    assert "Cannot infer target port" in result.errors[0]
    assert not any(call[0] == "module.execute" for call in rpc.calls)


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
    assert captured[0].configuration_summary["PAYLOAD"] == "cmd/unix/reverse_bash"
    assert rpc.calls[1][0] == "session.list" and rpc.calls[2][0] == "module.execute"

    execution, _, rpc = agent(module)
    def stale(request):
        return ExecutionAuthorization(**{**request.model_dump(), "target_id": "stale"}, approved=True)
    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorization_callback=stale)
    assert result.status == "rejected"
    assert not any(call[0] == "module.execute" for call in rpc.calls)


def test_command_contract_uses_one_fixed_generic_payload_without_requiring_session():
    module_results = {"command_output": "uid=0(root) gid=0(root) groups=0(root)"}
    _, _, _, module = fixtures(required=[ModuleOption(name="CMD", required=False)])
    rpc = Rpc(session=False, payloads=["cmd/unix/reverse_bash", "cmd/unix/generic"], results=module_results)
    events = []
    execution, _, _ = agent(module, rpc=rpc, events=events)
    result = invoke(execution, module, contract=COMMAND_CONTRACT)
    assert result.status == "completed"
    assert result.session_after == []
    assert result.verification_policy.accepted_rules == ("command_output_match",)
    expectation = result.verification_policy.command_expectations[0]
    assert expectation.source == "builtin:posix-id" and expectation.match_mode == "regex"
    assert execute_options(rpc)["CMD"] == "id"
    assert execute_options(rpc)["PAYLOAD"] == "cmd/unix/generic"
    assert len([call for call in rpc.calls if call[0] == "module.execute"]) == 1
    assert result.command_output_evidence[0]["output"].startswith("uid=0(root)")
    assert result.command_output_evidence[0]["source_detail"] in {
        "module.results.command_output", "module.results.result.command_output",
    }
    frozen = next(event for event in events if event["type"] == "verification_policy_frozen")
    assert frozen["contract"] == COMMAND_CONTRACT.model_dump(mode="json")


def test_command_contract_collects_fixed_id_from_new_shell_session():
    _, _, _, module = fixtures()
    events = []
    execution, _, rpc = agent(module, events=events)
    result = invoke(execution, module, contract=COMMAND_CONTRACT)

    assert result.status == "completed"
    assert result.verification_policy.accepted_rules == ("command_output_match",)
    assert execute_options(rpc)["PAYLOAD"] == "cmd/unix/reverse_bash"
    assert ("session.shell_write", ("3", "id\n")) in rpc.calls
    assert any(method == "session.shell_read" for method, _ in rpc.calls)
    assert result.command_output_evidence[0]["output"].startswith("uid=0(root)")
    assert result.command_output_evidence[0]["session_id"] == "3"
    assert result.command_output_evidence[0]["source_detail"] == "session.shell_read"
    assert any(event["type"] == "command_output_collected" for event in events)


def test_session_command_collector_skips_missing_or_non_shell_sessions():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module, rpc=Rpc(session=False))
    result = invoke(execution, module, contract=COMMAND_CONTRACT)
    assert result.status == "completed" and result.command_output_evidence == []
    assert not any(method.startswith("session.shell_") for method, _ in rpc.calls)

    execution, _, rpc = agent(module, rpc=Rpc(session_type="meterpreter"))
    result = invoke(execution, module, contract=COMMAND_CONTRACT)
    assert result.status == "completed" and result.command_output_evidence == []
    assert not any(method.startswith("session.shell_") for method, _ in rpc.calls)


def test_session_command_collector_failure_does_not_fail_completed_exploit():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module, rpc=Rpc(fail_shell=True))
    result = invoke(execution, module, contract=COMMAND_CONTRACT)
    assert result.status == "completed"
    assert result.command_output_evidence == []
    assert result.diagnostics["command_output"][0]["session_id"] == "3"
    assert "shell write failed" in result.diagnostics["command_output"][0]["error"]


def test_command_contract_rejects_nonfixed_command_without_retry():
    _, _, _, module = fixtures(required=[ModuleOption(name="CMD", required=False)])
    execution, _, rpc = agent(module)
    result = invoke(execution, module, contract=COMMAND_CONTRACT, options={"CMD": "whoami"})
    assert result.status == "failed"
    assert "fixed CMD=id" in result.errors[0]
    assert not any(call[0] == "module.execute" for call in rpc.calls)


def test_command_contract_without_generic_payload_is_unsupported_without_fallback():
    _, _, _, module = fixtures(required=[ModuleOption(name="CMD", required=False)])
    execution, _, rpc = agent(module, rpc=Rpc(payloads=["cmd/unix/reverse_bash"]))
    result = invoke(execution, module, contract=COMMAND_CONTRACT)
    assert result.status == "unsupported"
    assert "cmd/unix/generic" in result.errors[0]
    assert not any(call[0] == "module.execute" for call in rpc.calls)


def test_command_contract_is_bound_to_authorization_policy():
    _, plan, _, module = fixtures(required=[ModuleOption(name="CMD", required=False)])
    plan = plan.model_copy(update={"verification_contract": COMMAND_CONTRACT})
    execution, _, _ = agent(module, rpc=Rpc(
        session=False, payloads=["cmd/unix/reverse_bash", "cmd/unix/generic"],
    ))
    captured = []
    def authorize(request):
        captured.append(request)
        return ExecutionAuthorization(**request.model_dump(), approved=True)
    target, _, endpoint, _ = fixtures(required=[ModuleOption(name="CMD", required=False)])
    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorization_callback=authorize)
    assert result.status == "completed"
    assert captured[0].verification_policy_id == result.verification_policy.policy_id
    assert result.verification_policy.contract == COMMAND_CONTRACT
    assert captured[0].configuration_summary["CMD"] == "id"

    execution, _, rpc = agent(module, rpc=Rpc(
        session=False, payloads=["cmd/unix/reverse_bash", "cmd/unix/generic"],
    ))
    def stale_policy(request):
        return ExecutionAuthorization(**{
            **request.model_dump(), "verification_policy_id": "verification-stale",
        }, approved=True)
    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorization_callback=stale_policy)
    assert result.status == "rejected"
    assert not any(call[0] == "module.execute" for call in rpc.calls)


def file_write_fixture():
    target, plan, endpoint, module = fixtures()
    plan = plan.model_copy(update={
        "vulnerability_type": "File Write",
        "verification_contract": FILE_CONTRACT,
    })
    module.module_name = "exploit/multi/http/apache_activemq_upload_jsp"
    module.options = [
        ModuleOption(name="RHOSTS", required=True),
        ModuleOption(name="RPORT", required=True),
        ModuleOption(name="PAYLOAD", required=False),
        ModuleOption(name="JSP", required=False),
        ModuleOption(name="UploadPath", required=False),
        ModuleOption(name="AutoCleanup", required=False, current_value="true"),
    ]
    return target, plan, endpoint, module


def test_file_write_profile_freezes_options_and_collects_new_artifact():
    target, plan, endpoint, module = file_write_fixture()
    execution, _, rpc = agent(module)
    snapshots = iter([
        {"path_pattern": "/opt/*/webapps/api/vulnforge_probe.jsp", "matches": []},
        {"path_pattern": "/opt/*/webapps/api/vulnforge_probe.jsp", "matches": [{
            "path": "/opt/apache-activemq-5.11.1/webapps/api/vulnforge_probe.jsp",
            "size": 118140,
            "sha256": "c" * 64,
        }]},
    ])
    patterns = []

    def inspect(pattern):
        patterns.append(pattern)
        return next(snapshots)

    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorized=True, file_artifact_inspector=inspect)

    assert result.status == "completed"
    assert result.verification_policy.accepted_rules == ("file_artifact_observed",)
    assert result.verification_policy.file_expectations[0].path_pattern.startswith("/opt/*/webapps/api/")
    assert patterns == ["/opt/*/webapps/api/vulnforge_probe.jsp"] * 2
    options = execute_options(rpc)
    assert options["JSP"] == "vulnforge_probe"
    assert options["UploadPath"] == "api"
    assert options["AutoCleanup"] == "false"
    assert result.file_artifact_evidence[0]["existed_before"] is False
    assert result.file_artifact_evidence[0]["exists_after"] is True
    assert result.file_artifact_evidence[0]["new_files"][0]["path"].endswith("vulnforge_probe.jsp")


def test_file_write_profile_rejects_conflicting_or_missing_profile():
    target, plan, endpoint, module = file_write_fixture()
    execution, _, rpc = agent(module)
    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorized=True, options={"JSP": "other"},
                           file_artifact_inspector=lambda pattern: {"matches": []})
    assert result.status == "failed"
    assert "fixed JSP=vulnforge_probe" in result.errors[0]
    assert not any(call[0] == "module.execute" for call in rpc.calls)

    target, plan, endpoint, module = file_write_fixture()
    module.module_name = "exploit/multi/http/example"
    execution, _, rpc = agent(module)
    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorized=True, file_artifact_inspector=lambda pattern: {"matches": []})
    assert result.status == "unsupported"
    assert "verification profile" in result.errors[0]
    assert not any(call[0] == "module.execute" for call in rpc.calls)
