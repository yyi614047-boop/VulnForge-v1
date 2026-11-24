import json
from pathlib import Path

import pytest

from app.agents.execution import (
    DISABLED_VERIFICATION_POLICY_ID, ExecutionAgent, ExecutionAuthorization, RuntimeTarget,
)
from app.agents.metasploit_executor import MetasploitExecutor
from app.agents.metasploit_rpc import MetasploitRpcError
from app.agents.module_catalog import ModuleDelivery, ModuleMetadata, ModuleOption, PayloadMetadata
from app.agents.planner import ReproductionPlan
from app.agents.research import ResearchResult
from app.targets.material import LocalSource, TargetMaterial
from app.verification.contracts import EvidenceRequirement, FileArtifactExpectation, StateChangeExpectation, VerificationContract

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
    file_artifacts=(FileArtifactExpectation(
        path_pattern="/opt/activemq/webapps/api/s.jsp",
        source="local README",
    ),),
)
STATE_CONTRACT = VerificationContract(
    evidence_requirements=(EvidenceRequirement(
        kind="state_change", rule_name="state_change_observed",
        description="Anonymous access changes to authenticated access.",
    ),),
    result_label="auth_bypass_confirmed",
    state_changes=(StateChangeExpectation(
        indicator="authentication",
        before="anonymous",
        after="authenticated",
        source="local README",
    ),),
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
    def inspect_payloads(self, names):
        return {}


class Rpc:
    def __init__(self, fail_execute=False, session=True, fail_connect=False, host="172.22.0.4",
                 payloads=None, results_error=None, results=None, session_type="shell",
                 shell_output="uid=0(root) gid=0(root) groups=0(root)\n", fail_shell=False,
                 fail_execute_once=False, job_status="completed"):
        self.calls, self.fail_execute = [], fail_execute
        self.fail_execute_once = fail_execute_once
        self.job_status = job_status
        self.execute_attempts = 0
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
            self.execute_attempts += 1
            if self.fail_execute or (self.fail_execute_once and self.execute_attempts == 1):
                raise RuntimeError("module rejected")
            return {"job_id": 7, "uuid": "job-7"}
        if method == "module.results":
            if self.results_error:
                response = {"status": "errored", "error": True,
                            "error_message": self.results_error}
                raise MetasploitRpcError(self.results_error, method=method, response=response)
            return {"status": self.job_status, "result": self.results}
        return {}


def configured_payload(input_text):
    supplied = json.loads(input_text)
    candidates = supplied.get("compatible_payloads", [])
    for hint in supplied.get("payload_hints", []):
        if hint.get("payload_name") in candidates:
            return hint["payload_name"]
    contract = supplied.get("plan", {}).get("verification_contract") or {}
    option_names = {item.get("name") for item in supplied.get("module", {}).get("options", [])}
    if (any(item.get("kind") == "command_output" and item.get("required")
            for item in contract.get("evidence_requirements", [])) and "CMD" in option_names):
        return "cmd/unix/generic" if "cmd/unix/generic" in candidates else None
    platforms = {item.casefold() for item in supplied.get("module", {}).get("platforms", [])}
    if "java" in platforms and "java/jsp_shell_reverse_tcp" in candidates:
        return "java/jsp_shell_reverse_tcp"
    for preferred in ("cmd/unix/reverse_bash", "cmd/unix/reverse_python", "cmd/unix/reverse"):
        if preferred in candidates:
            return preferred
    for preferred in ("linux/x64/meterpreter/reverse_tcp", "java/jsp_shell_reverse_tcp",
                      "generic/shell_reverse_tcp"):
        if preferred in candidates:
            return preferred
    return next((name for name in candidates if "reverse_tcp" in name), None)


class Selector:
    def __init__(self, selected): self.selected = selected
    def run(self, **kwargs):
        schema = kwargs["result_schema"]
        if schema.__name__ == "_Selection":
            return schema(module_name=self.selected)
        if schema.__name__ == "ModuleConfigurationDecision":
            payload = configured_payload(kwargs["input_text"])
            overrides = {"PAYLOAD": payload} if payload else {}
            return schema(option_overrides=overrides, rationale="Selected from supplied payload evidence.")
        raise AssertionError(f"Unexpected schema: {schema.__name__}")


class RetryRunner:
    def __init__(self, selected, decisions):
        self.selected = selected
        self.decisions = list(decisions)
        self.review_calls = 0
        self.review_inputs = []

    def run(self, **kwargs):
        schema = kwargs["result_schema"]
        if schema.__name__ == "_Selection":
            return schema(module_name=self.selected)
        if schema.__name__ == "ModuleConfigurationDecision":
            payload = configured_payload(kwargs["input_text"])
            overrides = {"PAYLOAD": payload} if payload else {}
            return schema(option_overrides=overrides, rationale="Selected from supplied payload evidence.")
        self.review_calls += 1
        self.review_inputs.append(json.loads(kwargs["input_text"]))
        decision = self.decisions.pop(0)
        return schema.model_validate(decision)


class ConfigurationRunner:
    def __init__(self, overrides, *, supported=True, unsupported_reason=None):
        self.overrides = overrides
        self.supported = supported
        self.unsupported_reason = unsupported_reason
        self.inputs = {}

    def run(self, **kwargs):
        schema = kwargs["result_schema"]
        payload = json.loads(kwargs["input_text"])
        if schema.__name__ == "_Selection":
            self.inputs["selection"] = payload
            return schema(module_name="exploit/multi/http/example")
        if schema.__name__ == "ModuleConfigurationDecision":
            self.inputs["configuration"] = payload
            overrides = dict(self.overrides)
            selected_payload = configured_payload(kwargs["input_text"])
            if selected_payload and "PAYLOAD" not in overrides:
                overrides["PAYLOAD"] = selected_payload
            return schema(option_overrides=overrides,
                          supported=self.supported,
                          unsupported_reason=self.unsupported_reason,
                          rationale="Compose values from the supplied runtime facts and PoC hint.")
        raise AssertionError(f"Unexpected schema: {schema.__name__}")


def agent(module, *, names=None, selected=None, rpc=None, events=None, required=(), evidence_dir=None,
          max_attempts=3, runner=None):
    search = Search(module, names)
    rpc = rpc or Rpc()
    return ExecutionAgent(search, MetasploitExecutor(rpc, poll_interval=0),
                          runner=runner or Selector(selected if selected is not None else (module.module_name if module else None)),
                          event_sink=(events if events is not None else []).append, evidence_dir=evidence_dir,
                          max_attempts=max_attempts), search, rpc


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


def test_state_change_contract_collects_structured_rpc_evidence():
    target, plan, endpoint, module = fixtures()
    research = plan.research_context.model_copy(update={"vulnerability_type": "Auth Bypass"})
    plan = plan.model_copy(update={
        "vulnerability_type": "Auth Bypass",
        "research_context": research,
        "verification_contract": STATE_CONTRACT,
    })
    module = module.model_copy(update={
        "session_capable": False,
        "options": [item for item in module.options if item.name != "PAYLOAD"],
    })
    rpc = Rpc(session=False, results={
        "state_change": {
            "indicator": "authentication",
            "before": "anonymous",
            "after": "authenticated",
        },
    })
    events = []
    execution, _, _ = agent(module, rpc=rpc, events=events)

    result = execution.run(plan=plan, target=target, runtime_target=endpoint,
                           run_id="run-1", authorized=True)

    assert result.status == "completed"
    assert result.verification_policy.accepted_rules == ("state_change_observed",)
    assert result.state_change_evidence == [{
        "source": "metasploit_rpc_state_change",
        "execution_id": result.execution_id,
        "target_id": endpoint.container_id,
        "indicator": "authentication",
        "before": "anonymous",
        "after": "authenticated",
        "source_detail": "module.results.result.state_change",
    }]
    assert any(item.stage == "state_change" for item in result.observations)
    assert any(event["type"] == "state_change_collected" for event in events)
    assert "PAYLOAD" not in execute_options(rpc)


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


def test_execution_without_verification_contract_runs_with_bound_authorization():
    target, plan, endpoint, module = fixtures()
    plan = plan.model_copy(update={
        "verification_contract": None,
        "unsupported_reason": "No trusted evidence collector is implemented.",
    })
    events = []
    execution, _, rpc = agent(module, events=events)
    captured = []

    def authorize(request):
        captured.append(request)
        return ExecutionAuthorization(**request.model_dump(), approved=True)

    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorization_callback=authorize)

    assert result.status == "completed"
    assert result.verification_policy is None
    assert result.session_evidence
    assert captured[0].verification_policy_id == DISABLED_VERIFICATION_POLICY_ID
    assert execute_options(rpc)["PAYLOAD"] == "cmd/unix/reverse_bash"
    assert not any(event["type"] == "verification_policy_frozen" for event in events)


def test_empty_search_is_unsupported():
    execution, _, rpc = agent(None)
    result = invoke(execution, None)
    assert result.status == "unsupported" and not rpc.calls


def test_one_click_ignores_model_module_selection_for_exact_candidate():
    _, _, _, module = fixtures()
    execution, search, rpc = agent(module, selected="exploit/linux/fake")
    result = invoke(execution, module)
    assert result.status == "completed"
    assert result.module_name == module.module_name
    assert search.inspected == [module.module_name]
    assert any(method == "module.execute" for method, _ in rpc.calls)
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


def test_module_configurator_composes_validated_options_from_hints_and_runtime():
    _, _, _, module = fixtures(required=[
        ModuleOption(name="TARGETURI", required=True),
        ModuleOption(name="VHOST", required=False),
    ])
    runner = ConfigurationRunner({
        "TARGETURI": "/api/upload",
        "VHOST": "{{target_host}}",
        "FAKE": "ignored",
        "RHOSTS": "8.8.8.8",
    })
    events = []
    execution, _, rpc = agent(module, runner=runner, events=events)
    target = target_with_request("PUT /api/upload HTTP/1.1\nHost: localhost")

    result = invoke(execution, module, target=target)

    assert result.status == "completed"
    options = execute_options(rpc)
    assert options["TARGETURI"] == "/api/upload"
    assert options["VHOST"] == "172.22.0.4"
    assert options["RHOSTS"] == "172.22.0.4"
    assert "FAKE" not in options
    assert "selection" not in runner.inputs
    assert runner.inputs["configuration"]["document_markdown"] == ""
    assert runner.inputs["configuration"]["runtime_target"]["host"] == "172.22.0.4"
    assert runner.inputs["configuration"]["poc_hints"][0]["content"].startswith("PUT /api/upload")
    composed = next(event for event in events if event["type"] == "module_parameter_composition_completed")
    assert composed["ignored_options"] == ["FAKE", "RHOSTS"]


def test_default_configuration_does_not_require_configurator_approval():
    _, _, _, module = fixtures()
    runner = ConfigurationRunner(
        {}, supported=False,
        unsupported_reason="Not needed when module defaults are complete.",
    )
    execution, _, rpc = agent(module, runner=runner)

    result = invoke(execution, module)

    assert result.status == "completed"
    assert runner.inputs == {}
    assert any(call[0] == "module.execute" for call in rpc.calls)


def test_explicit_user_options_override_agent_composition():
    _, _, _, module = fixtures(required=[
        ModuleOption(name="TARGETURI", required=True),
        ModuleOption(name="VHOST", required=False),
    ])
    runner = ConfigurationRunner({
        "TARGETURI": "/agent",
        "VHOST": "{{target_host}}",
    })
    execution, _, rpc = agent(module, runner=runner)

    result = invoke(execution, module, options={"TARGETURI": "/explicit", "VHOST": "explicit.example"})

    assert result.status == "completed"
    options = execute_options(rpc)
    assert options["TARGETURI"] == "/explicit"
    assert options["VHOST"] == "explicit.example"


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
    assert result.success_basis == "job_completed"


def test_errored_job_with_new_session_is_still_successful():
    _, _, _, module = fixtures()
    execution, _, _ = agent(module, rpc=Rpc(job_status="errored"))

    result = invoke(execution, module)

    assert result.status == "completed"
    assert result.job_status == "errored"
    assert result.success_basis == "session_established"
    assert result.session_evidence
    assert result.errors == []
    job_observation = next(item for item in result.observations if item.source == "metasploit_rpc_job")
    assert job_observation.status == "observed"
    assert job_observation.data["success_basis"] == "session_established"


def test_target_override_is_rejected():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module)
    assert invoke(execution, module, options={"RHOSTS": "8.8.8.8"}).status == "rejected"
    assert not any(call[0] == "module.execute" for call in rpc.calls)


def test_payload_and_callback_options_are_allowed():
    _, _, _, module = fixtures(required=[
        ModuleOption(name="SRVHOST", required=True, current_value="0.0.0.0"),
        ModuleOption(name="SRVPORT", required=True, current_value="8080"),
    ])
    execution, _, rpc = agent(module)
    result = invoke(execution, module, options={"PAYLOAD": "cmd/unix/reverse_bash"})
    assert result.status == "completed"
    assert result.compatible_payloads
    options = execute_options(rpc)
    assert options["PAYLOAD"] == "cmd/unix/reverse_bash"
    assert options["SRVHOST"] == "0.0.0.0"
    assert options["SRVPORT"] == "8080"


def test_payload_omission_uses_metasploit_compatible_default():
    _, _, _, module = fixtures()

    class NoPayloadRunner:
        def run(self, **kwargs):
            schema = kwargs["result_schema"]
            if schema.__name__ == "_Selection":
                return schema(module_name=module.module_name)
            return schema(option_overrides={}, rationale="No payload selected.")

    execution, _, rpc = agent(module, runner=NoPayloadRunner(), max_attempts=1)

    result = invoke(execution, module)

    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "cmd/unix/reverse_bash"


def test_agent_selects_payload_when_absent_from_basic_module_options():
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
    assert result.compatible_payloads


def test_java_module_prefers_platform_payload_and_records_catalog_facts():
    _, _, _, module = fixtures()
    module.platforms = ["Java", "Linux", "Windows"]
    rpc = Rpc(payloads=["generic/shell_reverse_tcp", "java/jsp_shell_reverse_tcp"])
    execution, _, _ = agent(module, rpc=rpc)

    result = invoke(execution, module)

    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "java/jsp_shell_reverse_tcp"
    assert "java/jsp_shell_reverse_tcp" in result.compatible_payloads
    catalog = next(item for item in result.observations if item.source == "metasploit_catalog")
    assert catalog.data["modules"][0]["platforms"] == ["Java", "Linux", "Windows"]
    payloads = next(item for item in result.observations if item.source == "metasploit_compatible_payloads")
    assert "generic/shell_reverse_tcp" in payloads.data["platform_compatible_payloads"]
    assert "payloads" not in payloads.data


def test_payload_absent_from_compatible_list_is_rejected_before_execution():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module, rpc=Rpc(payloads=["cmd/unix/reverse_bash"]))

    result = invoke(execution, module, options={"PAYLOAD": "java/fake_reverse_tcp"})

    assert result.status == "failed"
    assert "compatible payload list" in result.errors[0]
    assert not any(call[0] == "module.execute" for call in rpc.calls)
    assert result.config_parameters == {}


def test_payload_selection_prefers_bash_over_telnet_dependent_double_reverse():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module, rpc=Rpc(payloads=["cmd/unix/reverse", "cmd/unix/reverse_bash"]))
    result = invoke(execution, module)
    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "cmd/unix/reverse_bash"


def test_non_reverse_payload_compatibility_is_delegated_to_metasploit():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module, rpc=Rpc(payloads=["java/jsp_shell_bind_tcp"]))
    result = invoke(execution, module)
    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "java/jsp_shell_bind_tcp"


def test_meterpreter_is_used_only_as_deterministic_fallback():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module, rpc=Rpc(payloads=["linux/x64/meterpreter/reverse_tcp"]))
    result = invoke(execution, module)
    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "linux/x64/meterpreter/reverse_tcp"


def test_rpc_failure_preserves_structured_diagnostics():
    _, _, _, module = fixtures()
    execution, _, rpc = agent(module, rpc=Rpc(results_error="No session created", session=False))
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


def test_documented_payload_and_runtime_platform_drive_configuration():
    target, plan, endpoint, module = fixtures()
    endpoint = endpoint.model_copy(update={"os": "linux", "architecture": "amd64"})
    module = module.model_copy(update={
        "platforms": ["Linux", "Windows"],
        "architectures": ["x64"],
        "targets": ["Windows", "Linux"],
        "target_ids": [4, 7],
    })
    documented = "use exploit/multi/http/example\nset PAYLOAD linux/x64/meterpreter/reverse_tcp\nrun"
    target = target_with_request(documented)
    rpc = Rpc(payloads=[
        "windows/x64/meterpreter/reverse_tcp",
        "cmd/unix/reverse_bash",
        "linux/x64/meterpreter/reverse_tcp",
    ])
    runner = ConfigurationRunner({})
    execution, _, _ = agent(module, rpc=rpc, runner=runner, max_attempts=1)

    result = execution.run(plan=plan, target=target, runtime_target=endpoint,
                           run_id="run-1", authorized=True)

    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "linux/x64/meterpreter/reverse_tcp"
    assert execute_options(rpc)["TARGET"] == "7"
    assert runner.inputs == {}


def test_explicit_compatible_cross_platform_payload_is_delegated_to_metasploit():
    target, plan, endpoint, module = fixtures()
    endpoint = endpoint.model_copy(update={"os": "linux", "architecture": "amd64"})
    module = module.model_copy(update={"platforms": ["Linux", "Windows"]})
    rpc = Rpc(payloads=["windows/x64/meterpreter/reverse_tcp", "cmd/unix/reverse_bash"])
    execution, _, _ = agent(module, rpc=rpc, max_attempts=1)

    result = execution.run(plan=plan, target=target, runtime_target=endpoint,
                           run_id="run-1", authorized=True,
                           options={"PAYLOAD": "windows/x64/meterpreter/reverse_tcp"})

    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "windows/x64/meterpreter/reverse_tcp"


def test_java_payload_is_compatible_with_linux_container():
    target, plan, endpoint, module = fixtures()
    endpoint = endpoint.model_copy(update={"os": "linux", "architecture": "amd64"})
    module = module.model_copy(update={"platforms": ["Java", "Linux"],
                                      "architectures": ["java", "x86"],
                                      "targets": ["Windows", "Linux", "Java Universal"],
                                      "target_ids": [4, 7, 9]})
    rpc = Rpc(payloads=["cmd/unix/reverse_bash", "java/jsp_shell_reverse_tcp"])
    execution, _, _ = agent(module, rpc=rpc, max_attempts=1)

    result = execution.run(plan=plan, target=target, runtime_target=endpoint,
                           run_id="run-1", authorized=True)

    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "java/jsp_shell_reverse_tcp"
    assert execute_options(rpc)["TARGET"] == "9"


def test_native_meterpreter_is_preferred_over_generic_shell():
    target, plan, endpoint, module = fixtures()
    endpoint = endpoint.model_copy(update={"os": "linux", "architecture": "amd64"})
    module = module.model_copy(update={"platforms": ["Linux"], "architectures": ["x64"]})
    rpc = Rpc(payloads=["generic/shell_reverse_tcp", "linux/x64/meterpreter/reverse_sctp",
                        "linux/x64/meterpreter/reverse_tcp"])
    execution, _, _ = agent(module, rpc=rpc, max_attempts=1)

    result = execution.run(plan=plan, target=target, runtime_target=endpoint,
                           run_id="run-1", authorized=True)

    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "linux/x64/meterpreter/reverse_tcp"


def test_payload_delivery_compatibility_is_delegated_to_metasploit():
    target, plan, endpoint, module = fixtures()
    endpoint = endpoint.model_copy(update={"os": "linux", "architecture": "amd64"})
    module = module.model_copy(update={
        "platforms": ["Java"],
        "architectures": ["java"],
        "delivery": ModuleDelivery(artifact="jar", required_entry_class="metasploit.Payload",
                                   trigger="http_request"),
    })
    contracts = {
        "java/jsp_shell_reverse_tcp": PayloadMetadata(
            name="java/jsp_shell_reverse_tcp", artifact="jsp", transport="reverse_tcp"),
        "java/meterpreter_reverse_tcp": PayloadMetadata(
            name="java/meterpreter_reverse_tcp", artifact="jar",
            entry_class="com.metasploit.meterpreter.StagelessMain", transport="reverse_tcp"),
        "java/shell_reverse_tcp": PayloadMetadata(
            name="java/shell_reverse_tcp", artifact="jar", entry_class="metasploit.Payload",
            transport="reverse_tcp"),
    }
    rpc = Rpc(payloads=list(contracts))
    runner = ConfigurationRunner({})
    execution, search, _ = agent(module, rpc=rpc, runner=runner, max_attempts=1)
    search.inspect_payloads = lambda names: {name: contracts[name] for name in names if name in contracts}

    result = execution.run(plan=plan, target=target, runtime_target=endpoint,
                           run_id="run-1", authorized=True)

    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == "java/jsp_shell_reverse_tcp"
    assert runner.inputs == {}


def test_explicit_payload_delivery_is_delegated_to_metasploit():
    target, plan, endpoint, module = fixtures()
    endpoint = endpoint.model_copy(update={"os": "linux", "architecture": "amd64"})
    module = module.model_copy(update={
        "platforms": ["Java"],
        "delivery": ModuleDelivery(artifact="jar", required_entry_class="metasploit.Payload"),
    })
    contract = PayloadMetadata(name="java/jsp_shell_reverse_tcp", artifact="jsp",
                               transport="reverse_tcp")
    rpc = Rpc(payloads=[contract.name, "java/shell_reverse_tcp"])
    execution, search, _ = agent(module, rpc=rpc, max_attempts=1)
    search.inspect_payloads = lambda names: {contract.name: contract}

    result = execution.run(plan=plan, target=target, runtime_target=endpoint,
                           run_id="run-1", authorized=True,
                           options={"PAYLOAD": contract.name})

    assert result.status == "completed"
    assert execute_options(rpc)["PAYLOAD"] == contract.name


def test_http_server_callback_option_is_exposed_without_runtime_override():
    target, plan, endpoint, module = fixtures(required=[
        ModuleOption(name="SRVHOST", required=True, current_value="0.0.0.0"),
        ModuleOption(name="SRVPORT", required=True, current_value="8080"),
    ])
    module = module.model_copy(update={
        "delivery": ModuleDelivery(artifact="raw", callback_options=["SRVHOST"]),
    })
    runner = ConfigurationRunner({"SRVHOST": "0.0.0.0"})
    execution, _, rpc = agent(module, runner=runner, max_attempts=1)

    result = execution.run(plan=plan, target=target, runtime_target=endpoint,
                           run_id="run-1", authorized=True)

    assert result.status == "completed"
    assert execute_options(rpc)["SRVHOST"] == "0.0.0.0"
    assert runner.inputs == {}


def test_retry_preserves_numeric_target_when_changing_another_option():
    target, plan, endpoint, module = fixtures(required=[
        ModuleOption(name="SRVPORT", required=True, current_value="8080"),
    ])
    endpoint = endpoint.model_copy(update={"os": "linux", "architecture": "amd64"})
    module = module.model_copy(update={"targets": ["Windows", "Linux"], "target_ids": [0, 1]})
    runner = RetryRunner(module.module_name, [{
        "action": "retry",
        "module_name": module.module_name,
        "option_overrides": {"SRVPORT": "8081"},
        "reason": "Change only the local HTTP server port.",
    }])
    rpc = Rpc(fail_execute_once=True)
    execution, _, _ = agent(module, rpc=rpc, runner=runner)

    result = execution.run(plan=plan, target=target, runtime_target=endpoint,
                           run_id="run-1", authorized=True)

    assert result.status == "completed"
    calls = [args[2] for method, args in rpc.calls if method == "module.execute"]
    assert calls[0]["TARGET"] == "1"
    assert calls[1]["TARGET"] == "1"
    assert calls[1]["SRVPORT"] == "8081"


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
    module.module_name = "exploit/multi/http/example"
    module.options = [
        ModuleOption(name="RHOSTS", required=True),
        ModuleOption(name="RPORT", required=True),
        ModuleOption(name="PAYLOAD", required=False),
        ModuleOption(name="JSP", required=False),
        ModuleOption(name="UploadPath", required=False),
        ModuleOption(name="AutoCleanup", required=False, current_value="true"),
    ]
    return target, plan, endpoint, module


def test_file_write_agent_composes_options_and_collects_new_artifact():
    target, plan, endpoint, module = file_write_fixture()
    runner = ConfigurationRunner({"JSP": "s", "AutoCleanup": "false"})
    execution, _, rpc = agent(module, runner=runner)
    snapshots = iter([
        {"path_pattern": "/opt/activemq/webapps/api/s.jsp", "matches": []},
        {"path_pattern": "/opt/activemq/webapps/api/s.jsp", "matches": [{
            "path": "/opt/activemq/webapps/api/s.jsp",
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
    assert result.verification_policy.file_expectations[0].path_pattern == "/opt/activemq/webapps/api/s.jsp"
    assert patterns == ["/opt/activemq/webapps/api/s.jsp"] * 2
    options = execute_options(rpc)
    assert "JSP" not in options
    assert "UploadPath" not in options
    assert "AutoCleanup" not in options
    assert runner.inputs == {}
    assert result.file_artifact_evidence[0]["existed_before"] is False
    assert result.file_artifact_evidence[0]["exists_after"] is True
    assert result.file_artifact_evidence[0]["new_files"][0]["path"].endswith("/s.jsp")


def test_failed_job_still_captures_configuration_files_and_structured_observations():
    target, plan, endpoint, module = file_write_fixture()
    runner = ConfigurationRunner({"JSP": "s", "AutoCleanup": "false"})
    rpc = Rpc(session=False, payloads=["generic/shell_reverse_tcp"], results_error="No session created")
    execution, _, _ = agent(module, rpc=rpc, runner=runner)
    snapshots = iter([
        {"path_pattern": "/opt/activemq/webapps/api/s.jsp", "matches": []},
        {"path_pattern": "/opt/activemq/webapps/api/s.jsp", "matches": [{
            "path": "/opt/activemq/webapps/api/s.jsp",
            "size": 118140,
            "sha256": "c" * 64,
        }]},
    ])

    result = execution.run(
        plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
        authorized=True,
        file_artifact_inspector=lambda pattern: next(snapshots),
        diagnostics_callback=lambda: {"target_log_tail": "JSP deployed but callback failed"},
    )

    assert result.status == "failed"
    assert result.job_status == "errored"
    assert result.config_parameters["PAYLOAD"] == "generic/shell_reverse_tcp"
    assert "JSP" not in result.config_parameters
    assert runner.inputs == {}
    assert result.file_artifact_evidence[0]["exists_after"] is True
    assert result.file_artifact_evidence[0]["new_files"][0]["path"].endswith("/s.jsp")
    assert result.verification_policy is not None
    sources = {item.source for item in result.observations}
    assert {"execution_configuration", "metasploit_rpc_job", "target_file_after", "target_logs"} <= sources
    assert any(item.source == "execution_error" for item in result.observations) is False
    assert result.attempt_history[0]["observation_count"] == len(result.observations)


def test_unavailable_file_baseline_does_not_block_authorized_execution():
    target, plan, endpoint, module = file_write_fixture()
    execution, _, rpc = agent(module)

    def unavailable(pattern):
        raise RuntimeError("File artifact root is outside the allowed local target paths")

    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorized=True, file_artifact_inspector=unavailable)
    assert result.status == "completed"
    assert any(method == "module.execute" for method, _ in rpc.calls)
    assert result.verification_policy.unsupported_reason
    assert any(item.source == "target_file_baseline_unavailable" for item in result.observations)


def test_file_write_missing_expectation_degrades_verification_without_blocking_execution():
    target, plan, endpoint, module = file_write_fixture()
    execution, _, rpc = agent(module)
    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorized=True, options={"JSP": "other"},
                           file_artifact_inspector=lambda pattern: {"matches": []})
    assert result.status == "completed"
    assert execute_options(rpc)["JSP"] == "other"
    assert any(call[0] == "module.execute" for call in rpc.calls)

    target, plan, endpoint, module = file_write_fixture()
    contract = FILE_CONTRACT.model_copy(update={"file_artifacts": ()})
    plan = plan.model_copy(update={"verification_contract": contract})
    execution, _, rpc = agent(module)
    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorized=True, file_artifact_inspector=lambda pattern: {"matches": []})
    assert result.status == "completed"
    assert result.verification_policy.unsupported_reason
    assert any(call[0] == "module.execute" for call in rpc.calls)


def test_retry_reviewer_sees_poc_hints_and_resolves_runtime_templates():
    _, _, _, module = fixtures(required=[ModuleOption(name="TARGETURI", required=True)])
    runner = RetryRunner(module.module_name, [{
        "action": "retry",
        "module_name": module.module_name,
        "option_overrides": {"TARGETURI": "/{{service}}/retry"},
        "reason": "The local PoC hint and runtime service support this retry path.",
    }])
    execution, _, rpc = agent(module, rpc=Rpc(fail_execute_once=True), runner=runner)
    target, plan, endpoint, _ = fixtures(required=[ModuleOption(name="TARGETURI", required=True)])
    target = target_with_request("PUT /first HTTP/1.1\nHost: localhost")

    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorized=True)

    assert result.status == "completed"
    execute_calls = [args[2] for method, args in rpc.calls if method == "module.execute"]
    assert execute_calls[1]["TARGETURI"] == "/web/retry"
    review = runner.review_inputs[0]
    assert review["runtime_target"]["service"] == "web"
    assert review["poc_hints"][0]["content"].startswith("PUT /first")
    assert review["compatible_payloads"]
    assert all("description" not in candidate for candidate in review["candidates"])
    assert review["last_attempt"]["config_parameters"]["PAYLOAD"] == "cmd/unix/reverse_bash"
    assert any(item["source"] == "execution_error" for item in review["observations"])


def test_agent_loop_retries_same_module_with_reauthorization():
    _, _, _, module = fixtures(required=[ModuleOption(name="TARGETURI", required=False)])
    runner = RetryRunner(module.module_name, [{
        "action": "retry",
        "module_name": module.module_name,
        "option_overrides": {"TARGETURI": "/retry"},
        "reason": "The first request path failed; use the documented retry path.",
    }])
    rpc = Rpc(fail_execute_once=True)
    execution, _, _ = agent(module, rpc=rpc, runner=runner)
    target, plan, endpoint, _ = fixtures(required=[ModuleOption(name="TARGETURI", required=False)])
    approvals = []

    def authorize(request):
        approvals.append(request)
        return ExecutionAuthorization(**request.model_dump(), approved=True)

    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorization_callback=authorize)

    assert result.status == "completed"
    assert result.attempt == 2
    assert len(result.attempt_history) == 2
    assert len(approvals) == 2
    assert approvals[0].configuration_fingerprint != approvals[1].configuration_fingerprint
    execute_calls = [args[2] for method, args in rpc.calls if method == "module.execute"]
    assert len(execute_calls) == 2
    assert execute_calls[1]["TARGETURI"] == "/retry"
    assert runner.review_calls == 1


def test_agent_loop_can_select_alternative_real_candidate():
    _, _, _, first = fixtures()
    second = first.model_copy(deep=True, update={"module_name": "exploit/multi/http/second"})

    class MultiSearch:
        def search(self, cve):
            return [first.module_name, second.module_name]

        def inspect(self, cve, name):
            return first if name == first.module_name else second
        def inspect_payloads(self, names):
            return {}

    runner = RetryRunner(first.module_name, [{
        "action": "next_module",
        "module_name": second.module_name,
        "option_overrides": {"PAYLOAD": "cmd/unix/reverse_bash"},
        "reason": "The first module failed; the second candidate has compatible metadata.",
    }])
    rpc = Rpc(fail_execute_once=True)
    execution = ExecutionAgent(MultiSearch(), MetasploitExecutor(rpc, poll_interval=0),
                               runner=runner, max_attempts=2)
    target, plan, endpoint, _ = fixtures()
    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorized=True)
    assert result.status == "completed"
    assert result.module_name == second.module_name
    assert result.attempt == 2
    assert len([call for call in rpc.calls if call[0] == "module.execute"]) == 2


def test_agent_loop_stops_on_invalid_retry_or_authorization_denial():
    _, _, _, module = fixtures(required=[ModuleOption(name="TARGETURI", required=False)])
    runner = RetryRunner(module.module_name, [{
        "action": "retry",
        "module_name": module.module_name,
        "option_overrides": {"INVENTED": "value"},
        "reason": "Invalid option proposal.",
    }])
    rpc = Rpc(fail_execute_once=True)
    execution, _, _ = agent(module, rpc=rpc, runner=runner)
    target, plan, endpoint, _ = fixtures(required=[ModuleOption(name="TARGETURI", required=False)])
    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorized=True)
    assert result.status == "failed"
    assert result.attempt == 1
    assert "absent from module metadata" in result.diagnostics["retry_controller"]["error"]
    assert len([call for call in rpc.calls if call[0] == "module.execute"]) == 1

    runner = RetryRunner(module.module_name, [{
        "action": "retry",
        "module_name": module.module_name,
        "option_overrides": {"TARGETURI": "/retry"},
        "reason": "Retry with a different path.",
    }])
    rpc = Rpc(fail_execute_once=True)
    execution, _, _ = agent(module, rpc=rpc, runner=runner)
    approvals = []

    def authorize(request):
        approvals.append(request)
        return ExecutionAuthorization(**request.model_dump(), approved=len(approvals) == 1)

    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorization_callback=authorize)
    assert result.status == "rejected"
    assert result.attempt == 2
    assert len(approvals) == 2
    assert len([call for call in rpc.calls if call[0] == "module.execute"]) == 1


def test_agent_loop_respects_max_attempts():
    _, _, _, module = fixtures(required=[ModuleOption(name="TARGETURI", required=False)])
    runner = RetryRunner(module.module_name, [
        {"action": "retry", "module_name": module.module_name,
         "option_overrides": {"TARGETURI": "/one"}, "reason": "Retry one."},
        {"action": "retry", "module_name": module.module_name,
         "option_overrides": {"TARGETURI": "/two"}, "reason": "Retry two."},
    ])
    rpc = Rpc(fail_execute=True)
    execution, _, _ = agent(module, rpc=rpc, runner=runner, max_attempts=3)
    target, plan, endpoint, _ = fixtures(required=[ModuleOption(name="TARGETURI", required=False)])
    result = execution.run(plan=plan, target=target, runtime_target=endpoint, run_id="run-1",
                           authorized=True)
    assert result.status == "failed"
    assert result.attempt == 3
    assert len(result.attempt_history) == 3
    assert len([call for call in rpc.calls if call[0] == "module.execute"]) == 3
