from copy import deepcopy
import json
from pathlib import Path

import pytest

from app.agents.planner import PlannerAgent, PlannerAgentError
from app.agents.research import ResearchDatabaseProbe, ResearchHttpProbe, ResearchObservation, ResearchResult
from app.agents.runner import AgentRunner
from app.targets.material import TargetMaterial


CVE = "CVE-2017-5638"


class MockModel:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def with_structured_output(self, schema):
        return self

    def invoke(self, messages):
        self.calls.append(messages)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.fixture
def research():
    return ResearchResult(
        cve_id=CVE,
        vulnerability_type="RCE",
        affected_component="Example component",
        vulnerability_summary="The local documentation describes remote command execution.",
        vulnerability_mechanism="The documented input reaches an unsafe command handler.",
        trigger_conditions=["The vulnerable handler receives the documented input."],
        prerequisites=["The affected component must be enabled."],
        limitations=["Runtime readiness has not been checked."],
        observations=[
            ResearchObservation(effect="Remote command execution", evidence_kind="command_output",
                                summary="The fixed id output can be returned.", source="local README",
                                quote="id command output", basis="analysis"),
            ResearchObservation(effect="Interactive access", evidence_kind="session",
                                summary="A shell session may be opened.", source="local README",
                                quote="shell session", basis="analysis"),
        ],
    )


@pytest.fixture
def target():
    # A nonexistent path ensures planning depends entirely on already loaded material.
    return TargetMaterial(
        identifier=CVE,
        root=Path("unused-local-root"),
        environment=Path("unused-local-root/example"),
        document=None,
        supporting_sources=(),
        attributes={"compose": {"services": {
            "web": {"image": "example/web:1", "ports": ["8080:80"]},
            "database": {"image": "example/db:1"},
        }}},
    )


@pytest.fixture
def draft():
    return {
        "cve_id": CVE,
        "vulnerability_type": "RCE",
        "target_service": "web",
        "prerequisite_indices": [0, 1],
        "observation_indices": [0, 1],
        "information_sufficient": True,
        "execution_method": "metasploit",
    }


def plan(research, target, draft, **kwargs):
    model = MockModel(draft)
    result = PlannerAgent(AgentRunner(model)).run(
        cve_id=CVE, research=research, target=target, **kwargs
    )
    return result, model


def test_normal_rce_plan_preserves_context_and_needs_no_files(research, target, draft):
    original_research = research.model_dump()
    original_target = deepcopy(target.attributes)
    result, model = plan(research, target, draft, document_markdown="Local document context.")

    assert result.status == "ready"
    assert result.executable
    assert result.automatic_verification_supported
    requirements = result.verification_contract.evidence_requirements
    assert [(item.kind, item.required) for item in requirements] == [
        ("command_output", True), ("session", False),
    ]
    assert result.verification_contract.result_label == "remote_command_execution"
    assert result.cve_id == CVE
    assert result.target_service == "web"
    assert result.execution_method == "metasploit"
    assert result.prerequisites == research.prerequisites + research.trigger_conditions
    assert "Local document context." in model.calls[0][1][1]
    assert research.limitations[0] in result.limitations
    assert research.model_dump() == original_research
    assert target.attributes == original_target
    assert result.model_dump()["executable"] is True
    assert result.research_context.model_dump() == original_research
    result.research_context.prerequisites.append("Detached context mutation.")
    assert research.model_dump() == original_research


def test_rce_plan_uses_only_implemented_evidence_rules(research, target, draft):
    research.observations = [
        ResearchObservation(
            effect="An out-of-band callback is observed", evidence_kind="oob_callback",
            summary="The callback is visible.", source="local README",
            quote="callback", basis="analysis",
        ),
        ResearchObservation(
            effect="Remote command execution", evidence_kind="command_output",
            summary="The fixed id output is returned.", source="local README",
            quote="id output", basis="analysis",
        ),
        ResearchObservation(
            effect="Tool logs show delivery", evidence_kind="command_output",
            summary="The exploit tool logged delivery.", source="local README",
            quote="tool log", basis="analysis",
        ),
    ]
    draft["observation_indices"] = [1]
    result, model = plan(research, target, draft)

    assert result.status == "ready"
    assert result.executable
    assert [item.kind for item in result.verification_contract.evidence_requirements] == [
        "command_output",
    ]
    prompt = model.calls[0][1][1]
    assert "oob_callback" in prompt
    assert "The exploit tool logged delivery." not in prompt


def test_planner_freezes_random_oob_token_without_blocking_execution(research, target, draft):
    research.observations.insert(0, ResearchObservation(
        effect="An out-of-band callback is observed", evidence_kind="oob_callback",
        summary="The callback is visible.", source="local README",
        quote="callback", basis="analysis",
    ))
    draft["observation_indices"] = [0]
    result, _ = plan(research, target, draft)

    assert result.status == "ready"
    assert result.executable
    assert result.automatic_verification_supported
    expectation = result.verification_contract.oob_expectations[0]
    assert expectation.path == f"/oob/{expectation.token}"
    assert len(expectation.token) >= 16


def test_planner_excludes_implemented_evidence_disallowed_by_type(research, target, draft):
    research.vulnerability_type = "File Write"
    draft["vulnerability_type"] = "File Write"
    research.observations = [
        ResearchObservation(
            effect="HTTP 204 response", evidence_kind="http_response",
            summary="The upload returns HTTP 204.", source="local README",
            quote="204", basis="analysis",
        ),
        ResearchObservation(
            effect="Root shell", evidence_kind="session",
            summary="A root shell is opened.", source="local README",
            quote="root shell", basis="analysis",
        ),
    ]
    draft["observation_indices"] = [1]
    result, model = plan(research, target, draft)

    assert result.status == "ready"
    assert result.executable
    assert not result.automatic_verification_supported
    assert "collector" in result.unsupported_reason
    prompt = json.loads(model.calls[0][1][1])
    assert prompt["observation_options"] == []


@pytest.mark.parametrize("missing", ["affected_component", "description", "trigger_conditions"])
def test_insufficient_research_blocks_even_when_model_claims_ready(research, target, draft, missing):
    if missing == "description":
        research.vulnerability_summary = None
        research.vulnerability_mechanism = None
    elif missing == "trigger_conditions":
        research.trigger_conditions = []
    else:
        research.affected_component = " "
    draft["prerequisite_indices"] = [0]
    result, _ = plan(research, target, draft)
    assert result.status == "blocked"
    assert not result.executable
    assert result.validation_errors


def test_model_can_report_insufficient_context(research, target, draft):
    draft["information_sufficient"] = False
    result, _ = plan(research, target, draft)
    assert result.status == "blocked"
    assert not result.executable


def test_unknown_type_is_blocked(research, target, draft):
    research.vulnerability_type = "Unknown"
    draft["vulnerability_type"] = "Unknown"
    result, _ = plan(research, target, draft)
    assert result.vulnerability_type == "Unknown"
    assert result.status == "blocked"
    assert not result.automatic_verification_supported
    assert not result.executable


def test_sqli_plan_executes_without_database_collector(research, target, draft):
    research.vulnerability_type = "SQLi"
    research.observations = [ResearchObservation(
        effect="SQLi", evidence_kind="database_result",
        summary="The documented database result is observable.",
        source="local README", quote="observable result", basis="analysis",
    )]
    draft["vulnerability_type"] = "SQLi"
    draft["observation_indices"] = [0]
    result, _ = plan(research, target, draft)
    assert result.status == "ready"
    assert result.vulnerability_type == "SQLi"
    assert result.target_service == "web"
    assert result.executable
    assert not result.automatic_verification_supported
    assert result.unsupported_reason in result.limitations
    assert "collector" in result.unsupported_reason


def test_http_response_plan_freezes_source_grounded_probe(research, target, draft):
    research.vulnerability_type = "File Read"
    research.observations = [ResearchObservation(
        effect="The passwd file is returned", evidence_kind="http_response",
        http_probe=ResearchHttpProbe(
            path="/icons/.%2e/%2e%2e/etc/passwd", expected_status=200,
            body_contains="root:x:0:0",
        ),
        summary="The documented file content is returned.", source="local README",
        quote="GET /icons/.%2e/%2e%2e/etc/passwd returns 200 with root:x:0:0",
        basis="explicit",
    )]
    draft["vulnerability_type"] = "File Read"
    draft["observation_indices"] = [0]
    result, model = plan(research, target, draft)

    assert result.automatic_verification_supported
    expectation = result.verification_contract.http_expectations[0]
    assert expectation.path == "/icons/.%2e/%2e%2e/etc/passwd"
    assert expectation.body_contains == "root:x:0:0"
    assert expectation.source == "local README"
    assert json.loads(model.calls[0][1][1])["observation_options"][0]["http_probe"]["expected_status"] == 200


def test_sqli_plan_freezes_exact_database_result_probe(research, target, draft):
    research.vulnerability_type = "SQLi"
    research.observations = [ResearchObservation(
        effect="A database-derived value is returned", evidence_kind="database_result",
        database_probe=ResearchDatabaseProbe(
            http_probe=ResearchHttpProbe(path="/api/users?id=1%27", expected_status=200),
            result_contains="admin@example.test",
        ),
        summary="The documented database value is returned.", source="local README",
        quote="GET /api/users?id=1%27 returns 200 with admin@example.test", basis="explicit",
    )]
    draft["vulnerability_type"] = "SQLi"
    draft["observation_indices"] = [0]
    result, _ = plan(research, target, draft)

    assert result.automatic_verification_supported
    expectation = result.verification_contract.database_results[0]
    assert expectation.result_contains == "admin@example.test"
    assert expectation.probe.body_contains == "admin@example.test"
    assert expectation.probe.path == "/api/users?id=1%27"


def test_auth_bypass_state_change_plan_is_ready(research, target, draft):
    research.vulnerability_type = "Auth Bypass"
    research.observations = [ResearchObservation(
        effect="Authentication bypass", evidence_kind="state_change",
        state_indicator="authentication", state_before="anonymous", state_after="authenticated",
        summary="A forged cookie changes anonymous access to authenticated access.",
        source="local README", quote="logged-in administration page", basis="analysis",
    )]
    draft["vulnerability_type"] = "Auth Bypass"
    draft["observation_indices"] = [0]

    result, model = plan(research, target, draft)

    assert result.status == "ready"
    assert result.vulnerability_type == "Auth Bypass"
    assert result.target_service == "web"
    assert result.automatic_verification_supported
    assert result.executable
    assert result.verification_contract.result_label == "auth_bypass_confirmed"
    assert [item.kind for item in result.verification_contract.evidence_requirements] == ["state_change"]
    assert [(item.indicator, item.before, item.after)
            for item in result.verification_contract.state_changes] == [
        ("authentication", "anonymous", "authenticated"),
    ]
    prompt = json.loads(model.calls[0][1][1])
    assert [item["evidence_kind"] for item in prompt["observation_options"]] == ["state_change"]


def test_file_write_plan_with_file_artifact_is_ready(research, target, draft):
    research.vulnerability_type = "File Write"
    research.observations = [ResearchObservation(
        effect="File Write", evidence_kind="file_artifact",
        artifact_path="/opt/activemq/webapps/api/s.jsp",
        summary="The documented file is created.",
        source="local README", quote="file created", basis="analysis",
    )]
    draft["vulnerability_type"] = "File Write"
    draft["observation_indices"] = [0]
    result, _ = plan(research, target, draft)
    assert result.status == "ready"
    assert result.executable
    assert result.automatic_verification_supported
    assert result.verification_contract.result_label == "file_write_confirmed"


def test_file_write_plan_accepts_multiple_source_grounded_alternatives(research, target, draft):
    research.vulnerability_type = "File Write"
    research.observations = [
        ResearchObservation(
            effect="Cron file written", evidence_kind="file_artifact",
            artifact_path="/etc/cron.d/root",
            summary="The documented cron file is created.",
            source="local README", quote="cron file created", basis="explicit",
        ),
        ResearchObservation(
            effect="JSP file written", evidence_kind="file_artifact",
            artifact_path="/opt/activemq/webapps/api/s.jsp",
            summary="The documented JSP file is created.",
            source="local README", quote="jsp file created", basis="explicit",
        ),
    ]
    draft["vulnerability_type"] = "File Write"
    draft["observation_indices"] = [0, 1]
    draft["acceptance_policy"] = "any"

    result, model = plan(research, target, draft)

    assert result.status == "ready"
    assert len(result.verification_contract.evidence_requirements) == 1
    assert [item.path_pattern for item in result.verification_contract.file_artifacts] == [
        "/etc/cron.d/root", "/opt/activemq/webapps/api/s.jsp",
    ]
    prompt = json.loads(model.calls[0][1][1])
    assert len(prompt["observation_options"]) == 2


@pytest.mark.parametrize("source", ["research", "target"])
def test_input_cve_mismatch_blocks_before_model_call(research, target, draft, source):
    if source == "research":
        research.cve_id = "CVE-2020-1234"
    else:
        from dataclasses import replace
        target = replace(target, identifier="CVE-2020-1234")
    result, model = plan(research, target, draft)
    assert result.status == "blocked"
    assert result.cve_id == CVE
    assert model.calls == []


def test_response_cve_mismatch_is_not_silently_accepted(research, target, draft):
    draft["cve_id"] = "CVE-2020-1234"
    result, _ = plan(research, target, draft)
    assert result.cve_id == CVE
    assert result.status == "blocked"


def test_model_cannot_override_research_type(research, target, draft):
    research.vulnerability_type = "SQLi"
    result, _ = plan(research, target, draft)
    assert result.vulnerability_type == "SQLi"
    assert result.status == "blocked"
    assert not result.automatic_verification_supported


@pytest.mark.parametrize("service", [None, "invented-service", "web:9999"])
def test_service_must_match_compose(research, target, draft, service):
    draft["target_service"] = service
    result, _ = plan(research, target, draft)
    assert result.target_service is None
    assert result.status == "blocked"
    assert not result.executable


@pytest.mark.parametrize("field,value", [
    ("target_port", 9999),
    ("target_image", "invented/image:latest"),
    ("module", "exploit/example/module"),
    ("poc", "print('generated PoC')"),
    ("http_payload", "POST / HTTP/1.1"),
    ("verification_rules", {"session": True}),
    ("execution_guidance", "Run a generated Python PoC as a fallback."),
    ("reproduction_goal", "Use curl against an invented target."),
    ("prerequisites", ["Run a generated PoC first."]),
])
def test_model_cannot_add_execution_instructions_or_target_facts(research, target, draft, field, value):
    draft[field] = value
    result, _ = plan(research, target, draft)
    assert result.status == "blocked"
    assert not result.executable
    assert result.target_service is None
    assert result.validation_errors
    assert "generated Python PoC" not in result.execution_guidance


@pytest.mark.parametrize("method", ["python", "http", "metasploit_then_poc"])
def test_execution_method_is_enforced_by_python(research, target, draft, method):
    draft["execution_method"] = method
    result, _ = plan(research, target, draft)
    assert result.execution_method == "metasploit"
    assert result.status == "blocked"
    assert not result.executable


@pytest.mark.parametrize("indices", [[-1], [99], [True], ["0"]])
def test_prerequisites_must_select_existing_research(research, target, draft, indices):
    draft["prerequisite_indices"] = indices
    result, _ = plan(research, target, draft)
    assert not result.executable
    assert result.status == "blocked"


def test_model_cannot_drop_existing_prerequisites(research, target, draft):
    draft["prerequisite_indices"] = []
    result, _ = plan(research, target, draft)
    assert result.prerequisites == research.prerequisites


@pytest.mark.parametrize("response", [None, [], {}, {"information_sufficient": "yes"}])
def test_invalid_structured_output_returns_blocked_plan(research, target, response):
    result, _ = plan(research, target, response)
    assert result.status == "blocked"
    assert not result.executable


def test_model_failure_raises_without_retry(research, target):
    model = MockModel(RuntimeError("model unavailable"))
    with pytest.raises(PlannerAgentError, match="model call failed"):
        PlannerAgent(AgentRunner(model)).run(cve_id=CVE, research=research, target=target)
    assert len(model.calls) == 1


def test_missing_compose_blocks_before_model_call(research, target, draft):
    target.attributes.clear()
    result, model = plan(research, target, draft)
    assert result.status == "blocked"
    assert model.calls == []




def test_command_output_only_plan_does_not_require_session(research, target, draft):
    draft["observation_indices"] = [0]
    result, _ = plan(research, target, draft)
    assert result.status == "ready" and result.executable
    requirements = result.verification_contract.evidence_requirements
    assert len(requirements) == 1
    assert requirements[0].kind == "command_output" and requirements[0].required


def test_all_acceptance_policy_makes_each_selected_observation_required(research, target, draft):
    draft["acceptance_policy"] = "all"
    result, _ = plan(research, target, draft)
    assert result.status == "ready"
    assert result.verification_contract.acceptance_policy == "all"
    assert all(item.required for item in result.verification_contract.evidence_requirements)


def test_session_only_selection_is_promoted_to_required(research, target, draft):
    draft["observation_indices"] = [1]
    result, _ = plan(research, target, draft)
    assert result.status == "ready"
    requirement = result.verification_contract.evidence_requirements[0]
    assert requirement.kind == "session" and requirement.required


@pytest.mark.parametrize("indices", [[-1], [99]])
def test_invalid_observation_indices_only_limit_verification(research, target, draft, indices):
    draft["observation_indices"] = indices
    result, _ = plan(research, target, draft)
    assert result.status == "ready"
    assert result.executable
    assert result.validation_errors == []
    assert any("观察索引" in error for error in result.limitations)


@pytest.mark.parametrize("indices", [[True], ["0"]])
def test_invalid_observation_index_types_block_plan(research, target, draft, indices):
    draft["observation_indices"] = indices
    result, _ = plan(research, target, draft)
    assert result.status == "blocked"
    assert not result.executable


def test_missing_observation_selection_only_limits_verification(research, target, draft):
    draft["observation_indices"] = []
    result, _ = plan(research, target, draft)
    assert result.status == "ready"
    assert result.executable
    assert result.validation_errors == []
    assert any("观察" in error for error in result.limitations)


def test_model_cannot_submit_rule_names_or_patterns(research, target, draft):
    draft["verification_rules"] = [{"rule_name": "always_success", "pattern": ".*"}]
    result, _ = plan(research, target, draft)
    assert result.status == "blocked"
    assert not result.executable


def test_frozen_contract_cannot_be_mutated(research, target, draft):
    from pydantic import ValidationError
    result, _ = plan(research, target, draft)
    with pytest.raises((ValidationError, TypeError)):
        result.verification_contract.acceptance_policy = "all"
    with pytest.raises((ValidationError, TypeError)):
        result.verification_contract.evidence_requirements[0].required = False


def test_optional_session_does_not_choose_any_policy_result_label(research, target, draft):
    research.observations.reverse()
    result, _ = plan(research, target, draft)
    assert result.status == "ready"
    assert [(item.kind, item.required) for item in result.verification_contract.evidence_requirements] == [
        ("session", False), ("command_output", True),
    ]
    assert result.verification_contract.result_label == "remote_command_execution"


def test_duplicate_rule_observation_is_not_offered_to_planner(research, target, draft):
    research.observations[1] = research.observations[0].model_copy(
        update={"summary": "A second command-output effect must be established separately."},
    )
    result, model = plan(research, target, draft)
    assert result.status == "ready"
    assert result.executable
    assert "A second command-output effect" not in model.calls[0][1][1]
    assert any("没有已实现的自动验证规则" in error for error in result.limitations)
