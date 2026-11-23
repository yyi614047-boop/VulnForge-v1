from copy import deepcopy
from pathlib import Path

import pytest

from app.agents.planner import PlannerAgent, PlannerAgentError
from app.agents.research import ResearchResult
from app.agents.runner import AgentRunner
from app.runtime.config import ConfigurationError
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


@pytest.mark.parametrize("vulnerability_type", ["SQLi", "File Write"])
def test_non_rce_plan_retains_research_but_is_unsupported(research, target, draft, vulnerability_type):
    research.vulnerability_type = vulnerability_type
    draft["vulnerability_type"] = vulnerability_type
    result, _ = plan(research, target, draft)
    assert result.status == "unsupported"
    assert result.vulnerability_type == vulnerability_type
    assert result.target_service == "web"
    assert not result.automatic_verification_supported
    assert not result.executable
    assert "V1 automatic verification supports RCE only." in result.limitations


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


def test_missing_model_configuration_uses_shared_factory(monkeypatch):
    monkeypatch.delenv("VULNFORGE_MODEL", raising=False)
    with pytest.raises(ConfigurationError, match="VULNFORGE_MODEL"):
        PlannerAgent.from_environment()
