from pathlib import Path

import pytest

from app.agents.research import ResearchAgent, ResearchAgentError
from app.agents.runner import AgentRunner
from app.targets.vulhub.loader import load_target


CVE = "CVE-2017-5638"


class FakeModel:
    def __init__(self, response):
        self.response = response
        self.messages = None
        self.schema = None

    def with_structured_output(self, schema):
        self.schema = schema
        return self

    def invoke(self, messages):
        self.messages = messages
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def make_target(tmp_path: Path, *, compose: str, readme: str | None = None):
    root = tmp_path / "vulhub"
    environment = root / "apache" / CVE
    environment.mkdir(parents=True)
    (environment / "docker-compose.yml").write_text(compose, encoding="utf-8")
    if readme is not None:
        (environment / "README.md").write_text(readme, encoding="utf-8")
    return load_target(root, CVE)


def run_with(target, document, response):
    model = FakeModel(response)
    result = ResearchAgent(AgentRunner(model)).run(
        cve_id=CVE,
        document_markdown=document,
        target=target,
    )
    return result, model


def test_researches_document_markdown_and_supplied_target_context(tmp_path):
    markdown = "Apache Struts 2.3.5 can execute a command when parsing a crafted multipart request."
    target = make_target(
        tmp_path,
        compose="services:\n  web:\n    image: example/struts:2.3.5\n    ports:\n      - 8080:8080\n",
    )
    response = {
        "cve_id": CVE,
        "vulnerability_type": "RCE",
        "affected_component": "Apache Struts 2.3.5",
        "vulnerability_summary": "A crafted multipart request can execute a command.",
        "vulnerability_mechanism": None,
        "trigger_conditions": ["A crafted multipart request is parsed."],
        "prerequisites": [],
        "limitations": [],
        "evidence": [
            {
                "field": "vulnerability_type",
                "claim": "RCE",
                "source": "Document Agent Markdown",
                "quote": "can execute a command",
                "basis": "analysis",
            },
            {
                "field": "affected_component",
                "claim": "Apache Struts 2.3.5",
                "source": "Document Agent Markdown",
                "quote": "Apache Struts 2.3.5",
                "basis": "explicit",
            },
            {
                "field": "vulnerability_summary",
                "claim": "A crafted multipart request can execute a command.",
                "source": "Document Agent Markdown",
                "quote": markdown,
                "basis": "analysis",
            },
            {
                "field": "trigger_conditions",
                "claim": "A crafted multipart request is parsed.",
                "source": "Document Agent Markdown",
                "quote": "a crafted multipart request",
                "basis": "analysis",
            },
        ],
    }

    result, model = run_with(target, markdown, response)

    assert result.vulnerability_type == "RCE"
    assert result.affected_component == "Apache Struts 2.3.5"
    assert result.cve_id == CVE
    assert model.schema is not None
    human_message = model.messages[1][1]
    assert markdown in human_message
    assert "example/struts:2.3.5" in human_message
    assert "ports" in human_message
    assert "Do not search" in model.messages[0][1]


def test_missing_readme_and_sparse_local_material_return_unknown(tmp_path):
    target = make_target(tmp_path, compose="services:\n  web:\n    image: example/unknown\n")
    result, model = run_with(
        target,
        "## 资料缺失\n\n未找到 README，Compose 仅标明服务镜像。",
        {"cve_id": CVE, "vulnerability_type": "Unknown"},
    )

    assert result.vulnerability_type == "Unknown"
    assert result.vulnerability_mechanism is None
    assert "Compose 仅标明服务镜像" in model.messages[1][1]


def test_conflicting_readme_and_compose_facts_are_both_provided(tmp_path):
    readme_fact = "The README identifies version 2.3.5 as affected."
    compose_fact = "image: example/struts:2.3.8"
    target = make_target(
        tmp_path,
        compose=f"services:\n  web:\n    {compose_fact}\n",
    )
    response = {
        "cve_id": CVE,
        "vulnerability_type": "Unknown",
        "limitations": ["The README version and configured image version conflict."],
        "evidence": [
            {
                "field": "limitations",
                "claim": "The README version and configured image version conflict.",
                "source": "Document Agent Markdown",
                "quote": readme_fact,
                "basis": "analysis",
            },
            {
                "field": "limitations",
                "claim": "The README version and configured image version conflict.",
                "source": target.supporting_sources[0].path.as_posix(),
                "quote": compose_fact,
                "basis": "analysis",
            },
        ],
    }

    result, model = run_with(target, readme_fact, response)

    assert readme_fact in model.messages[1][1]
    assert compose_fact in model.messages[1][1]
    assert result.limitations == ["The README version and configured image version conflict."]
    assert len([item for item in result.evidence if item.field == "limitations"]) == 2


def test_unconfirmed_vulnerability_type_remains_unknown():
    result, _ = run_with(
        None,
        "This local document describes a service but does not explain a vulnerability.",
        {"cve_id": CVE, "vulnerability_type": "Unknown"},
    )

    assert result.vulnerability_type == "Unknown"
    assert result.affected_component is None
    assert result.limitations


def test_invalid_structured_result_raises_research_error():
    with pytest.raises(ResearchAgentError, match="model call failed"):
        run_with(None, "local material", {"cve_id": CVE, "unexpected": "field"})


def test_model_call_failure_raises_research_error():
    with pytest.raises(ResearchAgentError, match="model call failed"):
        run_with(None, "local material", RuntimeError("model unavailable"))


def test_unsupported_key_facts_are_removed_and_marked():
    document = "The affected component is Apache Struts."
    result, _ = run_with(
        None,
        document,
        {
            "cve_id": "CVE-2020-9999",
            "vulnerability_type": "RCE",
            "affected_component": "Apache Tomcat",
            "evidence": [
                {
                    "field": "vulnerability_type",
                    "claim": "RCE",
                    "source": "Document Agent Markdown",
                    "quote": "Apache Struts",
                    "basis": "analysis",
                },
                {
                    "field": "affected_component",
                    "claim": "Apache Tomcat",
                    "source": "Document Agent Markdown",
                    "quote": "Apache Struts",
                    "basis": "explicit",
                },
            ],
        },
    )

    assert result.cve_id == CVE
    assert result.vulnerability_type == "RCE"
    assert result.affected_component is None
    assert any("affected component" in item for item in result.limitations)
    assert all(item.quote in document for item in result.evidence)
