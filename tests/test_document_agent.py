from pathlib import Path
from types import SimpleNamespace

import pytest

from app.agents.document import DocumentAgent, DocumentAgentError
from app.agents.runner import AgentRunner
from app.runtime.config import ConfigurationError
from app.targets.material import TargetMaterial
from app.targets.vulhub.loader import load_target


CVE = "CVE-2017-5638"


class FakeRunner:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def run_text(self, **kwargs):
        self.calls.append(kwargs)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeModel:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.inputs = []

    def invoke(self, messages):
        self.inputs.append(messages)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return SimpleNamespace(content=response)


def make_target(tmp_path: Path, *, readme: str | None) -> TargetMaterial:
    root = tmp_path / "vulhub"
    environment = root / "apache" / CVE
    environment.mkdir(parents=True)
    (environment / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: example/web\n", encoding="utf-8"
    )
    if readme is not None:
        (environment / "README.md").write_text(readme, encoding="utf-8")
    return load_target(root, CVE)


def test_document_agent_normalizes_readme_as_markdown(tmp_path):
    material = make_target(tmp_path, readme="# Overview\n\nThe service uses Apache Struts.\n")
    runner = FakeRunner("# 漏洞环境\n\nREADME 说明该环境运行 Apache Struts。")

    result = DocumentAgent(runner).run(material)

    assert result.startswith("# 漏洞环境")
    assert len(runner.calls) == 1
    prompt = runner.calls[0]["input_content"]
    assert isinstance(prompt, str)
    assert "README source:" in prompt
    assert "The service uses Apache Struts." in prompt


def test_missing_readme_uses_compose_and_marks_missing(tmp_path):
    material = make_target(tmp_path, readme=None)
    runner = FakeRunner("本地配置列出了一个 web 服务。")

    result = DocumentAgent(runner).run(material)

    assert "未找到该目标的 README" in result
    assert "docker-compose.yml" in runner.calls[0]["input_content"]
    assert "example/web" in runner.calls[0]["input_content"]
    assert "README is missing" in runner.calls[0]["input_content"]


def test_missing_readme_can_use_other_local_markdown(tmp_path):
    material = make_target(tmp_path, readme=None)
    notes_path = material.environment / "notes.md"
    notes_path.write_text("The service version is documented locally.", encoding="utf-8")
    material = load_target(tmp_path / "vulhub", CVE)
    runner = FakeRunner("本地资料提到了服务版本信息。")

    result = DocumentAgent(runner).run(material)

    assert "未找到该目标的 README" in result
    assert "The service version is documented locally." in runner.calls[0]["input_content"]


def test_missing_referenced_image_does_not_block_text_processing(tmp_path):
    material = make_target(tmp_path, readme="# Overview\n\n![diagram](images/missing.png)\n")
    runner = FakeRunner("# 环境说明\n\nREADME 引用了未找到的图片。")

    result = DocumentAgent(runner).run(material)

    assert result.startswith("# 环境说明")
    assert isinstance(runner.calls[0]["input_content"], str)
    assert "Referenced image is missing locally" in runner.calls[0]["input_content"]


def test_model_without_vision_support_retries_with_text(tmp_path):
    material = make_target(tmp_path, readme="# Overview\n\n![diagram](diagram.png)\n")
    (material.environment / "diagram.png").write_bytes(b"mock png data")
    runner = FakeRunner(ValueError("image input is not supported"), "# Text summary")

    result = DocumentAgent(runner).run(material, language="en")

    assert result == "# Text summary"
    assert len(runner.calls) == 2
    assert isinstance(runner.calls[0]["input_content"], list)
    assert isinstance(runner.calls[1]["input_content"], str)
    assert "cannot interpret images" in runner.calls[1]["input_content"]


def test_image_path_outside_target_is_rejected(tmp_path):
    material = make_target(tmp_path, readme="# Overview\n\n![diagram](../../outside.png)\n")
    runner = FakeRunner("should not be called")

    with pytest.raises(DocumentAgentError, match="escapes the target environment"):
        DocumentAgent(runner).run(material)

    assert runner.calls == []


def test_invalid_model_result_is_rejected(tmp_path):
    material = make_target(tmp_path, readme="# Overview\n")
    agent = DocumentAgent(AgentRunner(FakeModel("   ")))

    with pytest.raises(DocumentAgentError, match="model call failed"):
        agent.run(material)


def test_missing_model_configuration_fails_before_model_creation(monkeypatch):
    monkeypatch.delenv("VULNFORGE_MODEL", raising=False)

    with pytest.raises(ConfigurationError, match="VULNFORGE_MODEL"):
        DocumentAgent.from_environment()
