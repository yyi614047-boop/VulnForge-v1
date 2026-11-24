import json

import pytest

from app.agents.module_configuration import (
    propose_module_configuration,
    resolve_option_templates,
)


class CapturingRunner:
    def __init__(self, overrides=None):
        self.overrides = overrides or {}
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(kwargs)
        return kwargs["result_schema"](
            option_overrides=self.overrides,
            rationale="Values are supported by the supplied local snippet.",
        )


def test_resolves_only_approved_runtime_placeholders():
    resolved = resolve_option_templates(
        {"TARGETURI": "/{{service}}/{{target_port}}", "VHOST": "{{target_host}}"},
        target_host="172.22.0.4",
        target_port=8080,
        callback_host="172.22.0.2",
        service="web",
        cve="CVE-2024-1234",
    )

    assert resolved == {
        "TARGETURI": "/web/8080",
        "VHOST": "172.22.0.4",
    }


def test_rejects_unknown_templates():
    with pytest.raises(ValueError, match="unsupported template"):
        resolve_option_templates(
            {"TARGETURI": "/{{invented}}"},
            target_host="172.22.0.4",
            target_port=80,
            callback_host="172.22.0.2",
            service="web",
            cve="CVE-2024-1234",
        )


def test_configuration_prompt_contains_metadata_hints_and_runtime_facts():
    runner = CapturingRunner({"TARGETURI": "/api/upload"})
    decision = propose_module_configuration(
        runner,
        module={"module_name": "exploit/multi/http/example", "options": [{"name": "TARGETURI"}]},
        plan={"cve_id": "CVE-2024-1234", "target_service": "web"},
        runtime_target={"host": "172.22.0.4", "port": 80},
        poc_hints=[{"kind": "http_request", "content": "PUT /api/upload HTTP/1.1"}],
        compatible_payloads=["java/jsp_shell_reverse_tcp"],
        user_options={},
        previous_feedback=None,
    )

    assert decision.option_overrides == {"TARGETURI": "/api/upload"}
    payload = json.loads(runner.calls[0]["input_text"])
    assert payload["module"]["module_name"] == "exploit/multi/http/example"
    assert payload["runtime_target"]["port"] == 80
    assert payload["poc_hints"][0]["kind"] == "http_request"
    assert payload["compatible_payloads"] == ["java/jsp_shell_reverse_tcp"]
    instructions = runner.calls[0]["instructions"]
    assert "module.delivery.trigger" in instructions
    assert "wildcard bind address" in instructions
    assert "callback_host" in instructions
