"""Model-assisted composition of legal Metasploit option values."""
from __future__ import annotations

import json
import re

from pydantic import BaseModel, ConfigDict, Field

from app.agents.runner import AgentRunner


class ModuleConfigurationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    option_overrides: dict[str, str] = Field(default_factory=dict)
    supported: bool = True
    unsupported_reason: str | None = Field(default=None, max_length=500)
    rationale: str = Field(min_length=1, max_length=500)


_INSTRUCTIONS = """Compose module option values for a local, authorized Metasploit attempt.
Use only supplied module metadata, runtime target facts, plan facts, exact PoC snippets,
compatible payload choices, structured payload hints, payload delivery contracts and structured observations from previous attempts.
For a session-capable module, explicitly choose PAYLOAD from compatible_payloads and explain the
selection using the supplied evidence; the application will not choose it for you. The payload's
artifact and entry_class must satisfy module.delivery. Prefer a simple,
direct reverse_tcp payload over HTTP, multi/stager or ancillary transports unless the supplied evidence
requires otherwise. Return no overrides
when the evidence is insufficient. If verification_contract is present, preserve any module options
needed by its required evidence. If verification_contract is null, configure solely for execution and
do not reject the module because verification evidence is unavailable. Never guess unsupported values.
Do not execute snippet commands and do not
copy arbitrary commands into options. Do not invent paths, credentials, versions, ports or hosts.
Do not set RHOST, RHOSTS, RPORT, LHOST or other runtime-owned target/callback options. Listener options
listed in module.delivery.callback_options are not runtime-owned. If module.delivery.trigger is
http_request and the target must fetch a payload from the listener, choose a callback_host-reachable
SRVHOST (for example {{callback_host}}) instead of a wildcard bind address such as 0.0.0.0 or ::;
a wildcard can accept local connections but is not a usable advertised fetch address. If you set
TARGET, use only an exact numeric ID from the supplied target_ids list, never a target name. Values may
use only these placeholders when useful: {{target_host}}, {{target_port}}, {{callback_host}},
{{service}}, {{cve}}. The application validates option names, resolves placeholders and asks for
fresh execution authorization. Prefer concise literal values directly supported by a supplied
snippet or module default. Explain the evidence for each changed value in rationale."""


_TEMPLATE = re.compile(r"\{\{(target_host|target_port|callback_host|service|cve)\}\}")


def resolve_option_templates(overrides: dict[str, str], *, target_host: str,
                             target_port: int, callback_host: str, service: str,
                             cve: str) -> dict[str, str]:
    values = {
        "target_host": target_host,
        "target_port": str(target_port),
        "callback_host": callback_host,
        "service": service,
        "cve": cve,
    }

    def replace(match: re.Match[str]) -> str:
        return values[match.group(1)]

    resolved = {}
    for name, value in overrides.items():
        rendered = _TEMPLATE.sub(replace, value)
        if "{{" in rendered or "}}" in rendered:
            raise ValueError(f"Option {name} contains an unsupported template")
        resolved[name] = rendered
    return resolved


def propose_module_configuration(
    runner: AgentRunner,
    *,
    module: dict,
    plan: dict,
    runtime_target: dict,
    poc_hints: list[dict],
    compatible_payloads: list[str],
    user_options: dict[str, str],
    previous_feedback: dict | None,
    document_markdown: str = "",
    payload_hints: list[dict] | None = None,
    payload_contracts: list[dict] | None = None,
) -> ModuleConfigurationDecision:
    return runner.run(
        agent_name="Module Configurator",
        instructions=_INSTRUCTIONS,
        input_text=json.dumps({
            "module": module,
            "document_markdown": document_markdown,
            "runtime_target": runtime_target,
            "poc_hints": poc_hints,
            "compatible_payloads": compatible_payloads,
            "payload_hints": payload_hints or [],
            "payload_contracts": payload_contracts or [],
            "user_options": user_options,
            "previous_feedback": previous_feedback,
        }, ensure_ascii=False),
        result_schema=ModuleConfigurationDecision,
    )
