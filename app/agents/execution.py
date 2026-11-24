"""Single-shot Metasploit execution agent for an attested local Vulhub target."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.agents.execution_observations import ExecutionObservation, ExecutionObservationJournal
from app.agents.metasploit_executor import MetasploitExecutor, MetasploitJobError
from app.agents.metasploit_rpc import MetasploitRpcError
from app.agents.module_catalog import MetasploitSearch, ModuleMetadata, ModuleOption, PayloadMetadata
from app.agents.module_configuration import (
    propose_module_configuration,
    resolve_option_templates,
)
from app.agents.planner import ReproductionPlan
from app.agents.poc_hints import _payload_platform, extract_poc_hints
from app.agents.runner import AgentRunner
from app.agents.session_evidence import POSIX_ID_EXPECTATION, SessionEvidenceCollector
from app.targets.material import TargetMaterial
from app.verification.models import CommandExpectation, VerificationPolicy


DISABLED_VERIFICATION_POLICY_ID = "verification-disabled"


class UnsupportedExecutionError(RuntimeError):
    pass


class RuntimeTarget(BaseModel):
    """Endpoint resolved by the active local lab runtime, never by a model."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(min_length=1, max_length=128)
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    project: str = Field(pattern=r"^lab-[a-z0-9][a-z0-9_-]{0,48}$")
    service: str = Field(min_length=1, max_length=64)
    host: str = Field(min_length=1, max_length=45)
    callback_host: str = Field(min_length=1, max_length=45)
    port: int = Field(ge=1, le=65535)
    container_id: str = Field(min_length=12, max_length=128)
    network_name: str = Field(min_length=1, max_length=128)
    network_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    compose_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    os: str | None = Field(default=None, max_length=32)
    architecture: str | None = Field(default=None, max_length=32)
    oob_callback_host: str | None = Field(default=None, max_length=45)
    oob_callback_port: int | None = Field(default=None, ge=1, le=65535)
    oob_token: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{16,64}$")
    local_vulhub: Literal[True] = True

    @classmethod
    def from_vulhub(cls, *, target: TargetMaterial, run_id: str, service: str,
                    port: int, host: str, project: str, container_id: str,
                    network_name: str, network_id: str,
                    callback_host: str | None = None,
                    os: str | None = None, architecture: str | None = None) -> "RuntimeTarget":
        """Bind runtime Docker observations to the selected local Compose service."""
        cve = target.identifier.upper()
        services = target.attributes.get("compose", {}).get("services", {})
        if service not in services or not isinstance(services.get(service), dict):
            raise PermissionError("Runtime service is absent from the selected local Vulhub Compose file")
        declared_ports = services[service].get("ports", [])
        allowed_container_ports = set()
        for entry in declared_ports:
            if isinstance(entry, str):
                parts = entry.split(":")[-1].split("/")
                if (len(parts) == 1 or parts[1].lower() == "tcp") and parts[0].isdigit():
                    allowed_container_ports.add(int(parts[0]))
            elif (isinstance(entry, dict) and str(entry.get("protocol", "tcp")).lower() == "tcp"
                  and str(entry.get("target", "")).isdigit()):
                allowed_container_ports.add(int(entry["target"]))
        for entry in services[service].get("expose", []):
            parts = str(entry).split("/")
            try:
                if len(parts) == 1 or parts[1].lower() == "tcp":
                    allowed_container_ports.add(int(parts[0]))
            except ValueError:
                pass
        if port not in allowed_container_ports:
            raise PermissionError("Runtime target port is absent from the selected local Compose service")
        compose_sha256 = hashlib.sha256(
            json.dumps(target.attributes["compose"], sort_keys=True).encode()
        ).hexdigest()
        return cls(run_id=run_id, cve_id=cve, service=service, host=host,
                   callback_host=callback_host or host, port=port, project=project,
                   container_id=container_id, network_name=network_name,
                   network_id=network_id, compose_sha256=compose_sha256,
                   os=os, architecture=architecture)

    def validate_local(self, target: TargetMaterial, plan: ReproductionPlan, run_id: str) -> None:
        if self.run_id != run_id or self.cve_id != target.identifier.upper() or plan.cve_id != self.cve_id:
            raise PermissionError("Plan, Vulhub target and runtime endpoint must match this run and CVE")
        services = target.attributes.get("compose", {}).get("services", {})
        if self.service not in services or self.compose_sha256 != hashlib.sha256(
            json.dumps(target.attributes["compose"], sort_keys=True).encode()
        ).hexdigest():
            raise PermissionError("Runtime endpoint is not bound to the current local Compose service")
        ip = ipaddress.ip_address(self.host)
        if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local:
            raise PermissionError("Runtime target must be a private IPv4 endpoint on the local lab network")
        callback_ip = ipaddress.ip_address(self.callback_host)
        if (callback_ip.version != 4 or not callback_ip.is_private
                or callback_ip.is_loopback or callback_ip.is_link_local):
            raise PermissionError("Runtime callback must use a private IPv4 endpoint on the local lab network")
        if self.oob_callback_host is not None:
            oob_ip = ipaddress.ip_address(self.oob_callback_host)
            if (oob_ip.version != 4 or not oob_ip.is_private
                    or oob_ip.is_loopback or oob_ip.is_link_local):
                raise PermissionError("OOB callback must use a private IPv4 endpoint on the local lab network")


def _module_context(module: ModuleMetadata) -> dict:
    return module.model_dump(exclude={"raw_output", "description"})


def _runtime_target_context(target: RuntimeTarget | dict) -> dict:
    get = target.get if isinstance(target, dict) else lambda key: getattr(target, key)
    return {
        "cve_id": get("cve_id"),
        "service": get("service"),
        "host": get("host"),
        "callback_host": get("callback_host"),
        "port": get("port"),
        "os": get("os"),
        "architecture": get("architecture"),
        "oob_callback_url": (f"http://{get('oob_callback_host')}:{get('oob_callback_port')}"
                             f"/oob/{get('oob_token')}" if get("oob_callback_host") else None),
    }


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    cve_id: str
    module_name: str | None = None
    target: dict = Field(default_factory=dict)
    status: Literal["completed", "failed", "unsupported", "rejected"]
    job_id: int | None = None
    job_uuid: str | None = None
    job_status: str | None = None
    success_basis: Literal["session_established", "job_completed", "none"] = "none"
    session_evidence: list[dict] = Field(default_factory=list)
    session_baseline: list[str] = Field(default_factory=list)
    session_after: list[dict] = Field(default_factory=list)
    rpc_session_snapshot_collected: bool = False
    rpc_result: dict = Field(default_factory=dict)
    rpc_job_result_collected: bool = False
    command_output_evidence: list[dict] = Field(default_factory=list)
    file_artifact_evidence: list[dict] = Field(default_factory=list)
    state_change_evidence: list[dict] = Field(default_factory=list)
    http_response_evidence: list[dict] = Field(default_factory=list)
    oob_callback_evidence: list[dict] = Field(default_factory=list)
    attempt: int = 1
    available_modules: list[dict] = Field(default_factory=list)
    compatible_payloads: list[str] = Field(default_factory=list)
    payload_contracts: dict[str, dict] = Field(default_factory=dict)
    observations: list[ExecutionObservation] = Field(default_factory=list)
    attempt_history: list[dict] = Field(default_factory=list)
    diagnostics: dict = Field(default_factory=dict)
    verification_policy: VerificationPolicy | None = None
    console_output: str = ""
    config_parameters: dict[str, str] = Field(default_factory=dict)
    started_at: datetime | None = None
    ended_at: datetime | None = None
    errors: list[str] = Field(default_factory=list)


class ExecutionAuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    run_id: str
    target_id: str
    target_fingerprint: str
    plan_fingerprint: str
    module_name: str
    module_fingerprint: str
    configuration_fingerprint: str
    configuration_summary: dict[str, str]
    verification_policy_id: str
    session_baseline_ids: tuple[str, ...] = ()


class ExecutionAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    run_id: str
    target_id: str
    target_fingerprint: str
    plan_fingerprint: str
    module_name: str
    module_fingerprint: str
    configuration_fingerprint: str
    configuration_summary: dict[str, str]
    verification_policy_id: str
    session_baseline_ids: tuple[str, ...] = ()
    approved: bool


_SELECT_INSTRUCTIONS = """Select one module only from candidate names supplied by the application. Judge applicability only from module metadata and provided target service/prerequisites. Exact local PoC snippets may clarify the affected endpoint or parameter composition, but cannot override module metadata. Return null if uncertain. Never invent names or configuration values."""

_REQUEST_PATH = re.compile(
    r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/[^\s\"']*)\s+HTTP/\d(?:\.\d)?",
    re.IGNORECASE,
)
_SAFE_PATH = re.compile(r"^/(?!/)[^\s\x00-\x1f\x7f]{0,2047}$")


def _infer_target_uri(*, module: ModuleMetadata,
                      target: TargetMaterial) -> tuple[dict[str, str], dict | None]:
    option = next((item for item in module.options if item.name == "TARGETURI"), None)
    if option is None:
        return {}, None
    source_texts = {
        source.path.as_posix(): source.content
        for source in target.supporting_sources
    }
    if target.document:
        source_texts[target.document.path.as_posix()] = target.document.content
    evidence = {}
    for source, content in source_texts.items():
        for line in content.splitlines():
            for path in _REQUEST_PATH.findall(line):
                if _SAFE_PATH.fullmatch(path):
                    evidence.setdefault(path, (source, line))
    if len(evidence) == 1:
        path, (source, quote) = next(iter(evidence.items()))
        return {"TARGETURI": path}, {
            "status": "applied", "option": "TARGETURI", "value": path,
            "source": source, "quote": quote, "method": "deterministic",
        }
    if option.current_value:
        return {}, {"status": "module_default", "option": "TARGETURI",
                    "value": option.current_value}
    if evidence:
        return {}, {"status": "ambiguous", "option": "TARGETURI",
                    "paths": sorted(evidence)}
    return {}, {"status": "no_suggestion", "option": "TARGETURI"}


class _Selection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    module_name: str | None


class _RetryDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["retry", "next_module", "stop"]
    module_name: str | None = None
    option_overrides: dict[str, str] = Field(default_factory=dict)
    reason: str = Field(min_length=1, max_length=500)


_RETRY_INSTRUCTIONS = """Review a failed local Metasploit PoC attempt. Return one action:
'retry' to run the same module with changed valid options, 'next_module' to select a different
candidate from the supplied list, or 'stop' when no safe improvement is supported. Use only the
provided module metadata, diagnostics, runtime target facts, exact local PoC snippets, structured
payload hints, payload delivery contracts, compatible payload choices and structured observations. Never invent module names, option names, target values,
commands, payloads or facts. option_overrides may contain only options exposed by the selected module, excluding RHOST, RHOSTS, RPORT and LHOST.
PAYLOAD is allowed for session-capable modules and TARGET is allowed when module targets are supplied;
both must match the runtime platform. Payload artifact and entry_class must satisfy module.delivery.
TARGET must be an exact numeric ID from target_ids, never a name.
For a session-capable module, explicitly choose PAYLOAD from the
supplied platform-compatible choices; the application will not choose it for you. Prefer simple direct
reverse_tcp payloads over HTTP, multi/stager or ancillary transports unless supplied evidence requires
otherwise. Values may use only {{target_host}}, {{target_port}}, {{callback_host}}, {{service}} or {{cve}}
placeholders. A retry must change at least one option."""


_PAYLOAD_NAME = re.compile(r"^[a-z0-9_+-]+(?:/[a-z0-9_+-]+)+$")


def _payload_matches(*, name: str, module: ModuleMetadata, runtime_target: RuntimeTarget) -> bool:
    platform, architecture = _payload_platform(name)
    target_os = (runtime_target.os or "").casefold()
    target_arch = (runtime_target.architecture or "").casefold()
    arch_names = {"amd64": "x64", "x86_64": "x64", "386": "x86", "i386": "x86",
                  "arm64": "aarch64", "aarch64": "aarch64", "arm": "armle"}
    target_arch = arch_names.get(target_arch, target_arch)
    module_platforms = {item.casefold() for item in module.platforms}
    module_arches = {item.casefold() for item in module.architectures}
    if (platform in {"linux", "windows", "unix"} and target_os
            and platform not in {target_os, "unix" if target_os == "linux" else target_os}):
        return False
    if platform and module_platforms and platform not in module_platforms and not (
        platform == "unix" and "linux" in module_platforms
    ):
        return False
    if architecture and architecture != "java" and target_arch:
        if architecture not in {target_arch, "x86" if target_arch == "x64" else target_arch}:
            return False
    if architecture and architecture != "java" and module_arches:
        aliases = {"x64": {"x64", "x86_64"}, "x86": {"x86", "i386"},
                   "aarch64": {"aarch64", "arm64"}}
        if not aliases.get(architecture, {architecture}) & module_arches:
            return False
    return True


def _delivery_mismatch(*, module: ModuleMetadata, payload: PayloadMetadata) -> str | None:
    required = module.delivery.artifact
    if required in {"jar", "war"} and payload.artifact != "unknown" and payload.artifact != required:
        return (f"Payload delivery mismatch: module requires {required}, "
                f"but {payload.name} produces {payload.artifact}")
    if (module.delivery.required_entry_class and payload.entry_class
            and payload.entry_class != module.delivery.required_entry_class):
        return (f"Payload entry-point mismatch: module requires "
                f"{module.delivery.required_entry_class}, but {payload.name} provides {payload.entry_class}")
    return None


def _payload_candidates(*, module: ModuleMetadata, payloads: list[str],
                        runtime_target: RuntimeTarget,
                        payload_contracts: dict[str, PayloadMetadata] | None = None) -> list[str]:
    candidates = list(dict.fromkeys(
        name for name in payloads if isinstance(name, str) and _PAYLOAD_NAME.fullmatch(name)
        and _payload_matches(name=name, module=module, runtime_target=runtime_target)
    ))
    if payload_contracts:
        candidates = [name for name in candidates
                      if name not in payload_contracts
                      or _delivery_mismatch(module=module, payload=payload_contracts[name]) is None]
    return candidates


def _payload_name(*, module: ModuleMetadata, payloads: list[str], runtime_target: RuntimeTarget,
                  payload_hints: list[dict]) -> tuple[str, str]:
    candidates = _payload_candidates(module=module, payloads=payloads,
                                     runtime_target=runtime_target)
    filtered = candidates
    documented = [hint.get("payload_name") for hint in payload_hints
                  if isinstance(hint.get("payload_name"), str)
                  and hint["payload_name"] in candidates]
    for name in documented:
        return name, "source_payload"
    hinted_platforms = {(hint.get("platform") or "").casefold() for hint in payload_hints}
    hinted_platforms.discard("")
    if hinted_platforms:
        preferred = [name for name in filtered
                     if (_payload_platform(name)[0] or "") in hinted_platforms]
        if preferred:
            filtered = preferred
    if "java" in {item.casefold() for item in module.platforms} or "java" in hinted_platforms:
        for preferred in ("java/jsp_shell_reverse_tcp", "java/shell_reverse_tcp",
                          "java/meterpreter/reverse_tcp"):
            if preferred in filtered:
                return preferred, "source_platform" if hinted_platforms else "platform_shell"
    for preferred in ("cmd/unix/reverse_bash", "cmd/unix/reverse_python",
                      "cmd/unix/reverse_netcat", "cmd/unix/reverse",
                      "cmd/windows/reverse_powershell"):
        if preferred in filtered:
            return preferred, "platform_shell"
    shells = sorted(name for name in filtered if name.split("/")[0] != "generic"
                    and (name.endswith("/shell_reverse_tcp") or name.endswith("/shell/reverse_tcp")))
    if shells:
        return shells[0], "native_shell"
    meterpreters = sorted(name for name in filtered
                          if name.endswith("/meterpreter_reverse_tcp") or name.endswith("/meterpreter/reverse_tcp"))
    if meterpreters:
        return meterpreters[0], "native_meterpreter"
    if "generic/shell_reverse_tcp" in filtered:
        return "generic/shell_reverse_tcp", "generic_shell"
    other_native = sorted(name for name in filtered if name.split("/")[0] in {"cmd", "linux", "windows"}
                          and "reverse" in name)
    if other_native:
        return other_native[0], "native_shell"
    if candidates:
        return candidates[0], "metasploit_compatible"
    raise ValueError(f"No compatible payload is available for {module.module_name}")


def _select_payload(*, module: ModuleMetadata, payloads: list[str],
                    runtime_target: RuntimeTarget, payload_hints: list[dict] | None = None) -> tuple[str, str]:
    return _payload_name(module=module, payloads=payloads, runtime_target=runtime_target,
                         payload_hints=payload_hints or [])


def _target_name_matches_runtime(name: str, runtime_target: RuntimeTarget) -> bool:
    lowered = name.casefold()
    os_name = (runtime_target.os or "").casefold()
    mentioned = {item for item in {"linux", "windows", "unix"} if item in lowered}
    if mentioned and os_name and os_name not in mentioned and not (
        os_name == "linux" and "unix" in mentioned
    ):
        return False
    arch = {"amd64": "x64", "x86_64": "x64", "arm64": "aarch64"}.get(
        (runtime_target.architecture or "").casefold(), (runtime_target.architecture or "").casefold())
    aliases = {"x64": ("x64", "x86_64", "amd64"), "x86": ("x86", "i386", "386"),
               "aarch64": ("aarch64", "arm64")}
    mentioned_arches = {item for item in ("x64", "x86_64", "amd64", "x86", "i386", "386",
                                          "aarch64", "arm64") if item in lowered}
    if mentioned_arches and arch and not any(item in aliases.get(arch, (arch,))
                                             for item in mentioned_arches):
        return False
    return True


def _select_module_target(*, module: ModuleMetadata, runtime_target: RuntimeTarget,
                          payload_platform: str | None = None) -> int | None:
    if not module.targets:
        return None
    if payload_platform in {"java", "python", "ruby", "php"}:
        language_matches = [index for index, name in enumerate(module.targets)
                            if payload_platform in name.casefold()]
        if len(language_matches) == 1:
            target_id = module.target_ids[language_matches[0]] if module.target_ids else language_matches[0]
            return target_id
    os_name = (runtime_target.os or "").casefold()
    matches = []
    for index, name in enumerate(module.targets):
        lowered = name.casefold()
        if lowered in {os_name, "unix" if os_name == "linux" else os_name}:
            matches.append(index)
    if len(matches) > 1 and runtime_target.architecture:
        arch = {"amd64": "x64", "x86_64": "x64", "arm64": "aarch64"}.get(
            runtime_target.architecture.casefold(), runtime_target.architecture.casefold())
        aliases = {"x64": ("x64", "x86_64", "amd64"),
                   "x86": ("x86", "i386", "386"),
                   "aarch64": ("aarch64", "arm64")}
        arch_matches = [index for index in matches
                        if any(item in module.targets[index].casefold() for item in aliases.get(arch, (arch,)))]
        if len(arch_matches) == 1:
            matches = arch_matches
    if len(matches) == 1:
        target_id = module.target_ids[matches[0]] if module.target_ids else matches[0]
        return target_id
    return None


def _select_target_port(*, module: ModuleMetadata, target: TargetMaterial, service: str) -> int:
    services = target.attributes.get("compose", {}).get("services", {})
    config = services.get(service, {}) if isinstance(services, dict) else {}
    declared = set()
    for entry in config.get("ports", []) if isinstance(config, dict) else []:
        if isinstance(entry, str):
            value, separator, protocol = entry.rsplit(":", 1)[-1].partition("/")
            if value.isdigit() and (not separator or protocol.lower() == "tcp"):
                declared.add(int(value))
    for entry in config.get("expose", []) if isinstance(config, dict) else []:
        value, separator, protocol = str(entry).partition("/")
        if value.isdigit() and (not separator or protocol.lower() == "tcp"):
            declared.add(int(value))
    if len(declared) == 1:
        return next(iter(declared))
    default = next((option.current_value for option in module.options if option.name == "RPORT"), None)
    if default is not None and str(default).strip().isdigit() and int(str(default).strip()) in declared:
        return int(str(default).strip())
    if not declared:
        raise ValueError("The selected target service declares no TCP port")
    raise ValueError(
        "Cannot infer target port: the module default is not declared and the service declares multiple ports: "
        + ", ".join(str(port) for port in sorted(declared))
    )


class ExecutionAgent:
    def __init__(self, search: MetasploitSearch, executor: MetasploitExecutor,
                 *, runner: AgentRunner | None = None, event_sink: Callable[[dict], None] | None = None,
                 evidence_dir: Path | None = None,
                 session_evidence_collector: SessionEvidenceCollector | None = None,
                 max_attempts: int = 1):
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self.search, self.executor, self.runner = search, executor, runner
        self.max_attempts = max_attempts
        self.session_evidence_collector = session_evidence_collector or SessionEvidenceCollector(executor.rpc)
        self.event_sink, self.evidence_dir = event_sink or (lambda event: None), evidence_dir

    def _event(self, kind, **details):
        self.event_sink({"type": kind, "timestamp": datetime.now(timezone.utc).isoformat(), **details})

    def _observe(self, journal: ExecutionObservationJournal, stage: str, source: str, *,
                 data: dict | None = None, status: str = "observed", summary: str = "") -> None:
        journal.add(stage, source, data=data, status=status, summary=summary)
        self._event("execution_observation", run_id=journal.run_id,
                    execution_id=journal.execution_id, attempt=journal.attempt,
                    stage=stage, source=source, status=status, summary=summary, data=data or {})

    def _inspect_file_artifacts(self, *, journal: ExecutionObservationJournal,
                                expectations, baselines: dict, inspector,
                                target_id: str) -> tuple[list[dict], list[dict]]:
        evidence = []
        diagnostics = []
        for expectation in expectations:
            try:
                after = inspector(expectation.path_pattern)
                if not isinstance(after, dict) or not isinstance(after.get("matches"), list):
                    raise RuntimeError("File artifact inspector returned a malformed result")
                baseline_paths = {item.get("path") for item in baselines[expectation.path_pattern]["matches"]
                                  if isinstance(item, dict) and item.get("path")}
                new_files = [item for item in after["matches"]
                             if isinstance(item, dict) and item.get("path") not in baseline_paths]
                evidence.append({
                    "source": "vulhub_runtime_file_artifact",
                    "execution_id": journal.execution_id,
                    "target_id": target_id,
                    "path_pattern": expectation.path_pattern,
                    "existed_before": bool(baseline_paths),
                    "exists_after": bool(after["matches"]),
                    "new_files": new_files,
                })
                if new_files:
                    self._event("file_artifact_collected", run_id=journal.run_id,
                                path_pattern=expectation.path_pattern,
                                new_file_count=len(new_files))
            except Exception as exc:
                diagnostics.append({
                    "path_pattern": expectation.path_pattern,
                    "error": f"{type(exc).__name__}: {exc}",
                })
        self._observe(journal, "file_artifact", "target_file_after",
                      data={"evidence": evidence, "errors": diagnostics},
                      status="error" if diagnostics else "observed",
                      summary=f"Inspected {len(evidence)} file expectation(s) after execution.")
        return evidence, diagnostics

    def run(self, *, plan: ReproductionPlan, target: TargetMaterial,
            runtime_target: RuntimeTarget | None = None, run_id: str,
            target_resolver: Callable[[int], RuntimeTarget] | None = None,
            authorized: bool = False, options: dict[str, str] | None = None,
            verification_expectations: tuple[CommandExpectation, ...] = (),
            authorization_callback: Callable[[ExecutionAuthorizationRequest], ExecutionAuthorization | None] | None = None,
            diagnostics_callback: Callable[[], dict] | None = None,
            file_artifact_inspector: Callable[[str], dict] | None = None,
            document_markdown: str | None = None) -> ExecutionResult:
        history = []
        attempted_modules = []
        module_override = None
        option_overrides = None
        feedback = None
        last = None
        poc_hints = [hint.to_dict() for hint in extract_poc_hints(target)]
        payload_hints = [hint for hint in poc_hints if hint.get("kind") == "payload"]
        for attempt in range(1, self.max_attempts + 1):
            self._event("execution_attempt_started", run_id=run_id, attempt=attempt)
            last = self._run_once(
                plan=plan, target=target, runtime_target=runtime_target, run_id=run_id,
                target_resolver=target_resolver, authorized=authorized, options=options,
                verification_expectations=verification_expectations,
                authorization_callback=authorization_callback,
                diagnostics_callback=diagnostics_callback,
                file_artifact_inspector=file_artifact_inspector,
                document_markdown=document_markdown,
                attempt=attempt, module_override=module_override,
                option_overrides=option_overrides,
                attempted_modules=tuple(attempted_modules), feedback=feedback,
                poc_hints=poc_hints,
                payload_hints=payload_hints,
            )
            history.append({
                "attempt": attempt,
                "status": last.status,
                "module_name": last.module_name,
                "errors": list(last.errors),
                "diagnostics": last.diagnostics,
                "config_parameters": last.config_parameters,
                "compatible_payloads": last.compatible_payloads,
                "observation_count": len(last.observations),
            })
            if last.module_name and last.module_name not in attempted_modules:
                attempted_modules.append(last.module_name)
            if (last.status not in {"failed", "unsupported"}
                    or attempt >= self.max_attempts or self.runner is None
                    or not last.available_modules):
                break
            retry_payload_choices = []
            retry_contracts = {}
            if last.target and last.module_name:
                retry_target = RuntimeTarget.model_validate(last.target)
                retry_module = next((item for item in last.available_modules
                                     if item.get("module_name") == last.module_name), None)
                if retry_module:
                    retry_contracts = {name: PayloadMetadata.model_validate(item)
                                       for name, item in last.payload_contracts.items()}
                    retry_payload_choices = _payload_candidates(
                        module=ModuleMetadata.model_validate(retry_module),
                        payloads=last.compatible_payloads, runtime_target=retry_target,
                        payload_contracts=retry_contracts,
                    )
            review_input = {
                "attempt": attempt,
                "plan": {
                    "cve_id": plan.cve_id,
                    "vulnerability_type": plan.vulnerability_type,
                    "target_service": plan.target_service,
                    "prerequisites": plan.prerequisites,
                    "affected_component": plan.research_context.affected_component,
                    "vulnerability_summary": plan.research_context.vulnerability_summary,
                    "trigger_conditions": plan.research_context.trigger_conditions,
                    "verification_contract": plan.verification_contract.model_dump(mode="json")
                    if plan.verification_contract else None,
                },
                "last_attempt": {
                    "status": last.status,
                    "module_name": last.module_name,
                    "errors": last.errors,
                    "diagnostics": last.diagnostics,
                    "config_parameters": last.config_parameters,
                },
                "candidates": [_module_context(ModuleMetadata.model_validate(item))
                               for item in last.available_modules],
                "compatible_payloads": retry_payload_choices,
                "payload_contracts": [retry_contracts[name].model_dump() for name in retry_payload_choices
                                      if name in retry_contracts],
                "observations": [item.for_agent() for item in last.observations],
                "attempted_modules": attempted_modules,
                "runtime_target": _runtime_target_context(last.target) if last.target else None,
                "poc_hints": poc_hints,
                "payload_hints": payload_hints,
            }
            try:
                decision = self.runner.run(
                    agent_name="Execution Retry Reviewer",
                    instructions=_RETRY_INSTRUCTIONS,
                    input_text=json.dumps(review_input, ensure_ascii=False),
                    result_schema=_RetryDecision,
                )
            except Exception as exc:
                last = last.model_copy(update={"diagnostics": {
                    **last.diagnostics,
                    "retry_controller": {"error": f"{type(exc).__name__}: {exc}"},
                }})
                break
            retry_error = None
            next_module = None
            next_options = dict(decision.option_overrides)
            if (decision.action == "retry" and last.module_name
                    and last.config_parameters.get("PAYLOAD")
                    and "PAYLOAD" not in next_options):
                next_options["PAYLOAD"] = last.config_parameters["PAYLOAD"]
            if (decision.action == "retry" and last.module_name
                    and last.config_parameters.get("TARGET")
                    and "TARGET" not in next_options):
                next_options["TARGET"] = last.config_parameters["TARGET"]
            if decision.action == "stop":
                break
            if decision.action == "retry":
                next_module = decision.module_name or last.module_name
                if last.module_name is None or next_module != last.module_name or not next_options:
                    retry_error = "Retry must keep the module and change at least one option."
                elif all(last.config_parameters.get(key) == value for key, value in next_options.items()):
                    retry_error = "Retry options do not change the previous configuration."
            else:
                next_module = decision.module_name
                if (next_module not in {item.get("module_name") for item in last.available_modules}
                        or next_module in attempted_modules):
                    retry_error = "Next module must be a different unattempted candidate."
            selected = next((item for item in last.available_modules
                             if item.get("module_name") == next_module), None)
            if retry_error is None and selected is not None:
                if (decision.action == "retry"
                        and all(last.config_parameters.get(key) == value for key, value in next_options.items())):
                    retry_error = "Retry options do not change the previous configuration."
                if selected.get("session_capable") and "PAYLOAD" not in next_options:
                    retry_error = "Retry must explicitly select a PAYLOAD for a session-capable module."
                allowed_options = {item.get("name") for item in selected.get("options", [])}
                if selected.get("targets"):
                    allowed_options.add("TARGET")
                if selected.get("session_capable"):
                    allowed_options.add("PAYLOAD")
                if set(next_options) - allowed_options:
                    retry_error = "Retry options contain names absent from module metadata."
                elif set(next_options) & {"RHOST", "RHOSTS", "RPORT", "LHOST"}:
                    retry_error = "Retry cannot override runtime-derived target options."
                elif ("PAYLOAD" in next_options and last.compatible_payloads
                      and next_options["PAYLOAD"] not in last.compatible_payloads):
                    retry_error = "Retry payload is absent from the compatible payload list."
                elif ("TARGET" in next_options and (not next_options["TARGET"].isdigit()
                      or int(next_options["TARGET"]) not in (selected.get("target_ids")
                      or list(range(len(selected.get("targets", []))))))):
                    retry_error = "Retry target is absent from module metadata."
                elif any(any(ord(ch) < 32 for ch in value) for value in next_options.values()):
                    retry_error = "Retry options cannot contain control characters."
            if retry_error is not None:
                last = last.model_copy(update={"diagnostics": {
                    **last.diagnostics,
                    "retry_controller": {"error": retry_error},
                }})
                break
            module_override = next_module
            option_overrides = next_options
            feedback = {
                "previous_status": last.status,
                "previous_module": last.module_name,
                "previous_errors": last.errors,
                "previous_diagnostics": last.diagnostics,
                "previous_observations": [item.for_agent() for item in last.observations],
                "compatible_payloads": last.compatible_payloads,
                "payload_hints": payload_hints,
                "review_reason": decision.reason,
            }
            self._event("execution_retry_planned", run_id=run_id,
                        next_attempt=attempt + 1, action=decision.action,
                        module_name=next_module, reason=decision.reason)
        final = last.model_copy(update={"attempt_history": history})
        self._save_evidence(final)
        return final

    def _run_once(self, *, plan: ReproductionPlan, target: TargetMaterial,
                  runtime_target: RuntimeTarget | None = None, run_id: str,
                  target_resolver: Callable[[int], RuntimeTarget] | None = None,
                  authorized: bool = False, options: dict[str, str] | None = None,
                  verification_expectations: tuple[CommandExpectation, ...] = (),
                  authorization_callback: Callable[[ExecutionAuthorizationRequest], ExecutionAuthorization | None] | None = None,
                  diagnostics_callback: Callable[[], dict] | None = None,
                  file_artifact_inspector: Callable[[str], dict] | None = None,
                  attempt: int = 1, module_override: str | None = None,
                  option_overrides: dict[str, str] | None = None,
                  attempted_modules: tuple[str, ...] = (),
                  feedback: dict | None = None,
                  document_markdown: str | None = None,
                  poc_hints: list[dict] | None = None,
                  payload_hints: list[dict] | None = None) -> ExecutionResult:
        execution_id = str(uuid.uuid4())
        journal = ExecutionObservationJournal(run_id=run_id, execution_id=execution_id, attempt=attempt)
        compatible_payloads = []
        base = dict(run_id=run_id, execution_id=execution_id, attempt=attempt,
                    target_id=runtime_target.container_id if runtime_target else f"unresolved:{run_id}",
                    cve_id=plan.cve_id, target=runtime_target.model_dump() if runtime_target else {},
                    compatible_payloads=compatible_payloads, observations=journal.items)
        try:
            if not plan.executable or plan.status != "ready":
                raise ValueError("Reproduction plan is not executable")
            if runtime_target is not None:
                if plan.execution_method != "metasploit" or plan.target_service != runtime_target.service:
                    raise PermissionError("Plan method or target service does not match the resolved target")
                runtime_target.validate_local(target, plan, run_id)
            elif target_resolver is None:
                raise ValueError("A resolved runtime target or target resolver is required")
        except Exception as exc:
            return ExecutionResult(**base, status="rejected", errors=[str(exc)])

        started = datetime.now(timezone.utc)
        module = None
        verification_policy = None
        session_baseline = {}
        session_baseline_collected = False
        effective = {}
        file_expectations = ()
        file_baselines = {}
        state_change_evidence = []
        try:
            self._event("module_search_started", run_id=run_id, cve_id=plan.cve_id)
            names = self.search.search(plan.cve_id)
            self._event("module_candidates_found", run_id=run_id, module_names=names)
            if not names:
                result = ExecutionResult(**base, status="unsupported", errors=["No Metasploit modules matched this CVE."], started_at=started, ended_at=datetime.now(timezone.utc))
                self._save_evidence(result)
                return result
            metadata = [self.search.inspect(plan.cve_id, name) for name in names[:20]]
            base["available_modules"] = [
                item.model_dump(exclude={"raw_output"}) for item in metadata
            ]
            self._observe(journal, "module_catalog", "metasploit_catalog",
                          data={"modules": [_module_context(item) for item in metadata]},
                          summary=f"Inspected {len(metadata)} exact-CVE module candidate(s).")
            selection = module_override or next(
                (item.module_name for item in metadata if item.module_type == "exploit"
                 and plan.cve_id.upper() in {reference.upper() for reference in item.references}),
                None,
            )
            module = next((m for m in metadata if m.module_name == selection), None)
            if module is None:
                result = ExecutionResult(**base, status="unsupported", errors=["No applicable searched module was selected."], started_at=started, ended_at=datetime.now(timezone.utc))
                result.console_output = "\n".join(m.raw_output for m in metadata)
                self._save_evidence(result)
                return result
            if plan.cve_id.upper() not in {x.upper() for x in module.references}:
                result = ExecutionResult(**base, module_name=module.module_name,
                                       console_output=module.raw_output, errors=["Candidate does not establish applicability to the requested CVE."],
                                       started_at=started, ended_at=datetime.now(timezone.utc), status="unsupported")
                self._save_evidence(result)
                return result
            self._event("module_selected", run_id=run_id, module_name=module.module_name)
            if runtime_target is None:
                port = _select_target_port(module=module, target=target, service=plan.target_service)
                runtime_target = target_resolver(port)
                if plan.target_service != runtime_target.service:
                    raise PermissionError("Resolved target service does not match the reproduction plan")
                runtime_target.validate_local(target, plan, run_id)
                base.update(target_id=runtime_target.container_id, target=runtime_target.model_dump())
                self._event("runtime_target_resolved", run_id=run_id,
                            runtime_target=runtime_target.model_dump(mode="json"))
            self._observe(journal, "runtime_target", "vulhub_runtime",
                          data=_runtime_target_context(runtime_target),
                          summary="Runtime target resolved and bound to the local Compose service.")
            self._event("module_configuration_started", run_id=run_id, module_name=module.module_name)
            contract = plan.verification_contract
            file_required = bool(contract and any(
                requirement.kind == "file_artifact" and requirement.required
                for requirement in contract.evidence_requirements
            ))
            file_expectations = contract.file_artifacts if file_required and contract else ()
            file_baselines = {}
            file_baseline_errors = []
            if file_required and (not file_expectations or file_artifact_inspector is None):
                file_expectations = ()
            else:
                for expectation in file_expectations:
                    try:
                        baseline = file_artifact_inspector(expectation.path_pattern)
                        if not isinstance(baseline, dict) or not isinstance(baseline.get("matches"), list):
                            raise RuntimeError("File artifact inspector returned a malformed baseline")
                        file_baselines[expectation.path_pattern] = baseline
                    except Exception as exc:
                        file_expectations = ()
                        file_baselines = {}
                        file_baseline_errors.append({
                            "path_pattern": expectation.path_pattern,
                            "error": f"{type(exc).__name__}: {exc}",
                        })
                        break
            known = {o.name: o for o in module.options}
            if module.targets:
                known.setdefault("TARGET", ModuleOption(name="TARGET"))
            if module.session_capable:
                known.setdefault("PAYLOAD", ModuleOption(name="PAYLOAD"))
            if module.session_capable:
                try:
                    compatible_payloads.extend(self.executor.compatible_payloads(module))
                except Exception as exc:
                    self._observe(journal, "module_catalog", "metasploit_compatible_payloads",
                                  data={"error": f"{type(exc).__name__}: {exc}"}, status="error",
                                  summary="Compatible payload discovery failed.")
                    raise RuntimeError("Compatible payload discovery failed") from exc
                payload_choices = list(compatible_payloads)
                payload_contracts = {}
                self._observe(journal, "module_catalog", "metasploit_compatible_payloads",
                              data={"payload_count": len(payload_choices),
                                    "platform_compatible_payloads": payload_choices},
                              summary="Metasploit reported compatible payloads; final compatibility is delegated to Metasploit.")
            else:
                payload_choices = []
                payload_contracts = {}
            retry_overrides = resolve_option_templates(
                option_overrides or {},
                target_host=runtime_target.host,
                target_port=runtime_target.port,
                callback_host=runtime_target.callback_host,
                service=runtime_target.service,
                cve=plan.cve_id,
            )
            agent_overrides = {}
            missing_nondefault = any(
                option.required and option.name not in {"RHOST", "RHOSTS", "RPORT", "LHOST", "PAYLOAD", "TARGET"}
                and not option.current_value for option in module.options
            )
            if self.runner and not option_overrides and missing_nondefault:
                self._event("module_parameter_composition_started", run_id=run_id,
                            module_name=module.module_name)
                try:
                    decision = propose_module_configuration(
                        self.runner,
                        module=_module_context(module),
                        plan={
                            "cve_id": plan.cve_id,
                            "vulnerability_type": plan.vulnerability_type,
                            "target_service": plan.target_service,
                            "prerequisites": plan.prerequisites,
                            "affected_component": plan.research_context.affected_component,
                            "vulnerability_summary": plan.research_context.vulnerability_summary,
                            "trigger_conditions": plan.research_context.trigger_conditions,
                            "verification_contract": contract.model_dump(mode="json") if contract else None,
                        },
                        runtime_target=_runtime_target_context(runtime_target),
                        document_markdown=document_markdown or "",
                        poc_hints=poc_hints or [],
                        compatible_payloads=payload_choices,
                        payload_hints=payload_hints or [],
                        payload_contracts=[payload_contracts[name].model_dump()
                                           for name in payload_choices if name in payload_contracts],
                        user_options=_redact_options(options or {}),
                        previous_feedback=feedback,
                    )
                    if not decision.supported:
                        raise UnsupportedExecutionError(
                            decision.unsupported_reason
                            or "The selected module cannot be configured for execution."
                        )
                    invalid_names = set(decision.option_overrides) - set(known)
                    runtime_owned = set(decision.option_overrides) & {
                        "RHOST", "RHOSTS", "RPORT", "LHOST",
                    }
                    proposed = {
                        key: value for key, value in decision.option_overrides.items()
                        if key not in invalid_names and key not in runtime_owned
                    }
                    agent_overrides = resolve_option_templates(
                        proposed,
                        target_host=runtime_target.host,
                        target_port=runtime_target.port,
                        callback_host=runtime_target.callback_host,
                        service=runtime_target.service,
                        cve=plan.cve_id,
                    )
                    self._event("module_parameter_composition_completed", run_id=run_id,
                                module_name=module.module_name,
                                options=_redact_options(agent_overrides),
                                rationale=decision.rationale,
                                ignored_options=sorted(invalid_names | runtime_owned))
                except UnsupportedExecutionError:
                    raise
                except Exception as exc:
                    self._event("module_parameter_composition_fallback", run_id=run_id,
                                module_name=module.module_name,
                                error=f"{type(exc).__name__}: {exc}")
            supplied = dict(agent_overrides)
            supplied.update(retry_overrides)
            supplied.update(options or {})
            if "TARGETURI" in supplied:
                suggestion_evidence = {"status": "explicit", "option": "TARGETURI",
                                       "value": supplied["TARGETURI"]}
            else:
                self._event("module_path_inference_started", run_id=run_id,
                            module_name=module.module_name, option="TARGETURI")
                suggested, suggestion_evidence = _infer_target_uri(module=module, target=target)
                for name, value in suggested.items():
                    supplied.setdefault(name, value)
                self._event("module_path_inference_completed", run_id=run_id,
                            module_name=module.module_name,
                            inference=suggestion_evidence or {"status": "not_applicable"})
            if set(supplied) - set(known):
                raise ValueError("Configuration contains options absent from module metadata")
            if "PAYLOAD" in supplied and compatible_payloads and supplied["PAYLOAD"] not in compatible_payloads:
                raise ValueError("Configured payload is absent from Metasploit's compatible payload list")
            if "PAYLOAD" in supplied:
                payload_source = ("agent" if "PAYLOAD" in agent_overrides else
                                  "user" if "PAYLOAD" in (options or {}) else "retry")
                self._event("payload_selected", run_id=run_id, module_name=module.module_name,
                            payload=supplied["PAYLOAD"], reason=f"{payload_source}_selected")
            if "TARGET" in supplied:
                if not str(supplied["TARGET"]).isdigit() or int(supplied["TARGET"]) not in (
                    module.target_ids or list(range(len(module.targets)))
                ):
                    raise ValueError(
                        "Configured TARGET is absent from module metadata; expected one of: "
                        + ", ".join(str(item) for item in (module.target_ids or list(range(len(module.targets)))))
                    )
            if set(supplied) & {"RHOST", "RHOSTS", "RPORT", "LHOST"}:
                raise PermissionError("Target options are derived by the execution agent")
            if any(any(ord(ch) < 32 for ch in value) for value in supplied.values()):
                raise PermissionError("Control-character module options are disabled")
            command_required = bool(contract and any(
                requirement.kind == "command_output" and requirement.required
                for requirement in contract.evidence_requirements
            ))
            direct_command_output = command_required and "CMD" in known
            session_command_output = command_required and module.session_capable
            if command_required and not (direct_command_output or session_command_output):
                raise UnsupportedExecutionError(
                    "The selected module cannot provide structured command output."
                )
            if direct_command_output and supplied.get("CMD", "id") != "id":
                raise ValueError("The command-output contract requires fixed CMD=id.")
            if direct_command_output and "cmd/unix/generic" not in payload_choices:
                raise UnsupportedExecutionError(
                    "The selected module has no compatible cmd/unix/generic payload for command-output evidence."
                )
            payload_required = module.session_capable and "PAYLOAD" in known
            auto_payload = payload_required and "PAYLOAD" not in supplied
            effective = supplied.copy()
            if "RHOSTS" in known:
                effective["RHOSTS"] = runtime_target.host
            if "RHOST" in known:
                effective["RHOST"] = runtime_target.host
            if "RPORT" in known:
                effective["RPORT"] = str(runtime_target.port)
            if "SSL" in known and runtime_target.port == 80:
                effective["SSL"] = False
            for o in module.options:
                if (o.required and o.name not in effective and o.current_value
                        and not (auto_payload and o.name == "PAYLOAD")):
                    effective[o.name] = o.current_value
            if "CVE" in known:
                effective["CVE"] = plan.cve_id.upper()
            if module.session_capable:
                effective["LHOST"] = runtime_target.callback_host
            if direct_command_output:
                effective["CMD"] = "id"
            missing = [o.name for o in module.options if o.required and not effective.get(o.name)
                       and not (auto_payload and o.name == "PAYLOAD")]
            if missing:
                raise ValueError("Required module options missing: " + ", ".join(missing))
            if auto_payload:
                if direct_command_output:
                    if "cmd/unix/generic" not in compatible_payloads:
                        raise UnsupportedExecutionError(
                            "The selected module has no compatible cmd/unix/generic payload for command-output evidence."
                        )
                    payload, reason = "cmd/unix/generic", "verification_contract"
                else:
                    payload, reason = _select_payload(
                        module=module, payloads=compatible_payloads,
                        runtime_target=runtime_target, payload_hints=payload_hints,
                    )
                effective["PAYLOAD"] = payload
                self._event("payload_selected", run_id=run_id, module_name=module.module_name,
                            payload=payload, reason=reason)
            payload_platform = _payload_platform(str(effective.get("PAYLOAD", "")))[0]
            selected_target = _select_module_target(
                module=module, runtime_target=runtime_target, payload_platform=payload_platform,
            )
            if "TARGET" not in supplied and selected_target is not None:
                supplied["TARGET"] = str(selected_target)
                effective["TARGET"] = str(selected_target)
                self._event("module_target_selected", run_id=run_id,
                            module_name=module.module_name, target=selected_target,
                            reason="payload_and_runtime_platform")
            self._observe(journal, "configuration", "execution_configuration",
                          data={"module_name": module.module_name,
                                "options": _redact_options(effective),
                                "payload_reason": reason if auto_payload else "explicit_or_not_required",
                                "required_evidence": [item.kind for item in contract.evidence_requirements
                                                      if item.required] if contract else []},
                          summary="Effective Metasploit configuration frozen before authorization.")
            command_output_supported = bool(
                (
                    direct_command_output
                    and effective.get("CMD") == "id"
                    and ("PAYLOAD" not in known or effective.get("PAYLOAD") == "cmd/unix/generic")
                )
                or (
                    session_command_output
                    and module.session_capable
                    and effective.get("PAYLOAD") != "cmd/unix/generic"
                )
            )
            if command_required and not command_output_supported:
                raise UnsupportedExecutionError(
                    "The selected configuration cannot provide structured command output."
                )
            command_expectations = (
                tuple(verification_expectations) or (POSIX_ID_EXPECTATION,)
            ) if command_output_supported else ()
            if contract is not None:
                from app.verification.policy import build_verification_policy
                verification_policy = build_verification_policy(
                    run_id=run_id, target_id=runtime_target.container_id,
                    vulnerability_type=plan.vulnerability_type,
                    contract=contract,
                    module_type=module.module_type, module_name=module.module_name,
                    session_capable=(module.session_capable
                                     and effective.get("PAYLOAD") != "cmd/unix/generic"),
                    command_output_supported=command_output_supported,
                    command_expectations=command_expectations,
                    file_artifact_supported=bool(file_expectations),
                    file_expectations=file_expectations,
                    oob_callback_supported=runtime_target.oob_callback_host is not None,
                )
                self._event("verification_policy_frozen", run_id=run_id,
                            module_name=module.module_name, policy_id=verification_policy.policy_id,
                            contract=contract.model_dump(mode="json"))
            verification_policy_id = (
                verification_policy.policy_id if verification_policy else DISABLED_VERIFICATION_POLICY_ID
            )
            session_baseline = self.executor.snapshot_sessions()
            session_baseline_collected = True
            plan_fingerprint = _fingerprint(plan.model_dump(mode="json"))
            target_fingerprint = _fingerprint(runtime_target.model_dump(mode="json"))
            module_fingerprint = _fingerprint(module.model_dump(mode="json"))
            request = ExecutionAuthorizationRequest(
                run_id=run_id, target_id=runtime_target.container_id,
                target_fingerprint=target_fingerprint, plan_fingerprint=plan_fingerprint,
                module_name=module.module_name, module_fingerprint=module_fingerprint,
                configuration_fingerprint=_fingerprint(effective),
                configuration_summary=_redact_options(effective),
                verification_policy_id=verification_policy_id,
                session_baseline_ids=tuple(str(key) for key in session_baseline),
            )
            if authorization_callback is not None:
                try:
                    grant = authorization_callback(request)
                except Exception as exc:
                    raise PermissionError(f"Execution authorization callback failed: {exc}") from exc
                expected = request.model_dump()
                if (not isinstance(grant, ExecutionAuthorization) or not grant.approved or any(
                    getattr(grant, key) != value for key, value in expected.items()
                )):
                    raise PermissionError("Execution authorization is missing, denied or bound to changed inputs")
            elif not authorized:
                raise PermissionError("Explicit execution authorization is required")
            self._observe(journal, "authorization", "execution_authorization",
                          data={"module_name": module.module_name,
                                "configuration_fingerprint": request.configuration_fingerprint,
                                "verification_policy_id": verification_policy_id,
                                "approved": True},
                          summary="Fingerprint-bound execution authorization accepted.")
            if file_baselines:
                self._observe(journal, "file_artifact", "target_file_baseline",
                              data={"baselines": file_baselines},
                              summary="Captured target file baseline before execution.")
            if file_baseline_errors:
                self._observe(journal, "file_artifact", "target_file_baseline_unavailable",
                              data={"errors": file_baseline_errors}, status="error",
                              summary="File baseline is unavailable; execution continues without file verification.")
            self._event("module_configuration_completed", run_id=run_id, module_name=module.module_name,
                        options=_redact_options(effective))
            self._event("exploit_started", run_id=run_id, module_name=module.module_name)
            raw = self.executor.execute(module, effective, session_baseline=session_baseline)
            execution_succeeded = raw["job_status"] == "completed" or bool(raw["session_evidence"])
            success_basis = ("session_established" if raw["session_evidence"] else
                             "job_completed" if execution_succeeded else "none")
            self._event("exploit_completed", run_id=run_id, module_name=module.module_name,
                        job_id=raw["job_id"], job_status=raw["job_status"],
                        success_basis=success_basis)
            self._observe(journal, "execution", "metasploit_rpc_job",
                          data={"job_id": raw["job_id"], "job_uuid": raw["job_uuid"],
                                "job_status": raw["job_status"], "result": raw["result"],
                                "error": raw.get("error"), "success_basis": success_basis},
                          status="observed" if execution_succeeded else "error",
                          summary=(f"Metasploit job finished with status {raw['job_status']}; "
                                   f"execution outcome is based on {success_basis}."))
            self._observe(journal, "session", "metasploit_rpc_session_delta",
                          data={"baseline": raw["session_baseline"],
                                "after": raw["session_after"],
                                "new_sessions": raw["session_evidence"]},
                          summary=f"Observed {len(raw['session_evidence'])} new session(s).")
            if raw["job_status"] != "completed" and not execution_succeeded:
                self._event("execution_failed", run_id=run_id, module_name=module.module_name,
                            job_id=raw["job_id"], job_status=raw["job_status"], error="Metasploit job failed")
            if raw["session_evidence"]:
                self._event("session_detected", run_id=run_id, sessions=raw["session_evidence"])
            rpc_result = raw["result"] if isinstance(raw["result"], dict) else {"value": str(raw["result"])}
            state_change_evidence = [{
                "source": "metasploit_rpc_state_change",
                "execution_id": base.get("execution_id"),
                "target_id": runtime_target.container_id,
                **item,
            } for item in _extract_state_changes(rpc_result)]
            self._observe(journal, "state_change", "metasploit_rpc_state_change",
                          data={"evidence": state_change_evidence},
                          summary=f"Collected {len(state_change_evidence)} structured state-change record(s).")
            if state_change_evidence:
                self._event("state_change_collected", run_id=run_id,
                            evidence_count=len(state_change_evidence))
            command_output, output_source = _extract_command_output(rpc_result)
            command_evidence = ([{"source": "metasploit_rpc_command_output",
                                  "execution_id": base.get("execution_id"),
                                  "target_id": runtime_target.container_id,
                                  "output": command_output, "source_detail": output_source}]
                                if command_output else [])
            session_command_evidence = []
            command_diagnostics = []
            if command_required and execution_succeeded:
                session_command_evidence, command_diagnostics = self.session_evidence_collector.collect(
                    raw["session_evidence"], target_host=runtime_target.host
                )
            bound_session_evidence = []
            for row in session_command_evidence:
                if not isinstance(row, dict) or not row.get("output"):
                    continue
                bound_session_evidence.append({
                    "source": "metasploit_rpc_command_output",
                    "execution_id": base.get("execution_id"),
                    "target_id": runtime_target.container_id,
                    "output": row["output"],
                    "source_detail": row.get("source_detail", "session.shell_read"),
                    "session_id": str(row.get("session_id", "")),
                })
            command_evidence.extend(bound_session_evidence)
            if bound_session_evidence:
                self._event("command_output_collected", run_id=run_id,
                            evidence_count=len(bound_session_evidence),
                            session_ids=[item["session_id"] for item in bound_session_evidence])
            file_artifact_evidence = []
            file_diagnostics = []
            if file_expectations:
                file_artifact_evidence, file_diagnostics = self._inspect_file_artifacts(
                    journal=journal,
                    expectations=file_expectations,
                    baselines=file_baselines,
                    inspector=file_artifact_inspector,
                    target_id=runtime_target.container_id,
                )
            diagnostics = _collect_diagnostics(diagnostics_callback) if raw["job_status"] != "completed" else {}
            if raw.get("error"):
                diagnostics["rpc"] = {"method": "module.results", "response": raw["result"]}
            if command_diagnostics:
                diagnostics["command_output"] = command_diagnostics
            if file_diagnostics:
                diagnostics["file_artifact"] = file_diagnostics
            if diagnostics:
                self._observe(journal, "diagnostics", "target_logs",
                              data=diagnostics, status="error",
                              summary="Collected failure diagnostics and target logs.")
                self._event("execution_diagnostics", run_id=run_id, diagnostics=diagnostics)
            result = ExecutionResult(**base, module_name=module.module_name,
                                     status="completed" if execution_succeeded else "failed",
                                     job_id=raw["job_id"], job_uuid=raw["job_uuid"], job_status=raw["job_status"],
                                     success_basis=success_basis,
                                     session_evidence=raw["session_evidence"],
                                     session_baseline=raw["session_baseline"], session_after=raw["session_after"],
                                     rpc_session_snapshot_collected=True, rpc_result=rpc_result,
                                     rpc_job_result_collected=True, command_output_evidence=command_evidence,
                                     file_artifact_evidence=file_artifact_evidence,
                                     state_change_evidence=state_change_evidence,
                                     diagnostics=diagnostics, verification_policy=verification_policy,
                                     console_output=(module.raw_output + "\n\n--- RPC execution result ---\n" +
                                                     json.dumps(raw["result"], ensure_ascii=False)),
                                     config_parameters=_redact_options(effective),
                                     started_at=started, ended_at=datetime.now(timezone.utc),
                                     errors=[] if execution_succeeded else
                                     [raw.get("error") or "Metasploit module job failed."])
        except Exception as exc:
            unsupported = isinstance(exc, UnsupportedExecutionError)
            self._event("execution_unsupported" if unsupported else "execution_failed",
                        run_id=run_id, module_name=module.module_name if module else None,
                        error_type=type(exc).__name__, error=str(exc))
            diagnostics = {} if unsupported else _collect_diagnostics(diagnostics_callback)
            file_artifact_evidence = []
            file_diagnostics = []
            if file_expectations and file_baselines and file_artifact_inspector is not None:
                file_artifact_evidence, file_diagnostics = self._inspect_file_artifacts(
                    journal=journal,
                    expectations=file_expectations,
                    baselines=file_baselines,
                    inspector=file_artifact_inspector,
                    target_id=base["target_id"],
                )
            if file_diagnostics:
                diagnostics["file_artifact"] = file_diagnostics
            self._observe(journal, "execution", "execution_error",
                          data={"error_type": type(exc).__name__, "error": str(exc),
                                "effective_configuration": _redact_options(effective)},
                          status="error", summary="Execution raised an exception.")
            job_id = job_uuid = None
            rpc_result = {}
            rpc_job_result_collected = False
            rpc_error = exc.rpc_error if isinstance(exc, MetasploitJobError) else (
                exc if isinstance(exc, MetasploitRpcError) else None
            )
            if isinstance(exc, MetasploitJobError):
                job_id, job_uuid = exc.job_id, exc.job_uuid
            if rpc_error is not None:
                rpc_result = rpc_error.response
                rpc_job_result_collected = rpc_error.method == "module.results"
                diagnostics["rpc"] = {"method": rpc_error.method, "response": rpc_error.response}
            if isinstance(rpc_result, dict) and not state_change_evidence:
                state_change_evidence = [{
                    "source": "metasploit_rpc_state_change",
                    "execution_id": base.get("execution_id"),
                    "target_id": base["target_id"],
                    **item,
                } for item in _extract_state_changes(rpc_result)]
            if diagnostics:
                self._observe(journal, "diagnostics", "target_logs",
                              data=diagnostics, status="error",
                              summary="Collected failure diagnostics and target logs.")
                self._event("execution_diagnostics", run_id=run_id, diagnostics=diagnostics)
            result = ExecutionResult(**base, module_name=module.module_name if module else None,
                                     status=("unsupported" if unsupported else
                                             "rejected" if isinstance(exc, PermissionError) else "failed"),
                                     job_id=job_id, job_uuid=job_uuid, rpc_result=rpc_result,
                                     rpc_job_result_collected=rpc_job_result_collected,
                                     file_artifact_evidence=file_artifact_evidence,
                                     state_change_evidence=state_change_evidence,
                                     diagnostics=diagnostics, verification_policy=verification_policy,
                                     config_parameters=_redact_options(effective),
                                     session_baseline=[str(key) for key in session_baseline],
                                     rpc_session_snapshot_collected=session_baseline_collected,
                                     console_output=module.raw_output if module else "",
                                     started_at=started, ended_at=datetime.now(timezone.utc), errors=[f"{type(exc).__name__}: {exc}"])
        self._save_evidence(result)
        return result

    def _save_evidence(self, result: ExecutionResult):
        if self.evidence_dir is None:
            return
        path = self.evidence_dir
        path.mkdir(parents=True, exist_ok=True)
        output = path / "execution-result.json"
        output.write_text(result.model_dump_json(indent=2), encoding="utf-8")


def _collect_diagnostics(callback: Callable[[], dict] | None) -> dict:
    if callback is None:
        return {}
    try:
        diagnostics = callback()
        return dict(diagnostics) if isinstance(diagnostics, dict) else {}
    except Exception as exc:
        return {"diagnostics_error": f"{type(exc).__name__}: {exc}"}


def _extract_state_changes(result: dict) -> list[dict]:
    candidates = []
    for container, prefix in ((result, "module.results"), (result.get("result"), "module.results.result")):
        if not isinstance(container, dict):
            continue
        single = container.get("state_change")
        if isinstance(single, dict):
            candidates.append((single, f"{prefix}.state_change"))
        multiple = container.get("state_changes")
        if isinstance(multiple, list):
            candidates.extend((item, f"{prefix}.state_changes") for item in multiple
                              if isinstance(item, dict))

    extracted = []
    for item, source_detail in candidates:
        indicator = item.get("indicator")
        before, after = item.get("before"), item.get("after")
        if not (isinstance(indicator, str) and 1 <= len(indicator.strip()) <= 100
                and not any(ord(ch) < 32 or ord(ch) == 127 for ch in indicator)):
            continue
        if not _valid_state_value(before) or not _valid_state_value(after):
            continue
        extracted.append({
            "indicator": indicator,
            "before": before,
            "after": after,
            "source_detail": source_detail,
        })
    return extracted


def _valid_state_value(value) -> bool:
    if isinstance(value, str):
        return 1 <= len(value.strip()) <= 200 and not any(
            ord(ch) < 32 or ord(ch) == 127 for ch in value
        )
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    return False


def _extract_command_output(result: dict) -> tuple[str, str]:
    candidates = [("command_output", result.get("command_output"))]
    nested = result.get("result")
    if isinstance(nested, dict):
        candidates.append(("result.command_output", nested.get("command_output")))
    for path, value in candidates:
        if isinstance(value, str) and value:
            return value, f"module.results.{path}"
    return "", "module.results"


def _redact_options(options: dict) -> dict[str, str]:
    return {
        key: ("[REDACTED]" if re.search("pass|token|secret", key, re.I) else str(value))
        for key, value in options.items()
    }


def _fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
