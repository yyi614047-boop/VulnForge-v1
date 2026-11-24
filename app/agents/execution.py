"""Single-shot Metasploit execution agent for an attested local Vulhub target."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.agents.file_write_profiles import file_write_profile
from app.agents.metasploit_executor import MetasploitExecutor, MetasploitJobError
from app.agents.metasploit_rpc import MetasploitRpcError
from app.agents.module_catalog import MetasploitSearch, ModuleMetadata, ModuleOption
from app.agents.planner import ReproductionPlan
from app.agents.runner import AgentRunner
from app.agents.session_evidence import POSIX_ID_EXPECTATION, SessionEvidenceCollector
from app.targets.material import TargetMaterial
from app.verification.models import CommandExpectation, VerificationPolicy


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
    local_vulhub: Literal[True] = True

    @classmethod
    def from_vulhub(cls, *, target: TargetMaterial, run_id: str, service: str,
                    port: int, host: str, project: str, container_id: str,
                    network_name: str, network_id: str,
                    callback_host: str | None = None) -> "RuntimeTarget":
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
                   network_id=network_id, compose_sha256=compose_sha256)

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
    session_evidence: list[dict] = Field(default_factory=list)
    session_baseline: list[str] = Field(default_factory=list)
    session_after: list[dict] = Field(default_factory=list)
    rpc_session_snapshot_collected: bool = False
    rpc_result: dict = Field(default_factory=dict)
    rpc_job_result_collected: bool = False
    command_output_evidence: list[dict] = Field(default_factory=list)
    file_artifact_evidence: list[dict] = Field(default_factory=list)
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


_SELECT_INSTRUCTIONS = """Select one module only from candidate names supplied by the application. Judge applicability only from module metadata and provided target service/prerequisites. Return null if uncertain. Never invent names or configuration values."""

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


_PAYLOAD_NAME = re.compile(r"^[a-z0-9_+-]+(?:/[a-z0-9_+-]+)+$")


def _select_payload(*, module: ModuleMetadata, payloads: list[str]) -> tuple[str, str]:
    candidates = list(dict.fromkeys(
        name for name in payloads if isinstance(name, str) and _PAYLOAD_NAME.fullmatch(name)
    ))
    for preferred in (
        "cmd/unix/reverse_bash",
        "cmd/unix/reverse_python",
        "cmd/unix/reverse_netcat",
        "cmd/unix/reverse",
    ):
        if preferred in candidates:
            return preferred, "short_command"
    unix_commands = sorted(name for name in candidates if name.startswith("cmd/unix/") and "reverse" in name)
    if unix_commands:
        return unix_commands[0], "short_command"
    commands = sorted(name for name in candidates if name.startswith("cmd/") and "reverse" in name)
    if commands:
        return commands[0], "command"
    if "generic/shell_reverse_tcp" in candidates:
        return "generic/shell_reverse_tcp", "generic_shell"
    shells = sorted(name for name in candidates
                    if name.endswith("/shell_reverse_tcp") or name.endswith("/shell/reverse_tcp"))
    if shells:
        return shells[0], "native_shell"
    meterpreters = sorted(name for name in candidates
                          if name.endswith("/meterpreter_reverse_tcp") or name.endswith("/meterpreter/reverse_tcp"))
    if meterpreters:
        return meterpreters[0], "meterpreter_fallback"
    raise ValueError(f"No reliable reverse-session payload is compatible with {module.module_name}")


def _select_target_port(*, module: ModuleMetadata, target: TargetMaterial, service: str) -> int:
    default = next((option.current_value for option in module.options if option.name == "RPORT"), None)
    if default is not None and str(default).strip().isdigit():
        port = int(str(default).strip())
        if 1 <= port <= 65535:
            return port

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
    if not declared:
        raise ValueError("The selected target service declares no TCP port")
    raise ValueError(
        "Cannot infer target port: the module has no default RPORT and the service declares multiple ports: "
        + ", ".join(str(port) for port in sorted(declared))
    )


class ExecutionAgent:
    def __init__(self, search: MetasploitSearch, executor: MetasploitExecutor,
                 *, runner: AgentRunner | None = None, event_sink: Callable[[dict], None] | None = None,
                 evidence_dir: Path | None = None,
                 session_evidence_collector: SessionEvidenceCollector | None = None):
        self.search, self.executor, self.runner = search, executor, runner
        self.session_evidence_collector = session_evidence_collector or SessionEvidenceCollector(executor.rpc)
        self.event_sink, self.evidence_dir = event_sink or (lambda event: None), evidence_dir

    def _event(self, kind, **details):
        self.event_sink({"type": kind, "timestamp": datetime.now(timezone.utc).isoformat(), **details})

    def run(self, *, plan: ReproductionPlan, target: TargetMaterial,
            runtime_target: RuntimeTarget | None = None, run_id: str,
            target_resolver: Callable[[int], RuntimeTarget] | None = None,
            authorized: bool = False, options: dict[str, str] | None = None,
            verification_expectations: tuple[CommandExpectation, ...] = (),
            authorization_callback: Callable[[ExecutionAuthorizationRequest], ExecutionAuthorization | None] | None = None,
            diagnostics_callback: Callable[[], dict] | None = None,
            file_artifact_inspector: Callable[[str], dict] | None = None) -> ExecutionResult:
        base = dict(run_id=run_id, execution_id=str(uuid.uuid4()),
                    target_id=runtime_target.container_id if runtime_target else f"unresolved:{run_id}",
                    cve_id=plan.cve_id, target=runtime_target.model_dump() if runtime_target else {})
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
        try:
            self._event("module_search_started", run_id=run_id, cve_id=plan.cve_id)
            names = self.search.search(plan.cve_id)
            self._event("module_candidates_found", run_id=run_id, module_names=names)
            if not names:
                result = ExecutionResult(**base, status="unsupported", errors=["No Metasploit modules matched this CVE."], started_at=started, ended_at=datetime.now(timezone.utc))
                self._save_evidence(result)
                return result
            metadata = [self.search.inspect(plan.cve_id, name) for name in names[:20]]
            if self.runner:
                raw = self.runner.run(agent_name="Execution Agent", instructions=_SELECT_INSTRUCTIONS,
                                      input_text=json.dumps({"candidates": [m.model_dump() for m in metadata],
                                                             "service": plan.target_service,
                                                             "prerequisites": plan.prerequisites}), result_schema=_Selection)
                selection = raw.module_name
            else:
                selection = next((m.module_name for m in metadata if m.module_type == "exploit"
                                  and plan.cve_id.upper() in {r.upper() for r in m.references}), None)
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
            self._event("module_configuration_started", run_id=run_id, module_name=module.module_name)
            contract = plan.verification_contract
            if contract is None:
                raise ValueError("Reproduction plan has no verification contract")
            file_required = any(
                requirement.kind == "file_artifact" and requirement.required
                for requirement in contract.evidence_requirements
            )
            file_profile = file_write_profile(module.module_name) if file_required else None
            if file_required and file_profile is None:
                raise UnsupportedExecutionError(
                    "No trusted File Write verification profile is available for the selected module."
                )
            if file_required and file_artifact_inspector is None:
                raise UnsupportedExecutionError("File artifact inspection is unavailable for this run.")
            supplied = dict(options or {})
            if file_profile is not None:
                for key, value in file_profile.options.items():
                    if key in supplied and supplied[key] != value:
                        raise ValueError(f"File Write verification requires fixed {key}={value}.")
                    supplied[key] = value
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
            known = {o.name: o for o in module.options}
            if module.session_capable:
                known.setdefault("PAYLOAD", ModuleOption(name="PAYLOAD"))
            if set(supplied) - set(known):
                raise ValueError("Configuration contains options absent from module metadata")
            if any(k in supplied for k in ("RHOST", "RHOSTS", "RPORT")):
                raise PermissionError("Target options are derived by the execution agent")
            if any(any(ord(ch) < 32 for ch in value) for value in supplied.values()):
                raise PermissionError("Control-character module options are disabled")
            command_required = any(
                requirement.kind == "command_output" and requirement.required
                for requirement in contract.evidence_requirements
            )
            direct_command_output = command_required and "CMD" in known
            session_command_output = command_required and module.session_capable
            if command_required and not (direct_command_output or session_command_output):
                raise UnsupportedExecutionError(
                    "The selected module cannot provide structured command output."
                )
            auto_payload = module.session_capable and "PAYLOAD" in known and "PAYLOAD" not in supplied
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
                if supplied.get("CMD", "id") != "id":
                    raise ValueError("The command-output contract requires fixed CMD=id.")
                effective["CMD"] = "id"
            missing = [o.name for o in module.options if o.required and not effective.get(o.name)
                       and not (auto_payload and o.name == "PAYLOAD")]
            if missing:
                raise ValueError("Required module options missing: " + ", ".join(missing))
            if auto_payload:
                payloads = self.executor.compatible_payloads(module)
                if direct_command_output:
                    if "cmd/unix/generic" not in payloads:
                        raise UnsupportedExecutionError(
                            "The selected module has no compatible cmd/unix/generic payload for command-output evidence."
                        )
                    payload, reason = "cmd/unix/generic", "verification_contract"
                else:
                    payload, reason = _select_payload(module=module, payloads=payloads)
                effective["PAYLOAD"] = payload
                self._event("payload_selected", run_id=run_id, module_name=module.module_name,
                            payload=payload, reason=reason)
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
                file_artifact_supported=file_profile is not None,
                file_expectations=(file_profile.expectation,) if file_profile is not None else (),
            )
            if verification_policy.unsupported_reason:
                raise UnsupportedExecutionError(verification_policy.unsupported_reason)
            self._event("verification_policy_frozen", run_id=run_id,
                        module_name=module.module_name, policy_id=verification_policy.policy_id,
                        contract=contract.model_dump(mode="json"))
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
                configuration_summary={
                    key: ("[REDACTED]" if re.search("pass|token|secret", key, re.I) else str(value))
                    for key, value in effective.items()
                },
                verification_policy_id=verification_policy.policy_id,
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
            file_baseline = None
            if file_profile is not None:
                file_baseline = file_artifact_inspector(file_profile.expectation.path_pattern)
                if not isinstance(file_baseline, dict) or not isinstance(file_baseline.get("matches"), list):
                    raise RuntimeError("File artifact inspector returned a malformed baseline")
            self._event("module_configuration_completed", run_id=run_id, module_name=module.module_name,
                        options={k: ("[REDACTED]" if re.search("pass|token|secret", k, re.I) else v) for k, v in effective.items()})
            self._event("exploit_started", run_id=run_id, module_name=module.module_name)
            raw = self.executor.execute(module, effective, session_baseline=session_baseline)
            self._event("exploit_completed", run_id=run_id, module_name=module.module_name,
                        job_id=raw["job_id"], job_status=raw["job_status"])
            if raw["job_status"] != "completed":
                self._event("execution_failed", run_id=run_id, module_name=module.module_name,
                            job_id=raw["job_id"], job_status=raw["job_status"], error="Metasploit job failed")
            if raw["session_evidence"]:
                self._event("session_detected", run_id=run_id, sessions=raw["session_evidence"])
            rpc_result = raw["result"] if isinstance(raw["result"], dict) else {"value": str(raw["result"])}
            command_output, output_source = _extract_command_output(rpc_result)
            command_evidence = ([{"source": "metasploit_rpc_command_output",
                                  "execution_id": base.get("execution_id"),
                                  "target_id": runtime_target.container_id,
                                  "output": command_output, "source_detail": output_source}]
                                if command_output else [])
            session_command_evidence = []
            command_diagnostics = []
            if command_required and raw["job_status"] == "completed":
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
            if file_profile is not None and raw["job_status"] == "completed":
                try:
                    file_after = file_artifact_inspector(file_profile.expectation.path_pattern)
                    if not isinstance(file_after, dict) or not isinstance(file_after.get("matches"), list):
                        raise RuntimeError("File artifact inspector returned a malformed result")
                    baseline_paths = {item.get("path") for item in file_baseline.get("matches", [])
                                      if isinstance(item, dict) and item.get("path")}
                    new_files = [item for item in file_after["matches"]
                                 if isinstance(item, dict) and item.get("path") not in baseline_paths]
                    file_artifact_evidence.append({
                        "source": "vulhub_runtime_file_artifact",
                        "execution_id": base.get("execution_id"),
                        "target_id": runtime_target.container_id,
                        "path_pattern": file_profile.expectation.path_pattern,
                        "existed_before": bool(baseline_paths),
                        "exists_after": bool(file_after["matches"]),
                        "new_files": new_files,
                    })
                    if new_files:
                        self._event("file_artifact_collected", run_id=run_id,
                                    path_pattern=file_profile.expectation.path_pattern,
                                    new_file_count=len(new_files))
                except Exception as exc:
                    file_diagnostics.append({"error": f"{type(exc).__name__}: {exc}"})
            diagnostics = _collect_diagnostics(diagnostics_callback) if raw["job_status"] != "completed" else {}
            if command_diagnostics:
                diagnostics["command_output"] = command_diagnostics
            if file_diagnostics:
                diagnostics["file_artifact"] = file_diagnostics
            if diagnostics:
                self._event("execution_diagnostics", run_id=run_id, diagnostics=diagnostics)
            result = ExecutionResult(**base, module_name=module.module_name,
                                     status="completed" if raw["job_status"] == "completed" else "failed",
                                     job_id=raw["job_id"], job_uuid=raw["job_uuid"], job_status=raw["job_status"],
                                     session_evidence=raw["session_evidence"],
                                     session_baseline=raw["session_baseline"], session_after=raw["session_after"],
                                     rpc_session_snapshot_collected=True, rpc_result=rpc_result,
                                     rpc_job_result_collected=True, command_output_evidence=command_evidence,
                                     file_artifact_evidence=file_artifact_evidence,
                                     diagnostics=diagnostics, verification_policy=verification_policy,
                                     console_output=(module.raw_output + "\n\n--- RPC execution result ---\n" +
                                                     json.dumps(raw["result"], ensure_ascii=False)),
                                     config_parameters={k: ("[REDACTED]" if re.search("pass|token|secret", k, re.I) else str(v)) for k, v in effective.items()},
                                     started_at=started, ended_at=datetime.now(timezone.utc),
                                     errors=[] if raw["job_status"] == "completed" else ["Metasploit module job failed."])
        except Exception as exc:
            unsupported = isinstance(exc, UnsupportedExecutionError)
            self._event("execution_unsupported" if unsupported else "execution_failed",
                        run_id=run_id, module_name=module.module_name if module else None,
                        error_type=type(exc).__name__, error=str(exc))
            diagnostics = {} if unsupported else _collect_diagnostics(diagnostics_callback)
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
            if diagnostics:
                self._event("execution_diagnostics", run_id=run_id, diagnostics=diagnostics)
            result = ExecutionResult(**base, module_name=module.module_name if module else None,
                                     status=("unsupported" if unsupported else
                                             "rejected" if isinstance(exc, PermissionError) else "failed"),
                                     job_id=job_id, job_uuid=job_uuid, rpc_result=rpc_result,
                                     rpc_job_result_collected=rpc_job_result_collected,
                                     diagnostics=diagnostics, verification_policy=verification_policy,
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


def _extract_command_output(result: dict) -> tuple[str, str]:
    candidates = [("command_output", result.get("command_output"))]
    nested = result.get("result")
    if isinstance(nested, dict):
        candidates.append(("result.command_output", nested.get("command_output")))
    for path, value in candidates:
        if isinstance(value, str) and value:
            return value, f"module.results.{path}"
    return "", "module.results"


def _fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
