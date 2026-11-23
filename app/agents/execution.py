"""Single-shot Metasploit execution agent for an attested local Vulhub target."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import ssl
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field

from app.agents.planner import ReproductionPlan
from app.agents.runner import AgentRunner
from app.runtime.config import ConfigurationError
from app.targets.material import TargetMaterial
from app.verification.models import CommandExpectation, VerificationPolicy


class RuntimeTarget(BaseModel):
    """Endpoint resolved by the active local lab runtime, never by a model."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(min_length=1, max_length=128)
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    project: str = Field(pattern=r"^lab-[a-z0-9][a-z0-9_-]{0,48}$")
    service: str = Field(min_length=1, max_length=64)
    host: str = Field(min_length=1, max_length=45)
    port: int = Field(ge=1, le=65535)
    container_id: str = Field(min_length=12, max_length=128)
    network_name: str = Field(min_length=1, max_length=128)
    network_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    compose_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    local_vulhub: Literal[True] = True

    @classmethod
    def from_vulhub(cls, *, target: TargetMaterial, run_id: str, service: str,
                    port: int, host: str, project: str, container_id: str,
                    network_name: str, network_id: str) -> "RuntimeTarget":
        """Bind runtime Docker observations to the selected local Compose service."""
        cve = target.identifier.upper()
        services = target.attributes.get("compose", {}).get("services", {})
        if service not in services or not isinstance(services[service], dict):
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
            except ValueError: pass
        if port not in allowed_container_ports:
            raise PermissionError("Runtime target port is absent from the selected local Compose service")
        compose_sha256 = hashlib.sha256(
            json.dumps(target.attributes["compose"], sort_keys=True).encode()
        ).hexdigest()
        return cls(run_id=run_id, cve_id=cve, project=project, service=service,
                   host=host, port=port, container_id=container_id,
                   network_name=network_name, network_id=network_id,
                   compose_sha256=compose_sha256)

    def validate_local(self, target: TargetMaterial, plan: ReproductionPlan, run_id: str) -> None:
        if self.run_id != run_id or self.cve_id != target.identifier.upper() or plan.cve_id != self.cve_id:
            raise PermissionError("Plan, Vulhub target and runtime endpoint must match this run and CVE")
        if target.environment.name.upper() != self.cve_id:
            raise PermissionError("Resolved environment is not the local Vulhub directory for this CVE")
        services = target.attributes.get("compose", {}).get("services", {})
        if self.service not in services or self.compose_sha256 != hashlib.sha256(
            json.dumps(target.attributes["compose"], sort_keys=True).encode()
        ).hexdigest():
            raise PermissionError("Runtime endpoint is not bound to the current local Compose service")
        ip = ipaddress.ip_address(self.host)
        if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local:
            raise PermissionError("Runtime target must be a private IPv4 endpoint on the local lab network")


class ModuleOption(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    required: bool = False
    current_value: str | None = None
    description: str = ""


class ModuleMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    module_name: str
    module_type: Literal["exploit", "auxiliary"]
    name: str = ""
    description: str = ""
    platforms: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    session_capable: bool = False
    options: list[ModuleOption] = Field(default_factory=list)
    raw_output: str = ""


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
    verification_policy_id: str
    session_baseline_ids: tuple[str, ...] = ()
    approved: bool


class MetasploitSearch:
    """Read-only msfconsole CVE search and module inspection, compatible with v0."""
    MODULE_RE = re.compile(r"(?:exploit|auxiliary)/[A-Za-z0-9_./-]+")
    CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

    def __init__(self, *, container: str | None = None, executable: str = "msfconsole",
                 runner: Callable = subprocess.run, timeout: int = 180):
        self.container, self.executable, self.runner, self.timeout = container, executable, runner, timeout

    @classmethod
    def from_env(cls):
        return cls(container=os.getenv("MSF_CONTAINER_NAME") or None)

    def _console(self, command: str) -> str:
        argv = (["docker", "exec", self.container,
                 "/usr/src/metasploit-framework/msfconsole", "-q", "-x", command]
                if self.container else [self.executable, "-q", "-x", command])
        result = self.runner(argv, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=self.timeout, shell=False)
        output = ((result.stdout or "") + "\n" + (result.stderr or ""))[-32000:]
        if result.returncode:
            raise RuntimeError(f"Metasploit search failed ({result.returncode}): {output[-2000:]}")
        return output

    def search(self, cve_id: str) -> list[str]:
        if not self.CVE_RE.fullmatch(cve_id):
            raise ValueError("Invalid CVE identifier")
        found = self.MODULE_RE.findall(self._console(f"search cve:{cve_id.upper()}; exit"))
        return list(dict.fromkeys(x for x in found if all(p not in {"", ".", ".."} for p in x.split("/"))))

    def inspect(self, cve_id: str, module_name: str) -> ModuleMetadata:
        if not self.MODULE_RE.fullmatch(module_name) or ".." in module_name.split("/"):
            raise ValueError("Invalid Metasploit module name")
        raw = self._console(f"info {module_name}; exit")
        def field(label):
            m = re.search(rf"^\s*{label}\s*:\s*(.+)$", raw, re.I | re.M)
            return m.group(1).strip() if m else ""
        refs = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d{4,}", raw, re.I)))
        options = []
        in_options = False
        for line in raw.splitlines():
            if re.match(r"\s*(Basic|Advanced) Options\s*:?", line, re.I):
                in_options = True
                continue
            if in_options and re.match(r"\s*(Description|References|Targets|Payload information)\s*:?", line, re.I):
                in_options = False
            if in_options:
                m = re.match(r"^\s*([A-Z][A-Z0-9_]*)\s+(.*?)\s+(yes|no)\s{2,}(.+)$", line, re.I)
                if m:
                    options.append(ModuleOption(name=m.group(1), current_value=m.group(2).strip() or None,
                                                required=m.group(3).lower() == "yes", description=m.group(4).strip()))
        return ModuleMetadata(module_name=module_name, module_type=module_name.split("/", 1)[0],
                              name=field("Name"), description=raw[-12000:], references=refs,
                              raw_output=raw, options=options,
                              session_capable=(any(o.name == "PAYLOAD" for o in options)
                                               or bool(re.search(r"^\s*Payload information\s*:", raw, re.I | re.M))))


class MessagePackTransport:
    def __init__(self, host="127.0.0.1", port=55553, timeout=15, opener=urlopen):
        ip = ipaddress.ip_address(host)
        if not ip.is_loopback:
            raise ValueError("RPC connection must use loopback")
        self.host, self.port, self.timeout, self.opener = host, port, timeout, opener

    def call(self, method, *params):
        import msgpack
        req = Request(f"http://{self.host}:{self.port}/api/",
                      data=msgpack.packb([method, *params], use_bin_type=True),
                      headers={"Content-Type": "binary/message-pack"}, method="POST")
        try:
            with self.opener(req, timeout=self.timeout, context=None) as response:
                result = msgpack.unpackb(response.read(), raw=False, strict_map_key=False)
        except Exception as exc:
            raise RuntimeError(f"Metasploit RPC transport failed: {exc}") from exc
        if isinstance(result, dict) and result.get("error"):
            raise RuntimeError(str(result.get("error_message") or result.get("error_class") or result["error"]))
        return result


class DockerExecMessagePackTransport:
    """Use the legacy loopback RPC endpoint inside the already-running MSF container."""
    def __init__(self, container: str, port=55553, timeout=15, runner=subprocess.run):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", container):
            raise ValueError("Invalid Metasploit container name")
        self.container, self.port, self.timeout, self.runner = container, port, timeout, runner

    def call(self, method, *params):
        import base64
        import msgpack
        payload = msgpack.packb([method, *params], use_bin_type=True)
        ruby = ("require 'base64'; require 'net/http'; require 'uri'; "
                f"u=URI('http://127.0.0.1:{self.port}/api/'); "
                "r=Net::HTTP::Post.new(u); r['Content-Type']='binary/message-pack'; "
                "r['Accept']='binary/message-pack'; r.body=STDIN.read; "
                f"h=Net::HTTP.new(u.host,u.port,nil); h.open_timeout={self.timeout}; "
                f"h.read_timeout={self.timeout}; x=h.start{{|c|c.request(r)}}; "
                "STDOUT.write(Base64.strict_encode64(x.body))")
        try:
            result = self.runner(["docker", "exec", "-i", self.container, "ruby", "-e", ruby],
                                 input=payload, capture_output=True, timeout=self.timeout + 5, check=False)
            if result.returncode:
                raise RuntimeError("Docker Exec RPC command failed")
            raw = result.stdout.decode("ascii") if isinstance(result.stdout, bytes) else result.stdout
            response = msgpack.unpackb(base64.b64decode(raw), raw=False, strict_map_key=False)
        except Exception as exc:
            raise RuntimeError(f"Metasploit Docker Exec RPC failed: {exc}") from exc
        if isinstance(response, dict) and response.get("error"):
            raise RuntimeError(str(response.get("error_message") or response.get("error_class") or response["error"]))
        return response


class MetasploitRpc:
    ALLOWED = {"module.execute", "module.results", "job.list", "job.stop", "session.list", "console.create", "console.read", "console.destroy"}
    def __init__(self, transport, username: str, password: str):
        if not username or not password:
            raise ConfigurationError("MSFRPC_USER and MSFRPC_PASS are required")
        self.transport, self.username, self.password, self.token = transport, username, password, None

    @classmethod
    def from_env(cls):
        container = os.getenv("MSF_CONTAINER_NAME", "").strip()
        transport = (DockerExecMessagePackTransport(container, int(os.getenv("MSFRPC_CONTAINER_PORT", "55553")))
                     if os.getenv("MSFRPC_TRANSPORT", "docker-exec") == "docker-exec" and container
                     else MessagePackTransport(os.getenv("MSFRPC_HOST", "127.0.0.1"),
                                               int(os.getenv("MSFRPC_PORT", "55553"))))
        return cls(transport,
                   os.getenv("MSFRPC_USER", ""), os.getenv("MSFRPC_PASS", ""))

    def call(self, method, *args):
        if method not in self.ALLOWED:
            raise PermissionError("RPC method is not exposed")
        if self.token is None:
            auth = self.transport.call("auth.login", self.username, self.password)
            if not isinstance(auth, dict) or auth.get("result") != "success" or not auth.get("token"):
                raise RuntimeError("Metasploit RPC authentication failed")
            self.token = auth["token"]
        return self.transport.call(method, self.token, *args)


class MetasploitExecutor:
    def __init__(self, rpc, *, timeout=120, poll_interval=.2, clock=time.monotonic, sleeper=time.sleep):
        self.rpc, self.timeout, self.poll_interval = rpc, timeout, poll_interval
        self.clock, self.sleeper = clock, sleeper

    def snapshot_sessions(self) -> dict:
        result = self.rpc.call("session.list") or {}
        if not isinstance(result, dict):
            raise RuntimeError("Metasploit returned a malformed pre-execution session list")
        return result

    def execute(self, module: ModuleMetadata, options: dict[str, str], *, session_baseline: dict | None = None) -> dict:
        before = session_baseline if session_baseline is not None else self.snapshot_sessions()
        ticket = self.rpc.call("module.execute", module.module_type,
                               module.module_name.split("/", 1)[1], options)
        if not isinstance(ticket, dict) or not ticket.get("job_id") or not ticket.get("uuid"):
            raise RuntimeError("Metasploit returned an invalid job ticket")
        job_id, job_uuid = int(ticket["job_id"]), str(ticket["uuid"])
        deadline = self.clock() + self.timeout
        result = None
        while self.clock() < deadline:
            result = self.rpc.call("module.results", job_uuid)
            if isinstance(result, dict) and result.get("status") in {"completed", "failed", "errored", "error"}:
                break
            self.sleeper(self.poll_interval)
        else:
            self.rpc.call("job.stop", job_id)
            stop_deadline = self.clock() + 5
            while self.clock() < stop_deadline:
                active = self.rpc.call("job.list")
                if isinstance(active, dict) and str(job_id) not in {str(key) for key in active}:
                    break
                self.sleeper(min(self.poll_interval or .1, max(0, stop_deadline - self.clock())))
            else:
                raise RuntimeError(f"Metasploit job {job_uuid} could not be confirmed stopped")
            raise TimeoutError(f"Metasploit job {job_uuid} timed out; stop requested")
        after = self.rpc.call("session.list") or {}
        evidence = []
        for sid, value in after.items():
            if str(sid) not in {str(k) for k in before} and isinstance(value, dict):
                evidence.append({"session_id": str(sid), **value})
        return {"job_id": job_id, "job_uuid": job_uuid, "job_status": result.get("status"),
                "result": result, "session_evidence": evidence,
                "session_baseline": [str(key) for key in before],
                "session_after": [{"session_id": str(key), **value} for key, value in after.items()
                                  if isinstance(value, dict)]}


_SELECT_INSTRUCTIONS = """Select one module only from candidate names supplied by the application. Judge applicability only from module metadata and provided target service/prerequisites. Return null if uncertain. Never invent names or configuration values."""


class _Selection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    module_name: str | None


class ExecutionAgent:
    def __init__(self, search: MetasploitSearch, executor: MetasploitExecutor,
                 *, runner: AgentRunner | None = None, event_sink: Callable[[dict], None] | None = None,
                 evidence_dir: Path | None = None):
        self.search, self.executor, self.runner = search, executor, runner
        self.event_sink, self.evidence_dir = event_sink or (lambda event: None), evidence_dir

    def _event(self, kind, **details):
        self.event_sink({"type": kind, "timestamp": datetime.now(timezone.utc).isoformat(), **details})

    def run(self, *, plan: ReproductionPlan, target: TargetMaterial, runtime_target: RuntimeTarget,
            run_id: str, authorized: bool = False, options: dict[str, str] | None = None,
            verification_expectations: tuple[CommandExpectation, ...] = (),
            authorization_callback: Callable[[ExecutionAuthorizationRequest], ExecutionAuthorization | None] | None = None) -> ExecutionResult:
        base = dict(run_id=run_id, execution_id=str(uuid.uuid4()),
                    target_id=runtime_target.container_id,
                    cve_id=plan.cve_id, target=runtime_target.model_dump())
        try:
            if not plan.executable or plan.status != "ready":
                raise ValueError("Reproduction plan is not executable")
            if plan.execution_method != "metasploit" or plan.target_service != runtime_target.service:
                raise PermissionError("Plan method or target service does not match the resolved target")
            runtime_target.validate_local(target, plan, run_id)
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
                # Safe deterministic selection when no analysis runner was injected.
                selection = next((m.module_name for m in metadata if m.module_type == "exploit"
                                  and plan.cve_id.upper() in {r.upper() for r in m.references}), None)
            # LLM selections are accepted only by identity from actual search results.
            module = next((m for m in metadata if m.module_name == selection), None)
            if module is None:
                result = ExecutionResult(**base, status="unsupported", errors=["No applicable searched module was selected."], started_at=started, ended_at=datetime.now(timezone.utc))
                result.console_output = "\n".join(m.raw_output for m in metadata)
                self._save_evidence(result)
                return result
            if module.module_type != "exploit" or plan.cve_id.upper() not in {x.upper() for x in module.references}:
                result = ExecutionResult(**base, status="unsupported", module_name=module.module_name,
                                       console_output=module.raw_output, errors=["Candidate does not establish CVE applicability as an exploit."],
                                       started_at=started, ended_at=datetime.now(timezone.utc))
                self._save_evidence(result)
                return result
            self._event("module_selected", run_id=run_id, module_name=module.module_name)
            self._event("module_configuration_started", run_id=run_id, module_name=module.module_name)
            supplied = dict(options or {})
            known = {o.name: o for o in module.options}
            if set(supplied) - set(known):
                raise ValueError("Configuration contains options absent from module metadata")
            if any(k in supplied for k in ("RHOST", "RHOSTS", "RPORT")):
                raise PermissionError("Target options are derived by the execution agent")
            forbidden_options = {"CMD", "COMMAND", "COMMANDS", "EXEC", "SCRIPT", "SCRIPT_PATH",
                                 "COMMAND_STAGER", "PAYLOAD"}
            if set(supplied) & forbidden_options or any(
                any(ord(ch) < 32 for ch in value) for value in supplied.values()
            ):
                raise PermissionError("Shell, script and control-character module options are disabled")
            effective = supplied.copy()
            if "RHOSTS" in known: effective["RHOSTS"] = runtime_target.host
            if "RHOST" in known: effective["RHOST"] = runtime_target.host
            if "RPORT" in known: effective["RPORT"] = str(runtime_target.port)
            for o in module.options:
                if o.required and o.name not in effective and o.current_value:
                    effective[o.name] = o.current_value
            missing = [o.name for o in module.options if o.required and not effective.get(o.name)]
            if missing: raise ValueError("Required module options missing: " + ", ".join(missing))
            if any(k in effective for k in ("LHOST", "SRVHOST", "LPORT", "SRVPORT", "PAYLOAD")):
                raise PermissionError("Payload and callback configuration is disabled in this execution stage")
            # Freeze deterministic verification criteria after module selection and before exploit.
            from app.verification.policy import build_verification_policy
            verification_policy = build_verification_policy(
                run_id=run_id, target_id=runtime_target.container_id,
                vulnerability_type=plan.vulnerability_type,
                module_type=module.module_type, module_name=module.module_name,
                session_capable=module.session_capable,
                command_expectations=verification_expectations,
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
            self._event("module_configuration_completed", run_id=run_id, module_name=module.module_name,
                        options={k: ("[REDACTED]" if re.search("pass|token|secret", k, re.I) else v) for k,v in effective.items()})
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
            command_output = rpc_result.get("command_output")
            command_evidence = ([{"source": "metasploit_rpc_command_output",
                                  "execution_id": base.get("execution_id"),
                                  "target_id": runtime_target.container_id,
                                  "output": command_output, "source_detail": "module.results"}]
                                if isinstance(command_output, str) and command_output else [])
            result = ExecutionResult(**base, module_name=module.module_name,
                                     status="completed" if raw["job_status"] == "completed" else "failed",
                                     job_id=raw["job_id"], job_uuid=raw["job_uuid"], job_status=raw["job_status"],
                                     session_evidence=raw["session_evidence"],
                                     session_baseline=raw["session_baseline"], session_after=raw["session_after"],
                                     rpc_session_snapshot_collected=True, rpc_result=rpc_result,
                                     rpc_job_result_collected=True, command_output_evidence=command_evidence,
                                     verification_policy=verification_policy,
                                     console_output=(module.raw_output + "\n\n--- RPC execution result ---\n" +
                                                     json.dumps(raw["result"], ensure_ascii=False)),
                                     config_parameters={k: ("[REDACTED]" if re.search("pass|token|secret", k, re.I) else v) for k,v in effective.items()},
                                     started_at=started, ended_at=datetime.now(timezone.utc),
                                     errors=[] if raw["job_status"] == "completed" else ["Metasploit module job failed."])
        except Exception as exc:
            self._event("execution_failed", run_id=run_id, module_name=module.module_name if module else None,
                        error_type=type(exc).__name__, error=str(exc))
            result = ExecutionResult(**base, module_name=module.module_name if module else None,
                                     status="rejected" if isinstance(exc, PermissionError) else "failed",
                                     verification_policy=verification_policy,
                                     session_baseline=[str(key) for key in session_baseline],
                                     rpc_session_snapshot_collected=session_baseline_collected,
                                     console_output=module.raw_output if module else "",
                                     started_at=started, ended_at=datetime.now(timezone.utc), errors=[f"{type(exc).__name__}: {exc}"])
        self._save_evidence(result)
        return result

    def _save_evidence(self, result: ExecutionResult):
        if self.evidence_dir is None:
            return
        path = self.evidence_dir / result.run_id
        path.mkdir(parents=True, exist_ok=True)
        output = path / "execution-result.json"
        output.write_text(result.model_dump_json(indent=2), encoding="utf-8")


def _fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
