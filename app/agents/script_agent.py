"""Independent Python PoC generation, checking and isolated execution."""
from __future__ import annotations

import ast
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

from pydantic import BaseModel, ConfigDict, Field

from app.agents.execution import (
    ExecutionAuthorization,
    ExecutionAuthorizationRequest,
    ExecutionResult,
    RuntimeTarget,
)
from app.verification.models import CommandExpectation
from app.verification.policy import build_verification_policy


RESULT_MARKER = "__VULNFORGE_RESULT__"
_ALLOWED_IMPORTS = {
    "base64", "binascii", "hashlib", "hmac", "http", "ipaddress", "json",
    "os", "re", "socket", "ssl", "struct", "sys", "time", "urllib", "zlib",
}
_FORBIDDEN_CALLS = {
    "eval", "exec", "compile", "__import__", "breakpoint", "input", "memoryview",
}
_IP_LITERAL = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


class ScriptAgentError(RuntimeError):
    pass


class ScriptProgramCheckError(ValueError):
    pass


class _ScriptDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    python: str = Field(min_length=1, max_length=100_000)


class _ScriptReview(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    python: str = Field(min_length=1, max_length=100_000)


def extract_python(text: str) -> str:
    source = text.strip()
    if source.startswith("```"):
        lines = source.splitlines()
        if lines and lines[0].startswith("```python"):
            lines = lines[1:]
        elif lines:
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        source = "\n".join(lines).strip()
    if not source:
        raise ScriptProgramCheckError("Script Agent returned an empty program")
    return source


def check_python_program(source: str, *, target: RuntimeTarget) -> None:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ScriptProgramCheckError(f"Python syntax error: {exc.msg}") from exc
    allowed_addresses = {target.host}
    if target.oob_callback_host:
        allowed_addresses.add(target.oob_callback_host)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".", 1)[0] not in _ALLOWED_IMPORTS for alias in node.names):
                raise ScriptProgramCheckError("Program imports a module outside the sandbox allowlist")
        elif isinstance(node, ast.ImportFrom):
            if node.level or (node.module or "").split(".", 1)[0] not in _ALLOWED_IMPORTS:
                raise ScriptProgramCheckError("Program uses a relative or disallowed import")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in _FORBIDDEN_CALLS:
                raise ScriptProgramCheckError(f"Program calls forbidden function {node.func.id}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "system", "popen", "spawn", "fork", "execv", "execve", "remove", "unlink",
            }:
                raise ScriptProgramCheckError("Program invokes process or filesystem mutation APIs")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for literal in _IP_LITERAL.findall(node.value):
                try:
                    address = str(ipaddress.ip_address(literal))
                except ValueError:
                    raise ScriptProgramCheckError(f"Invalid IP literal: {literal}")
                if address not in allowed_addresses:
                    raise ScriptProgramCheckError("Program contains an address outside the runtime binding")
    if len(source.encode("utf-8")) > 100_000:
        raise ScriptProgramCheckError("Program exceeds the sandbox size limit")


def parse_program_result(output: str) -> dict:
    rows = [line[len(RESULT_MARKER):].strip() for line in output.splitlines()
            if line.startswith(RESULT_MARKER)]
    if not rows:
        return {}
    try:
        result = json.loads(rows[-1])
    except json.JSONDecodeError as exc:
        raise ScriptProgramCheckError("Program emitted malformed result JSON") from exc
    if not isinstance(result, dict):
        raise ScriptProgramCheckError("Program result must be a JSON object")
    return result


class IsolatedPythonRunner:
    def __init__(self, *, runner=subprocess.run, image="python:3.12-alpine",
                 timeout=120, memory="256m", cpus="1"):
        self.runner, self.image, self.timeout = runner, image, timeout
        self.memory, self.cpus = memory, cpus

    def run(self, source: str, *, target: RuntimeTarget, run_id: str,
            attempt: int, work_dir: Path) -> dict:
        work_dir.mkdir(parents=True, exist_ok=False)
        program = work_dir / "poc.py"
        program.write_text(source, encoding="utf-8")
        runtime_file = work_dir / "runtime.json"
        runtime_file.write_text(json.dumps({
            "ready": False, "callback_host": "0.0.0.0",
            "oob_callback_url": (f"http://{target.oob_callback_host}:{target.oob_callback_port}"
                                 f"/oob/{target.oob_token}" if target.oob_callback_host else None),
        }), encoding="utf-8")
        container = f"vulnforge-poc-{run_id[:8]}-{attempt}-{uuid.uuid4().hex[:8]}"
        command = [
            "docker", "run", "-d", "--rm", "--name", container,
            "--network", target.network_name, "--user", "65534:65534",
            "--network-alias", f"poc-{attempt}",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--pids-limit", "128", "--memory", self.memory,
            "--cpus", self.cpus, "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--pull=never",
            "--env", f"VULNFORGE_TARGET_HOST={target.host}",
            "--env", f"VULNFORGE_TARGET_PORT={target.port}",
            "--env", "VULNFORGE_CALLBACK_HOST=0.0.0.0",
            "--env", (f"VULNFORGE_OOB_CALLBACK_URL=http://{target.oob_callback_host}:"
                      f"{target.oob_callback_port}/oob/{target.oob_token}"
                      if target.oob_callback_host else "VULNFORGE_OOB_CALLBACK_URL="),
            "--env", f"VULNFORGE_CVE={target.cve_id}",
            "--mount", f"type=bind,source={program},target=/poc.py,readonly",
            "--mount", f"type=bind,source={runtime_file},target=/runtime.json,readonly",
            self.image, "sh", "-c",
            'while ! grep -q \'"ready":true\' /runtime.json; do sleep 0.05; done; '
            'exec python -I /poc.py',
        ]
        started = self.runner(command, capture_output=True, text=True, timeout=30)
        if started.returncode != 0 or not started.stdout.strip():
            return {"exit_code": started.returncode or 1, "stdout": started.stdout,
                    "stderr": started.stderr or "Sandbox container did not start", "container_id": None}
        container_id = started.stdout.strip()
        try:
            inspected = self.runner(
                ["docker", "inspect", container_id, "--format", "{{json .NetworkSettings.Networks}}"],
                capture_output=True, text=True, timeout=30)
            networks = json.loads(inspected.stdout)
            callback_host = networks[target.network_name]["IPAddress"]
            address = ipaddress.ip_address(callback_host)
            if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
                raise ScriptAgentError("Sandbox callback address is outside the private lab network")
        except Exception as exc:
            self.runner(["docker", "stop", "--time", "2", container_id], capture_output=True,
                        text=True, timeout=10)
            return {"exit_code": 1, "stdout": "", "stderr": f"Sandbox binding failed: {exc}",
                    "container_id": container_id}
        runtime_file.write_text(json.dumps({
            "ready": True, "callback_host": callback_host,
            "oob_callback_url": (f"http://{target.oob_callback_host}:{target.oob_callback_port}"
                                 f"/oob/{target.oob_token}" if target.oob_callback_host else None),
        }), encoding="utf-8")
        timed_out = False
        try:
            waited = self.runner(["docker", "wait", container_id], capture_output=True,
                                 text=True, timeout=self.timeout)
            exit_code = int(waited.stdout.strip()) if waited.returncode == 0 else waited.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
            self.runner(["docker", "stop", "--time", "2", container_id], capture_output=True,
                        text=True, timeout=10)
        logs = self.runner(["docker", "logs", container_id], capture_output=True,
                           text=True, timeout=30)
        return {"exit_code": exit_code, "stdout": logs.stdout, "stderr": logs.stderr,
                "container_id": container_id, "timed_out": timed_out}


_INSTRUCTIONS = """Generate one complete standalone Python PoC for an authorized isolated lab.
You are the Script Agent and must not depend on Metasploit or its modules. Use only the supplied
readable material and runtime bindings. Implement packet construction, payload delivery, callback
handling when needed, and verification output. Standard-library networking is sufficient.
Read target host/port from VULNFORGE_TARGET_HOST and VULNFORGE_TARGET_PORT. If a callback address
must be advertised, read /runtime.json and use callback_host; listeners may bind 0.0.0.0.
For out-of-band verification, use VULNFORGE_OOB_CALLBACK_URL when supplied; never invent a callback URL.
Never hard-code another host, use subprocess, import third-party packages, or mutate local files.
Print exactly one final line beginning __VULNFORGE_RESULT__ followed by a JSON object with optional
command_output, response, callback_received and state_changes fields. Return only Python source."""


class ScriptAgent:
    def __init__(self, runner, sandbox: IsolatedPythonRunner, *, max_attempts=3,
                 event_sink=None, evidence_dir: Path | None = None):
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self.runner, self.sandbox = runner, sandbox
        self.max_attempts, self.evidence_dir = max_attempts, evidence_dir
        self.event_sink = event_sink or (lambda event: None)

    def _event(self, kind, **fields):
        self.event_sink({"type": kind, "timestamp": datetime.now(timezone.utc).isoformat(), **fields})

    @staticmethod
    def _context(plan, target, document_markdown, runtime_target, feedback=None):
        return {
            "cve_id": plan.cve_id,
            "vulnerability_type": plan.vulnerability_type,
            "goal": plan.reproduction_goal,
            "document_markdown": document_markdown,
            "runtime_target": {
                "host": runtime_target.host, "port": runtime_target.port,
                "service": runtime_target.service, "os": runtime_target.os,
                "architecture": runtime_target.architecture,
                "oob_callback_url": (f"http://{runtime_target.oob_callback_host}:"
                                     f"{runtime_target.oob_callback_port}/oob/{runtime_target.oob_token}"
                                     if runtime_target.oob_callback_host else None),
            },
            "previous_attempt": feedback,
        }

    def run(self, *, plan, target, runtime_target: RuntimeTarget, run_id: str,
            document_markdown: str, authorization_callback, work_dir: Path) -> ExecutionResult:
        runtime_target.validate_local(target, plan, run_id)
        contract = plan.verification_contract
        policy = build_verification_policy(
            run_id=run_id, target_id=runtime_target.container_id,
            vulnerability_type=plan.vulnerability_type, contract=contract,
            module_type="script", module_name="script/python/poc",
            command_output_supported=True,
            command_expectations=(CommandExpectation(
                pattern=r"uid=\d+\([^)]+\).*\bgid=\d+\([^)]+\)",
                match_mode="regex", source="vulnforge.posix-id",
            ),) if contract else (),
            file_artifact_supported=True,
            file_expectations=contract.file_artifacts if contract else (),
            oob_callback_supported=runtime_target.oob_callback_host is not None,
        ) if contract else None
        context = self._context(plan, target, document_markdown, runtime_target)
        previous = None
        history = []
        last = None
        for attempt in range(1, self.max_attempts + 1):
            self._event("script_attempt_started", run_id=run_id, attempt=attempt)
            try:
                schema = _ScriptDraft if attempt == 1 else _ScriptReview
                instructions = _INSTRUCTIONS if attempt == 1 else _INSTRUCTIONS + (
                    "\nRepair the previous program using the supplied program check error or isolated"
                    " execution output. Keep the same authorized target and make the smallest necessary fix."
                )
                draft = self.runner.run(agent_name="Script Agent", instructions=instructions,
                                        input_text=json.dumps({**context, "previous_attempt": previous},
                                                              ensure_ascii=False), result_schema=schema)
                source = extract_python(draft.python)
                check_python_program(source, target=runtime_target)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                history.append({"attempt": attempt, "status": "check_failed", "error": error})
                self._event("script_check_failed", run_id=run_id, attempt=attempt, error=error)
                previous = {"program": locals().get("source"), "error": error}
                continue
            source_path = work_dir / "scripts" / f"attempt-{attempt}.py"
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text(source, encoding="utf-8")
            fingerprint = hashlib.sha256(source.encode()).hexdigest()
            request = ExecutionAuthorizationRequest(
                run_id=run_id, target_id=runtime_target.container_id,
                target_fingerprint=hashlib.sha256(runtime_target.model_dump_json().encode()).hexdigest(),
                plan_fingerprint=hashlib.sha256(plan.model_dump_json().encode()).hexdigest(),
                module_name=f"script/python/attempt-{attempt}", module_fingerprint=fingerprint,
                configuration_fingerprint=fingerprint,
                configuration_summary={"sandbox": self.sandbox.image, "program_sha256": fingerprint},
                verification_policy_id=policy.policy_id if policy else "verification-disabled",
            )
            try:
                grant = authorization_callback(request) if authorization_callback else None
                expected = request.model_dump()
                if (not isinstance(grant, ExecutionAuthorization) or not grant.approved
                        or any(getattr(grant, key) != value for key, value in expected.items())):
                    raise PermissionError("Script execution authorization is missing, denied or stale")
            except Exception as exc:
                return ExecutionResult(run_id=run_id, target_id=runtime_target.container_id,
                                       cve_id=plan.cve_id, target=runtime_target.model_dump(),
                                       module_name=request.module_name, status="rejected",
                                       attempt=attempt, attempt_history=history, errors=[str(exc)],
                                       verification_policy=policy)
            self._event("script_execution_started", run_id=run_id, attempt=attempt,
                        program_sha256=fingerprint)
            try:
                output = self.sandbox.run(source, target=runtime_target, run_id=run_id,
                                          attempt=attempt, work_dir=work_dir / "sandboxes" / str(attempt))
                result_data = parse_program_result(output["stdout"])
                status = "completed" if output["exit_code"] == 0 else "failed"
                command_output = result_data.get("command_output")
                rows = ([{"source": "script_command_output", "execution_id": str(uuid.uuid4()),
                          "target_id": runtime_target.container_id, "output": command_output}]
                        if isinstance(command_output, str) and command_output else [])
                last = ExecutionResult(
                    run_id=run_id, target_id=runtime_target.container_id, cve_id=plan.cve_id,
                    target=runtime_target.model_dump(), module_name=request.module_name,
                    status=status, success_basis="none", attempt=attempt,
                    command_output_evidence=rows, console_output=output["stdout"],
                    rpc_result={"script": result_data, "container_id": output.get("container_id")},
                    diagnostics={"stderr": output["stderr"][-8000:], "exit_code": output["exit_code"],
                                 "timed_out": output.get("timed_out", False)},
                    errors=[] if status == "completed" else [output["stderr"][-2000:] or "PoC exited unsuccessfully"],
                    verification_policy=policy,
                )
                last = last.model_copy(update={"execution_id": rows[0]["execution_id"]}) if rows else last
            except Exception as exc:
                last = ExecutionResult(run_id=run_id, target_id=runtime_target.container_id,
                                       cve_id=plan.cve_id, target=runtime_target.model_dump(),
                                       module_name=request.module_name, status="failed", attempt=attempt,
                                       errors=[f"{type(exc).__name__}: {exc}"], verification_policy=policy)
            history.append({"attempt": attempt, "status": last.status, "errors": last.errors,
                            "stdout": last.console_output[-4000:], "stderr": last.diagnostics.get("stderr", "")})
            self._event("script_execution_completed", run_id=run_id, attempt=attempt, status=last.status,
                        note="Execution status is not verification success")
            previous = history[-1]
            if last.status == "completed":
                break
        if last is None:
            last = ExecutionResult(run_id=run_id, target_id=runtime_target.container_id,
                                   cve_id=plan.cve_id, target=runtime_target.model_dump(),
                                   module_name="script/python/poc", status="failed",
                                   errors=["No generated program passed program checking"],
                                   verification_policy=policy)
        last = last.model_copy(update={"attempt_history": history})
        if self.evidence_dir:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            (self.evidence_dir / "script-result.json").write_text(last.model_dump_json(indent=2), encoding="utf-8")
        return last
