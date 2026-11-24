"""Single-shot Metasploit job execution and session snapshots."""
from __future__ import annotations

import time

from app.agents.metasploit_rpc import MetasploitRpcError, rpc_field, rpc_text
from app.agents.module_catalog import ModuleMetadata


class MetasploitJobError(RuntimeError):
    def __init__(self, message: str, *, job_id: int, job_uuid: str, rpc_error: MetasploitRpcError):
        super().__init__(message)
        self.job_id = job_id
        self.job_uuid = job_uuid
        self.rpc_error = rpc_error


class MetasploitExecutor:
    def __init__(self, rpc, *, timeout=120, poll_interval=.2,
                 clock=time.monotonic, sleeper=time.sleep):
        self.rpc, self.timeout, self.poll_interval = rpc, timeout, poll_interval
        self.clock, self.sleeper = clock, sleeper

    def snapshot_sessions(self) -> dict:
        result = self.rpc.call("session.list") or {}
        if not isinstance(result, dict):
            raise RuntimeError("Metasploit returned a malformed pre-execution session list")
        return result

    def compatible_payloads(self, module: ModuleMetadata) -> list[str]:
        result = self.rpc.call("module.compatible_payloads", module.module_name)
        payloads = rpc_field(result, "payloads") if isinstance(result, dict) else None
        if not isinstance(payloads, list) or any(not isinstance(name, str) for name in payloads):
            raise RuntimeError("Metasploit returned a malformed compatible payload list")
        return payloads

    def execute(self, module: ModuleMetadata, options: dict[str, str], *,
                session_baseline: dict | None = None) -> dict:
        before = session_baseline if session_baseline is not None else self.snapshot_sessions()
        ticket = self.rpc.call("module.execute", module.module_type,
                               module.module_name.split("/", 1)[1], options)
        job_id_value = rpc_field(ticket, "job_id") if isinstance(ticket, dict) else None
        job_uuid_value = rpc_field(ticket, "uuid") if isinstance(ticket, dict) else None
        if job_id_value is None or not job_uuid_value:
            raise RuntimeError(f"Metasploit returned an invalid job ticket: {ticket!r}")
        job_id, job_uuid = int(job_id_value), rpc_text(job_uuid_value)

        def job_call(method, *args):
            try:
                return self.rpc.call(method, *args)
            except MetasploitRpcError as exc:
                raise MetasploitJobError(str(exc), job_id=job_id, job_uuid=job_uuid,
                                         rpc_error=exc) from exc

        deadline = self.clock() + self.timeout
        result = None
        error = None
        try:
            while self.clock() < deadline:
                result = job_call("module.results", job_uuid)
                if isinstance(result, dict) and result.get("status") in {"completed", "failed", "errored", "error"}:
                    break
                self.sleeper(self.poll_interval)
            else:
                job_call("job.stop", job_id)
                stop_deadline = self.clock() + 5
                while self.clock() < stop_deadline:
                    active = job_call("job.list")
                    if isinstance(active, dict) and str(job_id) not in {str(key) for key in active}:
                        break
                    self.sleeper(min(self.poll_interval or .1, max(0, stop_deadline - self.clock())))
                else:
                    raise RuntimeError(f"Metasploit job {job_uuid} could not be confirmed stopped")
                raise TimeoutError(f"Metasploit job {job_uuid} timed out; stop requested")
        except MetasploitJobError as exc:
            result = exc.rpc_error.response if isinstance(exc.rpc_error.response, dict) else {
                "status": "errored", "error": str(exc),
            }
            error = str(exc)
        after = job_call("session.list") or {}
        evidence = []
        for sid, value in after.items():
            if str(sid) not in {str(k) for k in before} and isinstance(value, dict):
                evidence.append({"session_id": str(sid), **value})
        return {"job_id": job_id, "job_uuid": job_uuid, "job_status": result.get("status"),
                "result": result, "error": error, "session_evidence": evidence,
                "session_baseline": [str(key) for key in before],
                "session_after": [{"session_id": str(key), **value} for key, value in after.items()
                                  if isinstance(value, dict)]}
