"""Fixed-command evidence collection from newly created shell sessions."""
from __future__ import annotations

import re
import time

from app.agents.metasploit_rpc import rpc_field, rpc_text
from app.verification.models import CommandExpectation


POSIX_ID_EXPECTATION = CommandExpectation(
    pattern=r"(?m)^uid=\d+\([^\r\n)]+\)\s+gid=\d+\([^\r\n)]+\)",
    match_mode="regex",
    source="builtin:posix-id",
)


class SessionEvidenceCollector:
    def __init__(self, rpc, *, timeout=10, poll_interval=.2,
                 clock=time.monotonic, sleeper=time.sleep):
        self.rpc, self.timeout, self.poll_interval = rpc, timeout, poll_interval
        self.clock, self.sleeper = clock, sleeper

    def collect(self, sessions: list[dict], *, target_host: str) -> tuple[list[dict], list[dict]]:
        evidence = []
        diagnostics = []
        for session in sessions:
            if not isinstance(session, dict):
                continue
            session_type = str(session.get("type", session.get("session_type", ""))).casefold()
            host = session.get("target_host") or session.get("session_host")
            session_id = str(session.get("session_id", ""))
            if session_type != "shell" or host != target_host or not session_id:
                continue
            try:
                self.rpc.call("session.shell_write", session_id, "id\n")
                deadline = self.clock() + self.timeout
                chunks = []
                output = ""
                while self.clock() < deadline:
                    response = self.rpc.call("session.shell_read", session_id)
                    chunk = rpc_field(response, "result") if isinstance(response, dict) else response
                    chunk = rpc_text(chunk) if chunk is not None else ""
                    if chunk:
                        chunks.append(chunk)
                        output = "".join(chunks)[-65536:]
                    if re.search(POSIX_ID_EXPECTATION.pattern, output):
                        break
                    self.sleeper(self.poll_interval)
                if output:
                    evidence.append({
                        "session_id": session_id,
                        "output": output,
                        "source_detail": "session.shell_read",
                    })
            except Exception as exc:
                diagnostics.append({
                    "session_id": session_id,
                    "error": f"{type(exc).__name__}: {exc}",
                })
        return evidence, diagnostics
