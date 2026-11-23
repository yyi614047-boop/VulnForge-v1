"""RCE-specific checks over collected, run-bound RPC evidence."""
import re

from app.verification.models import Evidence, RuleResult, VerificationPolicy


ALLOWED_SESSION_TYPES = {"shell", "meterpreter"}


def verify_session_established(*, policy: VerificationPolicy,
                               evidence: tuple[Evidence, ...]) -> RuleResult:
    records = [e for e in evidence if e.evidence_type == "metasploit_session_delta"
               and e.source == "metasploit_rpc"]
    if not records:
        return RuleResult(rule_name="session_established", status="inconclusive",
                          reason="No Metasploit RPC session delta was collected.")
    used = []
    for record in records:
        data = record.metadata
        baseline = {str(x) for x in data.get("baseline_session_ids", [])}
        for session in data.get("sessions_after", []):
            if not isinstance(session, dict):
                continue
            sid = str(session.get("session_id", ""))
            if not sid or sid in baseline:
                continue
            session_type = str(session.get("type", session.get("session_type", ""))).casefold()
            host = session.get("target_host") or session.get("session_host")
            if session_type in ALLOWED_SESSION_TYPES and host == data.get("target_host"):
                used.append(record.evidence_id)
    if used:
        return RuleResult(rule_name="session_established", status="success",
                          reason="A new supported session was observed on the target.",
                          evidence_ids=tuple(dict.fromkeys(used)))
    return RuleResult(rule_name="session_established", status="inconclusive",
                      reason="No new supported session was observed on the target.",
                      evidence_ids=tuple(e.evidence_id for e in records))


def verify_command_output_match(*, policy: VerificationPolicy, evidence: tuple[Evidence, ...],
                                execution_id: str, module_name: str | None = None) -> RuleResult:
    if not policy.command_expectations:
        return RuleResult(rule_name="command_output_match", status="inconclusive",
                          reason="No command output expectation was frozen before execution.")
    records = [e for e in evidence if e.evidence_type == "metasploit_command_output"
               and e.source == "metasploit_rpc_command_output"
               and e.metadata.get("execution_id") == execution_id
               and e.metadata.get("target_id") == policy.target_id]
    if not records:
        return RuleResult(rule_name="command_output_match", status="inconclusive",
                          reason="No target-bound command output from the Metasploit execution was collected.")
    output = "\n".join(str(e.metadata.get("output", "")) for e in records)
    matched = []
    for expected in policy.command_expectations:
        try:
            found = (expected.pattern in output if expected.match_mode == "literal"
                     else re.search(expected.pattern, output) is not None)
        except re.error:
            found = False
        if found:
            matched.append(expected.source)
    if matched:
        return RuleResult(rule_name="command_output_match", status="success",
                          reason="Metasploit command output matched a pre-execution expectation.",
                          evidence_ids=tuple(e.evidence_id for e in records))
    return RuleResult(rule_name="command_output_match", status="inconclusive",
                      reason="Collected command output did not match the frozen expectation.",
                      evidence_ids=tuple(e.evidence_id for e in records))
