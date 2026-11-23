"""Deterministic verification policy selection, performed before execution."""
import hashlib
import json
import re

from app.verification.models import CommandExpectation, VerificationPolicy


def build_verification_policy(*, run_id: str, target_id: str, vulnerability_type: str,
                              module_type: str, module_name: str,
                              session_capable: bool = False,
                              command_expectations: tuple[CommandExpectation, ...] = ()) -> VerificationPolicy:
    category = vulnerability_type.casefold()
    reason = None
    if category != "rce":
        reason = f"Verification is not implemented for {vulnerability_type}."
    elif module_type != "exploit" or not module_name.startswith("exploit/"):
        reason = "RCE verification requires a selected Metasploit exploit module."
    rules = ["session_established"] if session_capable and reason is None else []
    if command_expectations:
        validate_expectations(command_expectations)
        if reason is None:
            rules.append("command_output_match")
    if not rules:
        reason = reason or "Selected module has no deterministic RCE evidence capability."
    identity = {"run_id": run_id, "target_id": target_id, "vulnerability_type": vulnerability_type,
                "accepted_rules": rules,
                "command_expectations": [x.model_dump(mode="json") for x in command_expectations],
                "module_name": module_name, "session_capable": session_capable,
                "unsupported_reason": reason}
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24]
    return VerificationPolicy(run_id=run_id, target_id=target_id, vulnerability_type=vulnerability_type,
                              accepted_rules=tuple(rules), command_expectations=command_expectations,
                              policy_id=f"verification-{digest}", unsupported_reason=reason)


def validate_expectations(expectations: tuple[CommandExpectation, ...]) -> None:
    """Reject invalid patterns before a policy can be frozen."""
    for expectation in expectations:
        if expectation.match_mode == "regex":
            try:
                re.compile(expectation.pattern)
            except re.error as exc:
                raise ValueError(f"Invalid pre-execution command output pattern: {exc}") from exc
