"""Deterministic verification policy selection, performed before execution."""
import hashlib
import json
import re

from app.verification.contracts import VerificationContract
from app.verification.models import (
    CommandExpectation,
    DatabaseResultExpectation,
    FileArtifactExpectation,
    HttpExpectation,
    OobExpectation,
    StateChangeExpectation,
    VerificationPolicy,
)
from app.verification.registry import validate_contract


def _policy_identity(*, run_id: str, target_id: str, vulnerability_type: str,
                     contract: VerificationContract, accepted_rules: tuple[str, ...],
                     command_expectations: tuple[CommandExpectation, ...],
                     file_expectations: tuple[FileArtifactExpectation, ...],
                     state_expectations: tuple[StateChangeExpectation, ...],
                     http_expectations: tuple[HttpExpectation, ...],
                     oob_expectations: tuple[OobExpectation, ...],
                     database_results: tuple[DatabaseResultExpectation, ...],
                     unsupported_reason: str | None) -> dict:
    return {
        "run_id": run_id,
        "target_id": target_id,
        "vulnerability_type": vulnerability_type,
        "contract": contract.model_dump(mode="json"),
        "accepted_rules": accepted_rules,
        "command_expectations": [item.model_dump(mode="json") for item in command_expectations],
        "file_expectations": [item.model_dump(mode="json") for item in file_expectations],
        "state_expectations": [item.model_dump(mode="json") for item in state_expectations],
        "http_expectations": [item.model_dump(mode="json") for item in http_expectations],
        "oob_expectations": [item.model_dump(mode="json") for item in oob_expectations],
        "database_results": [item.model_dump(mode="json") for item in database_results],
        "unsupported_reason": unsupported_reason,
    }


def _policy_id(identity: dict) -> str:
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()[:24]
    return f"verification-{digest}"


def compute_policy_id(policy: VerificationPolicy) -> str:
    return _policy_id(_policy_identity(
        run_id=policy.run_id,
        target_id=policy.target_id,
        vulnerability_type=policy.vulnerability_type,
        contract=policy.contract,
        accepted_rules=policy.accepted_rules,
        command_expectations=policy.command_expectations,
        file_expectations=policy.file_expectations,
        state_expectations=policy.state_expectations,
        http_expectations=policy.http_expectations,
        oob_expectations=policy.oob_expectations,
        database_results=policy.database_results,
        unsupported_reason=policy.unsupported_reason,
    ))


def build_verification_policy(*, run_id: str, target_id: str, vulnerability_type: str,
                              contract: VerificationContract,
                              module_type: str, module_name: str,
                              session_capable: bool = False,
                              command_output_supported: bool = False,
                              command_expectations: tuple[CommandExpectation, ...] = (),
                              file_artifact_supported: bool = False,
                              file_expectations: tuple[FileArtifactExpectation, ...] = (),
                              oob_callback_supported: bool = False) -> VerificationPolicy:
    validate_expectations(command_expectations)
    file_expectations = file_expectations or contract.file_artifacts
    state_expectations = contract.state_changes
    http_expectations = contract.http_expectations
    oob_expectations = contract.oob_expectations
    database_results = contract.database_results
    reason = validate_contract(vulnerability_type=vulnerability_type, contract=contract)
    if reason is None and not (
        (module_type == "exploit" and module_name.startswith("exploit/"))
        or (module_type == "script" and module_name.startswith("script/python/"))
    ):
        reason = "Verification requires a selected exploit module or standalone Python PoC."
    if reason is None:
        for requirement in contract.evidence_requirements:
            if not requirement.required:
                continue
            if requirement.kind == "session" and not session_capable:
                reason = "The selected module cannot provide the required session evidence."
            elif requirement.kind == "command_output":
                if not command_output_supported:
                    reason = "The selected module cannot provide structured command output."
                elif not command_expectations:
                    reason = "Command output verification requires a frozen application expectation."
            elif requirement.kind == "http_response":
                if not http_expectations:
                    reason = "HTTP response verification requires a frozen request and response expectation."
            elif requirement.kind == "oob_callback":
                if not oob_callback_supported or not oob_expectations:
                    reason = "OOB callback verification requires a running isolated collector and frozen token."
            elif requirement.kind == "database_result":
                if not database_results:
                    reason = "Database result verification requires a frozen probe and exact result."
            elif requirement.kind == "file_artifact":
                if not file_artifact_supported:
                    reason = "The selected runtime cannot inspect the required file artifact."
                elif not file_expectations:
                    reason = "File artifact verification requires a frozen application expectation."
            if reason is not None:
                break
    rule_names = tuple(requirement.rule_name for requirement in contract.evidence_requirements)
    accepted_rules = rule_names if reason is None else ()
    identity = _policy_identity(
        run_id=run_id,
        target_id=target_id,
        vulnerability_type=vulnerability_type,
        contract=contract,
        accepted_rules=accepted_rules,
        command_expectations=command_expectations,
        file_expectations=file_expectations,
        state_expectations=state_expectations,
        http_expectations=http_expectations,
        oob_expectations=oob_expectations,
        database_results=database_results,
        unsupported_reason=reason,
    )
    return VerificationPolicy(
        run_id=run_id,
        target_id=target_id,
        vulnerability_type=vulnerability_type,
        contract=contract,
        accepted_rules=accepted_rules,
        command_expectations=command_expectations,
        file_expectations=file_expectations,
        state_expectations=state_expectations,
        http_expectations=http_expectations,
        oob_expectations=oob_expectations,
        database_results=database_results,
        policy_id=_policy_id(identity),
        unsupported_reason=reason,
    )


def validate_expectations(expectations: tuple[CommandExpectation, ...]) -> None:
    """Reject invalid patterns before a policy can be frozen."""
    for expectation in expectations:
        if expectation.match_mode == "regex":
            try:
                re.compile(expectation.pattern)
            except re.error as exc:
                raise ValueError(f"Invalid pre-execution command output pattern: {exc}") from exc
