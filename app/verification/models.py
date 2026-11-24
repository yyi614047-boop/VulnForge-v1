"""Shared immutable policy, evidence and result contracts."""
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.verification.contracts import FileArtifactExpectation, FrozenModel, VerificationContract


class CommandExpectation(FrozenModel):
    """An operator/application supplied match fixed before the exploit runs."""
    pattern: str = Field(min_length=1, max_length=500)
    match_mode: Literal["literal", "regex"] = "literal"
    source: str = Field(min_length=1, max_length=200)


class VerificationPolicy(FrozenModel):
    run_id: str = Field(min_length=1, max_length=128)
    target_id: str = Field(min_length=1, max_length=200)
    vulnerability_type: str = Field(min_length=1, max_length=100)
    contract: VerificationContract
    accepted_rules: tuple[str, ...] = Field(default=(), max_length=10)
    command_expectations: tuple[CommandExpectation, ...] = Field(default=(), max_length=10)
    file_expectations: tuple[FileArtifactExpectation, ...] = Field(default=(), max_length=10)
    policy_id: str = Field(min_length=1, max_length=128)
    unsupported_reason: str | None = None


class Evidence(FrozenModel):
    evidence_id: str = Field(min_length=1, max_length=256)
    evidence_type: str = Field(min_length=1, max_length=100)
    run_id: str = Field(min_length=1, max_length=128)
    target_id: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=200)
    collected_at: datetime
    raw_reference: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceBundle(FrozenModel):
    run_id: str
    target_id: str
    execution_id: str
    evidence: tuple[Evidence, ...] = ()


class RuleResult(FrozenModel):
    rule_name: str
    status: Literal["success", "failed", "inconclusive"]
    reason: str
    evidence_ids: tuple[str, ...] = ()


class VerificationResult(FrozenModel):
    run_id: str
    target_id: str
    vulnerability_type: str
    result_label: str
    status: Literal["success", "failed", "inconclusive", "verification_unsupported"]
    rule_results: tuple[RuleResult, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    matched_rule_names: tuple[str, ...] = ()
    matched_evidence_ids: tuple[str, ...] = ()
    reason: str
