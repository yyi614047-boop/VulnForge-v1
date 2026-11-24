"""Deterministic verification for structured Metasploit state transitions."""
import json
import math

from app.verification.models import Evidence, RuleResult, VerificationPolicy


def _valid_indicator(value) -> bool:
    return (isinstance(value, str) and 1 <= len(value.strip()) <= 100
            and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value))


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


def verify_state_change_observed(*, policy: VerificationPolicy,
                                 evidence: tuple[Evidence, ...],
                                 execution_id: str) -> RuleResult:
    records = [item for item in evidence
               if item.evidence_type == "metasploit_state_change"
               and item.source == "metasploit_rpc_state_change"
               and item.metadata.get("execution_id") == execution_id
               and item.metadata.get("target_id") == policy.target_id]
    if not records:
        return RuleResult(
            rule_name="state_change_observed",
            status="inconclusive",
            reason="No target-bound structured state change was collected from Metasploit.",
        )
    if not policy.state_expectations:
        return RuleResult(
            rule_name="state_change_observed",
            status="inconclusive",
            reason="No state transition expectation was frozen before execution.",
            evidence_ids=tuple(item.evidence_id for item in records),
        )

    valid_records = []
    for record in records:
        metadata = record.metadata
        before, after = metadata.get("before"), metadata.get("after")
        if not _valid_indicator(metadata.get("indicator")):
            continue
        if not _valid_state_value(before) or not _valid_state_value(after):
            continue
        valid_records.append(record)

    if not valid_records:
        return RuleResult(
            rule_name="state_change_observed",
            status="inconclusive",
            reason="Collected state-change records did not contain a valid indicator and scalar before/after values.",
            evidence_ids=tuple(item.evidence_id for item in records),
        )

    matched = []
    expected_indicators = {item.indicator for item in policy.state_expectations}
    contradicted = []
    for record in valid_records:
        metadata = record.metadata
        for expected in policy.state_expectations:
            if (metadata.get("indicator") == expected.indicator
                    and _state_key(metadata.get("before")) == _state_key(expected.before)
                    and _state_key(metadata.get("after")) == _state_key(expected.after)):
                matched.append(record.evidence_id)
                break
        else:
            if metadata.get("indicator") in expected_indicators:
                contradicted.append(record.evidence_id)

    if matched:
        return RuleResult(
            rule_name="state_change_observed",
            status="success",
            reason="A target-bound Metasploit result matched the frozen before/after state transition.",
            evidence_ids=tuple(dict.fromkeys(matched)),
        )
    if contradicted:
        return RuleResult(
            rule_name="state_change_observed",
            status="failed",
            reason="Structured Metasploit evidence contradicted the frozen state transition.",
            evidence_ids=tuple(dict.fromkeys(contradicted)),
        )
    return RuleResult(
        rule_name="state_change_observed",
        status="inconclusive",
        reason="Collected state changes did not address the frozen indicator.",
        evidence_ids=tuple(item.evidence_id for item in valid_records),
    )


def _state_key(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
