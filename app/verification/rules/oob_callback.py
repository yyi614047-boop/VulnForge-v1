"""Deterministic verification for token-bound out-of-band callbacks."""
from app.verification.models import Evidence, RuleResult, VerificationPolicy


def verify_oob_callback_observed(*, policy: VerificationPolicy,
                                 evidence: tuple[Evidence, ...],
                                 execution_id: str) -> RuleResult:
    if not policy.oob_expectations:
        return RuleResult(rule_name="oob_callback_observed", status="inconclusive",
                          reason="No OOB token and path expectation was frozen before execution.")
    records = [item for item in evidence
               if item.evidence_type == "oob_callback"
               and item.source == "vulnforge_oob_collector"
               and item.metadata.get("execution_id") == execution_id
               and item.metadata.get("target_id") == policy.target_id]
    if not records:
        return RuleResult(rule_name="oob_callback_observed", status="inconclusive",
                          reason="No target-bound OOB callback was collected.")

    matched = []
    for expectation in policy.oob_expectations:
        for record in records:
            metadata = record.metadata
            if (metadata.get("expectation") == expectation.model_dump(mode="json")
                    and metadata.get("token") == expectation.token
                    and metadata.get("path") == expectation.path
                    and metadata.get("remote_host") == metadata.get("target_host")
                    and metadata.get("remote_host")):
                matched.append(record.evidence_id)
                break
    if matched:
        return RuleResult(
            rule_name="oob_callback_observed", status="success",
            reason="A callback with the frozen token and path was collected from the target network.",
            evidence_ids=tuple(dict.fromkeys(matched)),
        )
    return RuleResult(
        rule_name="oob_callback_observed", status="inconclusive",
        reason="No callback matched the frozen token, path and target binding.",
        evidence_ids=tuple(item.evidence_id for item in records),
    )
