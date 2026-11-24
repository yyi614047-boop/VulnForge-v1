"""Deterministic verification for exact database-derived response values."""
from app.verification.models import Evidence, RuleResult, VerificationPolicy


def verify_database_result_observed(*, policy: VerificationPolicy,
                                    evidence: tuple[Evidence, ...],
                                    execution_id: str) -> RuleResult:
    if not policy.database_results:
        return RuleResult(rule_name="database_result_observed", status="inconclusive",
                          reason="No database result probe was frozen before execution.")
    records = [item for item in evidence
               if item.evidence_type == "http_response"
               and item.source == "vulnforge_http_probe"
               and item.metadata.get("execution_id") == execution_id
               and item.metadata.get("target_id") == policy.target_id]
    if not records:
        return RuleResult(rule_name="database_result_observed", status="inconclusive",
                          reason="No independently collected response is available for database verification.")

    matched = []
    for expectation in policy.database_results:
        probe = expectation.probe.model_dump(mode="json")
        for record in records:
            metadata = record.metadata
            if (metadata.get("expectation") == probe
                    and not metadata.get("error") and not metadata.get("truncated")
                    and metadata.get("status") == expectation.probe.expected_status
                    and expectation.result_contains in metadata.get("body", "")):
                matched.append(record.evidence_id)
                break
    if matched:
        return RuleResult(
            rule_name="database_result_observed", status="success",
            reason="An independently collected response contained the frozen database-derived value.",
            evidence_ids=tuple(dict.fromkeys(matched)),
        )
    return RuleResult(
        rule_name="database_result_observed", status="inconclusive",
        reason="No collected response contained the frozen database-derived value.",
        evidence_ids=tuple(item.evidence_id for item in records),
    )
