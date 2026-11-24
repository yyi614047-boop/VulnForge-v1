"""Deterministic verification over independently collected HTTP responses."""
from app.verification.models import Evidence, RuleResult, VerificationPolicy


def verify_http_response_observed(*, policy: VerificationPolicy,
                                  evidence: tuple[Evidence, ...],
                                  execution_id: str) -> RuleResult:
    if not policy.http_expectations:
        return RuleResult(rule_name="http_response_observed", status="inconclusive",
                          reason="No HTTP request and response expectation was frozen before execution.")
    records = [item for item in evidence
               if item.evidence_type == "http_response"
               and item.source == "vulnforge_http_probe"
               and item.metadata.get("execution_id") == execution_id
               and item.metadata.get("target_id") == policy.target_id]
    if not records:
        return RuleResult(rule_name="http_response_observed", status="inconclusive",
                          reason="No target-bound HTTP response was independently collected.")

    matched = []
    for expectation in policy.http_expectations:
        expected = expectation.model_dump(mode="json")
        for record in records:
            metadata = record.metadata
            if metadata.get("expectation") != expected:
                continue
            if metadata.get("error") or metadata.get("truncated"):
                continue
            if metadata.get("status") != expectation.expected_status:
                continue
            body = metadata.get("body", "")
            if expectation.body_contains is not None and expectation.body_contains not in body:
                continue
            if expectation.header_contains is not None:
                headers = {
                    str(name).casefold(): str(value)
                    for name, value in metadata.get("headers", [])
                }
                if expectation.header_contains not in headers.get(expectation.header_name.casefold(), ""):
                    continue
            matched.append(record.evidence_id)
            break
    if matched:
        return RuleResult(
            rule_name="http_response_observed", status="success",
            reason="An independently collected HTTP response matched the frozen status and content expectation.",
            evidence_ids=tuple(dict.fromkeys(matched)),
        )
    return RuleResult(
        rule_name="http_response_observed", status="inconclusive",
        reason="No collected HTTP response matched the frozen status and content expectation.",
        evidence_ids=tuple(item.evidence_id for item in records),
    )
