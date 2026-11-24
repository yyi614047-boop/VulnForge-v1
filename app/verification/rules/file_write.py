"""Deterministic verification for newly created target files."""
from app.verification.models import Evidence, RuleResult, VerificationPolicy


def verify_file_artifact_observed(*, policy: VerificationPolicy,
                                  evidence: tuple[Evidence, ...],
                                  execution_id: str) -> RuleResult:
    if not policy.file_expectations:
        return RuleResult(rule_name="file_artifact_observed", status="inconclusive",
                          reason="No file artifact expectation was frozen before execution.")
    records = [item for item in evidence
               if item.evidence_type == "target_file_artifact"
               and item.source == "vulhub_runtime_file_artifact"
               and item.metadata.get("execution_id") == execution_id
               and item.metadata.get("target_id") == policy.target_id]
    if not records:
        return RuleResult(rule_name="file_artifact_observed", status="inconclusive",
                          reason="No target-bound file artifact was collected.")

    used = []
    for expectation in policy.file_expectations:
        matched = False
        for record in records:
            metadata = record.metadata
            if (metadata.get("path_pattern") == expectation.path_pattern
                    and metadata.get("existed_before") is False
                    and metadata.get("exists_after") is True
                    and metadata.get("new_files")):
                matched = True
                used.append(record.evidence_id)
                break
        if not matched:
            return RuleResult(rule_name="file_artifact_observed", status="inconclusive",
                              reason="The frozen file artifact was not newly observed on the target.",
                              evidence_ids=tuple(item.evidence_id for item in records))
    return RuleResult(rule_name="file_artifact_observed", status="success",
                      reason="All frozen file artifacts were newly observed on the target.",
                      evidence_ids=tuple(dict.fromkeys(used)))
