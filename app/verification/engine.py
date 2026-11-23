"""Category-neutral deterministic verification orchestration."""
from app.verification.models import EvidenceBundle, VerificationPolicy, VerificationResult
from app.verification.rules.rce import verify_command_output_match, verify_session_established


RULES = {
    "RCE": {
        "session_established": verify_session_established,
        "command_output_match": verify_command_output_match,
    },
}


class VerificationEngine:
    def verify(self, *, policy: VerificationPolicy, execution, evidence: EvidenceBundle) -> VerificationResult:
        common = dict(run_id=policy.run_id, target_id=policy.target_id,
                      vulnerability_type=policy.vulnerability_type)
        if execution.run_id != policy.run_id or evidence.run_id != policy.run_id:
            return VerificationResult(**common, status="failed", reason="Execution or evidence run ID differs from frozen policy.")
        if execution.target_id != policy.target_id or evidence.target_id != policy.target_id:
            return VerificationResult(**common, status="failed", reason="Execution or evidence target ID differs from frozen policy.")
        if evidence.execution_id != execution.execution_id:
            return VerificationResult(**common, status="failed", reason="Evidence is not bound to this execution.")
        if any(e.run_id != policy.run_id or e.target_id != policy.target_id for e in evidence.evidence):
            return VerificationResult(**common, status="failed", reason="Evidence contains a foreign run or target.")
        if execution.status in {"failed", "rejected"}:
            return VerificationResult(**common, status="failed", evidence_ids=tuple(e.evidence_id for e in evidence.evidence),
                                      reason="Execution has an explicit failure or rejection status.")
        if execution.verification_policy is None or execution.verification_policy != policy:
            return VerificationResult(**common, status="failed",
                                      reason="Verification policy is missing or differs from the policy frozen before execution.")
        if policy.unsupported_reason or policy.vulnerability_type.upper() not in RULES or not policy.accepted_rules:
            return VerificationResult(**common, status="verification_unsupported",
                                      reason=policy.unsupported_reason or "No deterministic verification rules are available for this category.")
        category = RULES[policy.vulnerability_type.upper()]
        results = []
        for name in policy.accepted_rules:
            rule = category.get(name)
            if rule is None:
                return VerificationResult(**common, status="verification_unsupported", reason=f"Policy names an unsupported rule: {name}.")
            kwargs = {"policy": policy, "evidence": evidence.evidence}
            if name == "command_output_match":
                kwargs["execution_id"] = execution.execution_id
            results.append(rule(**kwargs))
        result_status = ("success" if any(r.status == "success" for r in results) else
                         "failed" if results and all(r.status == "failed" for r in results) else "inconclusive")
        return VerificationResult(**common, status=result_status, rule_results=tuple(results),
                                  evidence_ids=tuple(e.evidence_id for e in evidence.evidence),
                                  reason=("At least one pre-approved rule matched trusted evidence." if result_status == "success"
                                          else "Evidence does not establish the vulnerability; no success conclusion was inferred."))
