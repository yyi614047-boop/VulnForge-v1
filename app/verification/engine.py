"""Category-neutral deterministic verification orchestration."""
from app.verification.models import EvidenceBundle, VerificationPolicy, VerificationResult
from app.verification.policy import compute_policy_id
from app.verification.registry import (
    EVIDENCE_RULES,
    VULNERABILITY_TYPES,
    EvidenceRuleRegistry,
    VulnerabilityTypeRegistry,
    validate_contract,
)


class VerificationEngine:
    def __init__(self, *, type_registry: VulnerabilityTypeRegistry | None = None,
                 rule_registry: EvidenceRuleRegistry | None = None):
        self.type_registry = type_registry or VULNERABILITY_TYPES
        self.rule_registry = rule_registry or EVIDENCE_RULES

    def verify(self, *, policy: VerificationPolicy, execution,
               evidence: EvidenceBundle) -> VerificationResult:
        common = dict(
            run_id=policy.run_id,
            target_id=policy.target_id,
            vulnerability_type=policy.vulnerability_type,
            result_label=policy.contract.result_label,
        )
        all_evidence_ids = tuple(item.evidence_id for item in evidence.evidence)
        if execution.run_id != policy.run_id or evidence.run_id != policy.run_id:
            return VerificationResult(**common, status="failed",
                                      reason="Execution or evidence run ID differs from frozen policy.")
        if execution.target_id != policy.target_id or evidence.target_id != policy.target_id:
            return VerificationResult(**common, status="failed",
                                      reason="Execution or evidence target ID differs from frozen policy.")
        if evidence.execution_id != execution.execution_id:
            return VerificationResult(**common, status="failed",
                                      reason="Evidence is not bound to this execution.")
        if any(item.run_id != policy.run_id or item.target_id != policy.target_id
               for item in evidence.evidence):
            return VerificationResult(**common, status="failed",
                                      reason="Evidence contains a foreign run or target.")
        if execution.verification_policy is None or execution.verification_policy != policy:
            return VerificationResult(**common, status="failed",
                                      reason="Verification policy is missing or differs from the policy frozen before execution.")
        if policy.policy_id != compute_policy_id(policy):
            return VerificationResult(**common, status="failed",
                                      reason="Verification policy fingerprint does not match its frozen contents.")
        if execution.status in {"failed", "rejected"}:
            return VerificationResult(**common, status="failed", evidence_ids=all_evidence_ids,
                                      reason="Execution has an explicit failure or rejection status.")
        if execution.status == "unsupported":
            return VerificationResult(**common, status="verification_unsupported",
                                      evidence_ids=all_evidence_ids,
                                      reason=policy.unsupported_reason or "Execution is unsupported.")
        contract_reason = validate_contract(
            vulnerability_type=policy.vulnerability_type,
            contract=policy.contract,
            type_registry=self.type_registry,
            rule_registry=self.rule_registry,
        )
        expected_rules = tuple(
            requirement.rule_name for requirement in policy.contract.evidence_requirements
        )
        if policy.unsupported_reason or contract_reason or policy.accepted_rules != expected_rules:
            return VerificationResult(
                **common,
                status="verification_unsupported",
                evidence_ids=all_evidence_ids,
                reason=(policy.unsupported_reason or contract_reason
                        or "Policy accepted rules differ from the frozen verification contract."),
            )

        results = []
        for requirement in policy.contract.evidence_requirements:
            definition = self.rule_registry.get(requirement.rule_name)
            if definition is None or definition.verifier is None:
                return VerificationResult(
                    **common,
                    status="verification_unsupported",
                    evidence_ids=all_evidence_ids,
                    reason=f"Policy names an unsupported rule: {requirement.rule_name}.",
                )
            kwargs = {"policy": policy, "evidence": evidence.evidence}
            if definition.requires_execution_id:
                kwargs["execution_id"] = execution.execution_id
            results.append(definition.verifier(**kwargs))

        required_statuses = [
            result.status
            for requirement, result in zip(policy.contract.evidence_requirements, results)
            if requirement.required
        ]
        if policy.contract.acceptance_policy == "all":
            if required_statuses and all(status == "success" for status in required_statuses):
                result_status = "success"
            elif any(status == "failed" for status in required_statuses):
                result_status = "failed"
            elif any(status == "inconclusive" for status in required_statuses):
                result_status = "inconclusive"
            else:
                result_status = "failed"
        else:
            if any(status == "success" for status in required_statuses):
                result_status = "success"
            elif any(status == "inconclusive" for status in required_statuses):
                result_status = "inconclusive"
            else:
                result_status = "failed"

        matched = [result for result in results if result.status == "success"]
        matched_rule_names = tuple(result.rule_name for result in matched)
        matched_evidence_ids = tuple(dict.fromkeys(
            evidence_id for result in matched for evidence_id in result.evidence_ids
        ))
        if result_status == "success":
            reason = (
                "All required pre-approved rules matched trusted evidence."
                if policy.contract.acceptance_policy == "all" else
                "At least one required pre-approved rule matched trusted evidence."
            )
        elif result_status == "inconclusive":
            reason = "Evidence does not establish the vulnerability; no success conclusion was inferred."
        else:
            reason = "Required evidence rules explicitly failed; no success conclusion was inferred."
        return VerificationResult(
            **common,
            status=result_status,
            rule_results=tuple(results),
            evidence_ids=all_evidence_ids,
            matched_rule_names=matched_rule_names,
            matched_evidence_ids=matched_evidence_ids,
            reason=reason,
        )
