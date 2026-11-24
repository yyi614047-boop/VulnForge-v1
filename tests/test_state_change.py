import pytest

from app.agents.execution import ExecutionResult, _extract_state_changes
from app.verification.collector import EvidenceCollector
from app.verification.contracts import EvidenceRequirement, StateChangeExpectation, VerificationContract
from app.verification.engine import VerificationEngine
from app.verification.policy import build_verification_policy


CONTRACT = VerificationContract(
    evidence_requirements=(EvidenceRequirement(
        kind="state_change",
        rule_name="state_change_observed",
        description="Anonymous access changes to authenticated access.",
    ),),
    result_label="auth_bypass_confirmed",
    state_changes=(StateChangeExpectation(
        indicator="authentication",
        before="anonymous",
        after="authenticated",
        source="local README",
    ),),
)


def make_execution(*, rows=(), console_output=""):
    policy = build_verification_policy(
        run_id="run-1",
        target_id="container-1",
        vulnerability_type="Auth Bypass",
        contract=CONTRACT,
        module_type="exploit",
        module_name="exploit/multi/http/example",
    )
    return ExecutionResult(
        run_id="run-1",
        execution_id="exec-1",
        target_id="container-1",
        cve_id="CVE-2020-17526",
        module_name="exploit/multi/http/example",
        status="completed",
        job_uuid="job-1",
        state_change_evidence=list(rows),
        verification_policy=policy,
        console_output=console_output,
    )


def state_row(*, indicator="authentication", before="anonymous", after="authenticated",
              execution_id="exec-1", target_id="container-1"):
    return {
        "source": "metasploit_rpc_state_change",
        "execution_id": execution_id,
        "target_id": target_id,
        "indicator": indicator,
        "before": before,
        "after": after,
        "source_detail": "module.results.state_change",
    }


def verify(execution):
    bundle = EvidenceCollector().collect(execution)
    return VerificationEngine().verify(
        policy=execution.verification_policy,
        execution=execution,
        evidence=bundle,
    )


def test_structured_state_transition_verifies_successfully():
    result = verify(make_execution(rows=[state_row()]))

    assert result.status == "success"
    assert result.matched_rule_names == ("state_change_observed",)
    assert result.matched_evidence_ids


def test_unchanged_structured_state_is_an_explicit_failure():
    result = verify(make_execution(rows=[state_row(before="anonymous", after="anonymous")]))

    assert result.status == "failed"
    assert result.rule_results[0].status == "failed"


def test_unrelated_state_indicator_does_not_satisfy_or_contradict_expectation():
    result = verify(make_execution(rows=[state_row(indicator="role", before="user", after="admin")]))

    assert result.status == "inconclusive"
    assert result.matched_evidence_ids == ()


def test_missing_state_change_is_inconclusive_and_console_prose_is_not_proof():
    result = verify(make_execution(console_output="Authentication bypass succeeded"))

    assert result.status == "inconclusive"
    assert result.matched_evidence_ids == ()


def test_foreign_execution_or_target_binding_is_ignored():
    result = verify(make_execution(rows=[
        state_row(execution_id="other-exec"),
        state_row(target_id="other-target"),
    ]))

    assert result.status == "inconclusive"
    assert result.evidence_ids == ()


def test_extractor_accepts_only_structured_scalar_transitions():
    result = _extract_state_changes({
        "state_change": {
            "indicator": "authentication",
            "before": False,
            "after": True,
        },
        "result": {
            "state_changes": [
                {"indicator": "role", "before": "user", "after": "admin"},
                {"indicator": "missing", "before": "same", "after": "same"},
                {"indicator": "invalid", "before": {"nested": True}, "after": False},
                {"indicator": "", "before": False, "after": True},
            ],
        },
    })

    assert result == [
        {"indicator": "authentication", "before": False, "after": True,
         "source_detail": "module.results.state_change"},
        {"indicator": "role", "before": "user", "after": "admin",
         "source_detail": "module.results.result.state_changes"},
        {"indicator": "missing", "before": "same", "after": "same",
         "source_detail": "module.results.result.state_changes"},
    ]


@pytest.mark.parametrize("value", ["", "bad\nvalue", {"nested": True}, [True], None, float("nan")])
def test_extractor_rejects_invalid_state_values(value):
    assert _extract_state_changes({
        "state_change": {"indicator": "authentication", "before": value, "after": True},
    }) == []
