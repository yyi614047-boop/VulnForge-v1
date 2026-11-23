from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.agents.execution import ExecutionResult
from app.verification.collector import EvidenceCollector
from app.verification.engine import VerificationEngine
from app.verification.models import CommandExpectation, Evidence, EvidenceBundle, VerificationPolicy
from app.verification.policy import build_verification_policy


def execution(**changes):
    data = dict(run_id="run-1", execution_id="exec-1", target_id="container-1",
                cve_id="CVE-2017-5638", module_name="exploit/multi/http/example",
                target={"host": "172.22.0.4", "port": 80}, status="completed",
                job_id=4, job_uuid="job-4", job_status="completed",
                session_baseline=["1"], session_after=[], rpc_result={},
                rpc_session_snapshot_collected=True, rpc_job_result_collected=True,
                command_output_evidence=[], console_output="Exploit completed")
    data.update(changes)
    if "verification_policy" not in data:
        data["verification_policy"] = policy()
    return ExecutionResult(**data)


def policy(*, rules=("session_established",), expectations=(), category="RCE"):
    return VerificationPolicy(run_id="run-1", target_id="container-1", vulnerability_type=category,
                              accepted_rules=rules, command_expectations=tuple(expectations), policy_id="policy-1")


def bundle(result, evidence_dir=None):
    return EvidenceCollector(evidence_dir).collect(result)


def session(*, sid="2", host="172.22.0.4", kind="shell", module="multi/http/example", job="job-4"):
    return {"session_id": sid, "target_host": host, "type": kind,
            "via_exploit": module, "exploit_uuid": job}


def test_policy_is_deterministic_frozen_and_rce_only_when_module_supports_session():
    p = build_verification_policy(run_id="run-1", target_id="container-1", vulnerability_type="RCE",
                                  module_type="exploit", module_name="exploit/multi/http/example", session_capable=True)
    assert p.accepted_rules == ("session_established",)
    with pytest.raises((ValidationError, TypeError)):
        p.accepted_rules = ("always_success",)
    p2 = build_verification_policy(run_id="run-1", target_id="container-1", vulnerability_type="RCE",
                                   module_type="exploit", module_name="exploit/multi/http/example",
                                   session_capable=True,
                                   command_expectations=(CommandExpectation(pattern="proof:ok", source="approved config"),))
    assert p2.accepted_rules == ("session_established", "command_output_match")
    unsupported = build_verification_policy(run_id="run-1", target_id="container-1", vulnerability_type="SQLi",
                                            module_type="exploit", module_name="exploit/multi/http/example")
    assert unsupported.unsupported_reason and unsupported.accepted_rules == ()


def test_new_linked_supported_session_proves_rce():
    result = execution(session_after=[session()])
    outcome = VerificationEngine().verify(policy=policy(), execution=result, evidence=bundle(result))
    assert outcome.status == "success"
    assert outcome.rule_results[0].status == "success"


@pytest.mark.parametrize("row,baseline", [
    (session(sid="1"), ["1"]),
    (session(host="172.22.0.99"), ["1"]),
    (session(kind="python"), ["1"]),
    (session(job="other-job"), ["1"]),
    (session(module="multi/handler"), ["1"]),
])
def test_unrelated_historical_or_unsupported_sessions_do_not_prove(row, baseline):
    result = execution(session_baseline=baseline, session_after=[row])
    assert VerificationEngine().verify(policy=policy(), execution=result, evidence=bundle(result)).status == "inconclusive"


def test_session_without_reliable_execution_link_is_inconclusive():
    row = session()
    row.pop("exploit_uuid")
    result = execution(session_after=[row])
    assert VerificationEngine().verify(policy=policy(), execution=result, evidence=bundle(result)).status == "inconclusive"


def test_predeclared_command_output_match_is_success_and_nonmatch_is_inconclusive():
    expected = CommandExpectation(pattern="proof:ok", match_mode="literal", source="fixed check")
    p = policy(rules=("command_output_match",), expectations=(expected,))
    result = execution(verification_policy=p, command_output_evidence=[{"source": "metasploit_rpc_command_output",
                                                   "execution_id": "exec-1", "target_id": "container-1",
                                                   "output": "proof:ok"}])
    assert VerificationEngine().verify(policy=p, execution=result, evidence=bundle(result)).status == "success"
    miss = execution(verification_policy=p, command_output_evidence=[{"source": "metasploit_rpc_command_output",
                                                 "execution_id": "exec-1", "target_id": "container-1",
                                                 "output": "no match"}])
    assert VerificationEngine().verify(policy=p, execution=miss, evidence=bundle(miss)).status == "inconclusive"


def test_console_claim_and_job_completion_are_not_success_evidence():
    result = execution(console_output="Meterpreter session opened. Exploit completed", job_status="completed")
    outcome = VerificationEngine().verify(policy=policy(), execution=result, evidence=bundle(result))
    assert outcome.status == "inconclusive"


def test_missing_rpc_evidence_and_no_enabled_rule_are_not_success():
    result = execution(rpc_session_snapshot_collected=False, rpc_job_result_collected=False)
    assert VerificationEngine().verify(policy=policy(), execution=result,
                                       evidence=EvidenceBundle(run_id="run-1", target_id="container-1",
                                                               execution_id="exec-1")).status == "inconclusive"
    unsupported_rule = policy(rules=("unregistered",))
    result = execution(verification_policy=unsupported_rule)
    assert VerificationEngine().verify(policy=unsupported_rule, execution=result,
                                       evidence=bundle(result)).status == "verification_unsupported"


def test_engine_returns_distinct_verification_unsupported_status():
    unsupported = policy(category="SQLi")
    result = execution(verification_policy=unsupported)
    outcome = VerificationEngine().verify(policy=unsupported, execution=result, evidence=bundle(result))
    assert outcome.status == "verification_unsupported"


def test_run_target_and_execution_mismatches_are_rejected():
    result = execution()
    engine = VerificationEngine()
    assert engine.verify(policy=policy(), execution=result.model_copy(update={"run_id": "other"}),
                         evidence=bundle(result)).status == "failed"
    wrong = EvidenceBundle(run_id="run-1", target_id="other-target", execution_id="exec-1")
    assert engine.verify(policy=policy(), execution=result, evidence=wrong).status == "failed"
    foreign = Evidence(evidence_id="foreign", evidence_type="metasploit_session_delta", run_id="other",
                       target_id="container-1", source="metasploit_rpc", collected_at=datetime.now(timezone.utc))
    bundle_foreign = EvidenceBundle(run_id="run-1", target_id="container-1", execution_id="exec-1",
                                    evidence=(foreign,))
    assert engine.verify(policy=policy(), execution=result, evidence=bundle_foreign).status == "failed"


def test_multiple_allowed_rules_use_or_semantics_and_no_llm():
    expected = CommandExpectation(pattern="proof:ok", source="approved")
    p = policy(rules=("session_established", "command_output_match"), expectations=(expected,))
    result = execution(verification_policy=p, session_after=[session()], command_output_evidence=[{
        "source": "metasploit_rpc_command_output", "execution_id": "exec-1",
        "target_id": "container-1", "output": "proof:ok"}])
    outcome = VerificationEngine().verify(policy=p, execution=result, evidence=bundle(result))
    assert outcome.status == "success" and len(outcome.rule_results) == 2
    assert "runner" not in VerificationEngine.__dict__


def test_policy_changed_after_execution_is_rejected():
    frozen = policy()
    result = execution(verification_policy=frozen)
    changed = policy(rules=("command_output_match",),
                     expectations=(CommandExpectation(pattern="proof", source="late"),))
    assert VerificationEngine().verify(policy=changed, execution=result, evidence=bundle(result)).status == "failed"


def test_collector_ignores_foreign_and_untrusted_command_output():
    result = execution(command_output_evidence=[
        {"source": "docker_exec", "execution_id": "exec-1", "target_id": "container-1", "output": "proof:ok"},
        {"source": "metasploit_rpc_command_output", "execution_id": "other", "target_id": "container-1", "output": "proof:ok"},
    ])
    collected = bundle(result)
    assert not any(e.evidence_type == "metasploit_command_output" for e in collected.evidence)
    assert any(e.evidence_type == "metasploit_console" and e.metadata["is_success_evidence"] is False
               for e in collected.evidence)


def test_execution_policy_is_frozen_before_run_and_collector_can_persist_evidence(tmp_path):
    expected = CommandExpectation(pattern="challenge:42", source="fixed verification config")
    result = execution(verification_policy=policy(rules=("command_output_match",), expectations=(expected,)),
                       command_output_evidence=[{"source": "metasploit_rpc_command_output",
                                                 "execution_id": "exec-1", "target_id": "container-1",
                                                 "output": "challenge:42"}])
    collected = bundle(result, tmp_path)
    assert (tmp_path / "run-1" / "evidence-bundle.json").exists()
    assert VerificationEngine().verify(policy=result.verification_policy, execution=result,
                                       evidence=collected).status == "success"
