from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.agents.execution import ExecutionResult
from app.verification.collector import EvidenceCollector
from app.verification.contracts import EvidenceRequirement, VerificationContract
from app.verification.engine import VerificationEngine
from app.verification.models import (
    CommandExpectation, Evidence, EvidenceBundle, FileArtifactExpectation, RuleResult, VerificationPolicy,
)
from app.verification.policy import build_verification_policy, compute_policy_id
from app.verification.registry import (
    EvidenceRuleDefinition, EvidenceRuleRegistry, VulnerabilityTypeDefinition,
    VulnerabilityTypeRegistry, copy_rule_registry, validate_contract,
)


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


def policy(*, rules=("session_established",), expectations=(), category="RCE", contract=None,
           session_capable=True, command_output_supported=True):
    kinds = {"session_established": "session", "command_output_match": "command_output"}
    if contract is None:
        contract = VerificationContract(
            evidence_requirements=tuple(EvidenceRequirement(
                kind=kinds.get(name, "state_change"), rule_name=name,
                description="Expected trusted evidence.",
            ) for name in rules),
            result_label="session_access" if rules == ("session_established",) else "remote_command_execution",
        )
    frozen_expectations = tuple(expectations)
    rule_names = rules if contract is None else tuple(
        requirement.rule_name for requirement in contract.evidence_requirements
    )
    if "command_output_match" in rule_names and not frozen_expectations:
        frozen_expectations = (CommandExpectation(pattern="proof:ok", source="fixed test expectation"),)
    return build_verification_policy(
        run_id="run-1", target_id="container-1", vulnerability_type=category,
        contract=contract, module_type="exploit", module_name="exploit/multi/http/example",
        session_capable=session_capable, command_output_supported=command_output_supported,
        command_expectations=frozen_expectations,
    )


def bundle(result, evidence_dir=None):
    return EvidenceCollector(evidence_dir).collect(result)


def session(*, sid="2", host="172.22.0.4", kind="shell", module="multi/http/example", job="job-4"):
    return {"session_id": sid, "target_host": host, "type": kind,
            "via_exploit": module, "exploit_uuid": job}


def test_policy_is_deterministic_frozen_and_contract_driven(verification_contracts):
    p = policy(contract=verification_contracts["session"])
    assert p.accepted_rules == ("session_established",)
    with pytest.raises((ValidationError, TypeError)):
        p.accepted_rules = ("always_success",)
    p2 = policy(contract=verification_contracts["command_optional_session"])
    assert p2.accepted_rules == ("command_output_match", "session_established")
    assert p2.policy_id == compute_policy_id(p2)
    unsupported = policy(category="SQLi", contract=verification_contracts["http"])
    assert unsupported.unsupported_reason and unsupported.accepted_rules == ()
    assert "collector" in unsupported.unsupported_reason


def test_policy_id_covers_the_complete_contract(verification_contracts, command_expectation):
    first = policy(contract=verification_contracts["command"], expectations=(command_expectation,))
    changed_label = verification_contracts["command"].model_copy(update={"result_label": "different_label"})
    second = policy(contract=changed_label, expectations=(command_expectation,))
    assert first.policy_id != second.policy_id


def test_new_linked_supported_session_proves_rce():
    result = execution(session_after=[session()])
    outcome = VerificationEngine().verify(policy=policy(), execution=result, evidence=bundle(result))
    assert outcome.status == "success"
    assert outcome.rule_results[0].status == "success"


@pytest.mark.parametrize("row,baseline", [
    (session(sid="1"), ["1"]),
    (session(host="172.22.0.99"), ["1"]),
    (session(kind="python"), ["1"]),
])
def test_unrelated_historical_or_unsupported_sessions_do_not_prove(row, baseline):
    result = execution(session_baseline=baseline, session_after=[row])
    assert VerificationEngine().verify(policy=policy(), execution=result, evidence=bundle(result)).status == "inconclusive"


def test_session_does_not_require_job_module_or_exploit_uuid_binding():
    row = session()
    row.pop("via_exploit")
    row.pop("exploit_uuid")
    result = execution(session_after=[row])
    assert VerificationEngine().verify(policy=policy(), execution=result, evidence=bundle(result)).status == "success"


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


def test_session_command_output_requires_new_target_bound_session():
    expected = CommandExpectation(pattern="proof:ok", match_mode="literal", source="fixed check")
    p = policy(rules=("command_output_match",), expectations=(expected,))
    row = {"source": "metasploit_rpc_command_output", "execution_id": "exec-1",
           "target_id": "container-1", "output": "proof:ok", "session_id": "2"}
    result = execution(verification_policy=p, session_after=[session()], command_output_evidence=[row])
    assert VerificationEngine().verify(policy=p, execution=result, evidence=bundle(result)).status == "success"

    for unrelated in (
        [],
        [session(sid="1")],
        [session(host="172.22.0.99")],
        [session(kind="python")],
    ):
        result = execution(verification_policy=p, session_after=unrelated,
                           command_output_evidence=[row])
        outcome = VerificationEngine().verify(policy=p, execution=result, evidence=bundle(result))
        assert outcome.status == "inconclusive"


def test_file_artifact_expectation_is_frozen_and_new_file_proves_write():
    expectation = FileArtifactExpectation(
        path_pattern="/opt/*/webapps/api/vulnforge_probe.jsp",
        source="builtin:test",
    )
    contract = VerificationContract(
        evidence_requirements=(EvidenceRequirement(
            kind="file_artifact", rule_name="file_artifact_observed",
            description="A new file is observed.",
        ),),
        result_label="file_write_confirmed",
    )
    p = build_verification_policy(
        run_id="run-1", target_id="container-1", vulnerability_type="File Write",
        contract=contract, module_type="exploit", module_name="exploit/multi/http/example",
        file_artifact_supported=True, file_expectations=(expectation,),
    )
    row = {"source": "vulhub_runtime_file_artifact", "execution_id": "exec-1",
           "target_id": "container-1", "path_pattern": expectation.path_pattern,
           "existed_before": False, "exists_after": True,
           "new_files": [{"path": "/opt/activemq/webapps/api/vulnforge_probe.jsp"}]}
    result = execution(verification_policy=p, file_artifact_evidence=[row])
    outcome = VerificationEngine().verify(policy=p, execution=result, evidence=bundle(result))
    assert outcome.status == "success"
    assert outcome.matched_rule_names == ("file_artifact_observed",)

    existing = execution(verification_policy=p, file_artifact_evidence=[{
        **row, "existed_before": True, "new_files": [],
    }])
    outcome = VerificationEngine().verify(policy=p, execution=existing, evidence=bundle(existing))
    assert outcome.status == "inconclusive"

    changed = p.model_copy(update={"file_expectations": (expectation.model_copy(update={
        "path_pattern": "/opt/*/webapps/admin/vulnforge_probe.jsp",
    }),)})
    assert compute_policy_id(changed) != p.policy_id


def test_file_artifact_expectation_rejects_unsafe_paths():
    with pytest.raises(ValidationError):
        FileArtifactExpectation(path_pattern="/opt/../etc/passwd", source="test")
    with pytest.raises(ValidationError):
        FileArtifactExpectation(path_pattern="/opt/a;id", source="test")


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


def test_multiple_allowed_rules_use_any_semantics_and_no_llm():
    expected = CommandExpectation(pattern="proof:ok", source="approved")
    p = policy(rules=("session_established", "command_output_match"), expectations=(expected,))
    result = execution(verification_policy=p, command_output_evidence=[{
        "source": "metasploit_rpc_command_output", "execution_id": "exec-1",
        "target_id": "container-1", "output": "proof:ok"}])
    outcome = VerificationEngine().verify(policy=p, execution=result, evidence=bundle(result))
    assert outcome.status == "success" and len(outcome.rule_results) == 2
    assert outcome.matched_rule_names == ("command_output_match",)
    assert "runner" not in VerificationEngine.__dict__


def test_command_output_success_survives_missing_optional_session(verification_contracts):
    p = policy(contract=verification_contracts["command_optional_session"])
    result = execution(verification_policy=p, command_output_evidence=[{
        "source": "metasploit_rpc_command_output", "execution_id": "exec-1",
        "target_id": "container-1", "output": "proof:ok",
    }])
    outcome = VerificationEngine().verify(policy=p, execution=result, evidence=bundle(result))
    assert outcome.status == "success"
    assert outcome.result_label == "remote_command_execution"
    assert outcome.matched_rule_names == ("command_output_match",)
    assert [rule.status for rule in outcome.rule_results] == ["success", "inconclusive"]
    assert all("console" not in evidence_id for evidence_id in outcome.matched_evidence_ids)


def test_command_output_success_without_any_session(verification_contracts):
    p = policy(contract=verification_contracts["command"])
    result = execution(verification_policy=p, command_output_evidence=[{
        "source": "metasploit_rpc_command_output", "execution_id": "exec-1",
        "target_id": "container-1", "output": "proof:ok",
    }])
    assert VerificationEngine().verify(policy=p, execution=result, evidence=bundle(result)).status == "success"


def test_console_and_job_completion_cannot_satisfy_command_contract(verification_contracts):
    p = policy(contract=verification_contracts["command"])
    result = execution(verification_policy=p, console_output="uid=0(root) gid=0(root) Exploit completed",
                       job_status="completed")
    outcome = VerificationEngine().verify(policy=p, execution=result, evidence=bundle(result))
    assert outcome.status == "inconclusive"
    assert outcome.matched_rule_names == () and outcome.matched_evidence_ids == ()


def test_all_policy_requires_every_required_rule(verification_contracts):
    p = policy(contract=verification_contracts["all"])
    result = execution(verification_policy=p, command_output_evidence=[{
        "source": "metasploit_rpc_command_output", "execution_id": "exec-1",
        "target_id": "container-1", "output": "proof:ok",
    }])
    outcome = VerificationEngine().verify(policy=p, execution=result, evidence=bundle(result))
    assert outcome.status == "inconclusive"
    assert outcome.matched_rule_names == ("command_output_match",)


def test_policy_changed_after_execution_is_rejected():
    frozen = policy()
    result = execution(verification_policy=frozen)
    changed = policy(rules=("command_output_match",),
                     expectations=(CommandExpectation(pattern="proof", source="late"),))
    assert VerificationEngine().verify(policy=changed, execution=result, evidence=bundle(result)).status == "failed"


def test_policy_fingerprint_mutation_is_rejected():
    frozen = policy()
    changed = frozen.model_copy(update={"policy_id": "verification-forged"})
    result = execution(verification_policy=frozen)
    assert VerificationEngine().verify(policy=changed, execution=result, evidence=bundle(result)).status == "failed"


def test_execution_id_binding_and_explicit_failure_are_rejected():
    frozen = policy()
    result = execution(verification_policy=frozen)
    wrong = EvidenceBundle(run_id="run-1", target_id="container-1", execution_id="other")
    assert VerificationEngine().verify(policy=frozen, execution=result, evidence=wrong).status == "failed"
    for status in ("failed", "rejected"):
        failed = execution(verification_policy=frozen, status=status)
        assert VerificationEngine().verify(policy=frozen, execution=failed, evidence=bundle(failed)).status == "failed"


@pytest.mark.parametrize("rule_status,expected", [
    ("success", "success"), ("inconclusive", "inconclusive"), ("failed", "failed"),
])
def test_registered_non_rce_rule_extends_engine_without_type_branch(rule_status, expected):
    def verify_fake(*, policy, evidence):
        row = evidence[0]
        return RuleResult(rule_name="artifact_observed", status=rule_status,
                          reason="Registered fake rule result.", evidence_ids=(row.evidence_id,))

    contract = VerificationContract(
        evidence_requirements=(EvidenceRequirement(
            kind="file_artifact", rule_name="artifact_observed",
            description="A registered fake artifact rule.",
        ),),
        result_label="file_read_confirmed",
    )
    base = policy(category="File Read", contract=contract)
    frozen = base.model_copy(update={"accepted_rules": ("artifact_observed",), "unsupported_reason": None})
    frozen = frozen.model_copy(update={"policy_id": compute_policy_id(frozen)})
    row = Evidence(evidence_id="artifact-1", evidence_type="fake_artifact", run_id="run-1",
                   target_id="container-1", source="fake_collector",
                   collected_at=datetime.now(timezone.utc))
    evidence = EvidenceBundle(run_id="run-1", target_id="container-1", execution_id="exec-1", evidence=(row,))
    engine = VerificationEngine(
        type_registry=VulnerabilityTypeRegistry((VulnerabilityTypeDefinition(
            "File Read", True, frozenset({"file_artifact"}),
        ),)),
        rule_registry=EvidenceRuleRegistry((EvidenceRuleDefinition(
            "file_artifact", "artifact_observed", verify_fake, True,
        ),)),
    )
    outcome = engine.verify(policy=frozen, execution=execution(verification_policy=frozen), evidence=evidence)
    assert outcome.status == expected
    assert outcome.result_label == "file_read_confirmed"
    assert outcome.matched_evidence_ids == (("artifact-1",) if rule_status == "success" else ())


def test_contract_validation_rejects_missing_duplicate_and_unknown_rules(verification_contracts):
    command = verification_contracts["command"].evidence_requirements[0]
    with pytest.raises(ValidationError):
        VerificationContract(evidence_requirements=(command.model_copy(update={"required": False}),),
                             result_label="invalid")
    with pytest.raises(ValidationError):
        VerificationContract(evidence_requirements=(command, command), result_label="invalid")
    unknown_rule = command.model_copy(update={"rule_name": "always_success"})
    contract = verification_contracts["command"].model_copy(
        update={"evidence_requirements": (unknown_rule,)},
    )
    assert "Unregistered evidence rule" in validate_contract(
        vulnerability_type="RCE", contract=contract,
    )
    wrong_kind = command.model_copy(update={"kind": "session"})
    contract = verification_contracts["command"].model_copy(
        update={"evidence_requirements": (wrong_kind,)},
    )
    assert "does not collect" in validate_contract(vulnerability_type="RCE", contract=contract)
    assert "Unrecognized vulnerability type" in validate_contract(
        vulnerability_type="Invented", contract=verification_contracts["command"],
    )
    assert "collector" in validate_contract(
        vulnerability_type="RCE", contract=verification_contracts["http"],
    )


def test_policy_backend_capabilities_only_constrain_required_evidence(verification_contracts,
                                                                       command_expectation):
    unsupported_session = policy(contract=verification_contracts["session"], session_capable=False)
    assert unsupported_session.unsupported_reason and unsupported_session.accepted_rules == ()
    unsupported_command = build_verification_policy(
        run_id="run-1", target_id="container-1", vulnerability_type="RCE",
        contract=verification_contracts["command"], module_type="exploit",
        module_name="exploit/multi/http/example", command_output_supported=True,
    )
    assert unsupported_command.unsupported_reason and unsupported_command.accepted_rules == ()
    optional_session = policy(contract=verification_contracts["command_optional_session"],
                              session_capable=False, expectations=(command_expectation,))
    assert optional_session.unsupported_reason is None
    assert optional_session.accepted_rules == ("command_output_match", "session_established")


def test_command_rule_reports_only_the_evidence_record_that_matched(verification_contracts):
    p = policy(contract=verification_contracts["command"])
    result = execution(verification_policy=p, command_output_evidence=[
        {"source": "metasploit_rpc_command_output", "execution_id": "exec-1",
         "target_id": "container-1", "output": "not the expected output"},
        {"source": "metasploit_rpc_command_output", "execution_id": "exec-1",
         "target_id": "container-1", "output": "proof:ok"},
    ])
    collected = bundle(result)
    matching = next(item for item in collected.evidence
                    if item.metadata.get("output") == "proof:ok")
    outcome = VerificationEngine().verify(policy=p, execution=result, evidence=collected)
    assert outcome.status == "success"
    assert outcome.matched_evidence_ids == (matching.evidence_id,)


def test_failed_optional_rule_never_overrides_required_success(verification_contracts):
    def fail_optional(*, policy, evidence):
        return RuleResult(rule_name="optional_state", status="failed", reason="Optional rule failed.")

    command = verification_contracts["command"].evidence_requirements[0]
    optional = EvidenceRequirement(kind="state_change", rule_name="optional_state",
                                   required=False, description="Optional state evidence.")
    contract = verification_contracts["command"].model_copy(
        update={"evidence_requirements": (command, optional)},
    )
    base = policy(contract=contract)
    frozen = base.model_copy(update={
        "accepted_rules": ("command_output_match", "optional_state"), "unsupported_reason": None,
    })
    frozen = frozen.model_copy(update={"policy_id": compute_policy_id(frozen)})
    result = execution(verification_policy=frozen, command_output_evidence=[{
        "source": "metasploit_rpc_command_output", "execution_id": "exec-1",
        "target_id": "container-1", "output": "proof:ok",
    }])
    rules = copy_rule_registry()
    rules.register(EvidenceRuleDefinition("state_change", "optional_state", fail_optional, True))
    engine = VerificationEngine(
        type_registry=VulnerabilityTypeRegistry((VulnerabilityTypeDefinition(
            "RCE", True, frozenset({"command_output", "state_change"}),
        ),)),
        rule_registry=rules,
    )
    outcome = engine.verify(policy=frozen, execution=result, evidence=bundle(result))
    assert outcome.status == "success"
    assert outcome.matched_rule_names == ("command_output_match",)
    assert [rule.status for rule in outcome.rule_results] == ["success", "failed"]


def test_all_policy_fails_when_one_required_registered_rule_fails():
    def verifier(status):
        def verify(*, policy, evidence):
            return RuleResult(rule_name=status, status=status, reason=f"{status} result.")
        return verify

    contract = VerificationContract(
        evidence_requirements=(
            EvidenceRequirement(kind="file_artifact", rule_name="success",
                                description="Required artifact evidence."),
            EvidenceRequirement(kind="state_change", rule_name="failed",
                                description="Required state evidence."),
        ),
        acceptance_policy="all", result_label="file_read_confirmed",
    )
    base = policy(category="File Read", contract=contract)
    frozen = base.model_copy(update={"accepted_rules": ("success", "failed"), "unsupported_reason": None})
    frozen = frozen.model_copy(update={"policy_id": compute_policy_id(frozen)})
    engine = VerificationEngine(
        type_registry=VulnerabilityTypeRegistry((VulnerabilityTypeDefinition(
            "File Read", True, frozenset({"file_artifact", "state_change"}),
        ),)),
        rule_registry=EvidenceRuleRegistry((
            EvidenceRuleDefinition("file_artifact", "success", verifier("success"), True),
            EvidenceRuleDefinition("state_change", "failed", verifier("failed"), True),
        )),
    )
    result = execution(verification_policy=frozen)
    outcome = engine.verify(policy=frozen, execution=result, evidence=bundle(result))
    assert outcome.status == "failed"
    assert [rule.status for rule in outcome.rule_results] == ["success", "failed"]


def test_all_policy_explicit_failure_precedes_another_required_inconclusive_rule():
    def verifier(status):
        def verify(*, policy, evidence):
            return RuleResult(rule_name=status, status=status, reason=f"{status} result.")
        return verify

    contract = VerificationContract(
        evidence_requirements=(
            EvidenceRequirement(kind="file_artifact", rule_name="inconclusive",
                                description="Required artifact evidence."),
            EvidenceRequirement(kind="state_change", rule_name="failed",
                                description="Required state evidence."),
        ),
        acceptance_policy="all", result_label="file_read_confirmed",
    )
    base = policy(category="File Read", contract=contract)
    frozen = base.model_copy(update={"accepted_rules": ("inconclusive", "failed"), "unsupported_reason": None})
    frozen = frozen.model_copy(update={"policy_id": compute_policy_id(frozen)})
    engine = VerificationEngine(
        type_registry=VulnerabilityTypeRegistry((VulnerabilityTypeDefinition(
            "File Read", True, frozenset({"file_artifact", "state_change"}),
        ),)),
        rule_registry=EvidenceRuleRegistry((
            EvidenceRuleDefinition("file_artifact", "inconclusive", verifier("inconclusive"), True),
            EvidenceRuleDefinition("state_change", "failed", verifier("failed"), True),
        )),
    )
    result = execution(verification_policy=frozen)
    outcome = engine.verify(policy=frozen, execution=result, evidence=bundle(result))
    assert outcome.status == "failed"
    assert [rule.status for rule in outcome.rule_results] == ["inconclusive", "failed"]


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
    assert (tmp_path / "evidence-bundle.json").exists()
    assert VerificationEngine().verify(policy=result.verification_policy, execution=result,
                                       evidence=collected).status == "success"
