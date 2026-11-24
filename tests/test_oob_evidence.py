import json
import subprocess

import pytest
from pydantic import ValidationError

from app.agents.execution import ExecutionResult, RuntimeTarget
from app.verification.collector import EvidenceCollector
from app.verification.contracts import EvidenceRequirement, OobExpectation, VerificationContract
from app.verification.engine import VerificationEngine
from app.verification.oob_collector import OobCallbackCollector
from app.verification.policy import build_verification_policy

TOKEN = "test_oob_token_1234567890"


def expectation():
    return OobExpectation(token=TOKEN, path=f"/oob/{TOKEN}", source="README")


def execution():
    target = RuntimeTarget(
        run_id="run-1", cve_id="CVE-2021-41773", project="lab-run1", service="web",
        host="172.22.0.4", callback_host="172.22.0.3", port=80,
        container_id="a" * 64, network_name="isolated", network_id="b" * 64,
        compose_sha256="c" * 64, local_vulhub=True,
    )
    return ExecutionResult(run_id="run-1", target_id=target.container_id,
                           cve_id=target.cve_id, target=target.model_dump(), status="completed")


def policy_for(probe):
    contract = VerificationContract(
        evidence_requirements=(EvidenceRequirement(
            kind="oob_callback", rule_name="oob_callback_observed",
            description="The target calls the frozen callback URL.",
        ),), result_label="ssrf_confirmed", oob_expectations=(probe,),
    )
    return build_verification_policy(
        run_id="run-1", target_id="a" * 64, vulnerability_type="RCE", contract=contract,
        module_type="exploit", module_name="exploit/multi/http/example",
        oob_callback_supported=True,
    )


def runner_for(remote_host):
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if command[:2] == ["docker", "run"]:
            return subprocess.CompletedProcess(command, 0, "collector-id\n", "")
        if command[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(command, 0,
                json.dumps({"isolated": {"IPAddress": "172.22.0.5"}}), "")
        if command[:2] == ["docker", "logs"]:
            row = {"path": f"/oob/{TOKEN}", "method": "GET",
                   "remote_host": remote_host, "remote_port": 43210}
            return subprocess.CompletedProcess(command, 0,
                "__VULNFORGE_OOB__" + json.dumps(row) + "\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")
    return runner, calls


def test_oob_collector_binds_token_network_and_target_source():
    probe = expectation()
    runner, calls = runner_for("172.22.0.4")
    collector = OobCallbackCollector(runner=runner)
    binding = collector.start(run_id="run-1", network_name="isolated", expectation=probe)
    result = execution()
    policy = policy_for(probe)
    result = result.model_copy(update={"verification_policy": policy})
    rows = collector.collect(run_id="run-1", execution=result,
                             expectation=probe, target_host="172.22.0.4")
    result = result.model_copy(update={"oob_callback_evidence": rows})
    outcome = VerificationEngine().verify(
        policy=policy, execution=result, evidence=EvidenceCollector().collect(result))
    collector.stop(run_id="run-1")

    assert binding["callback_url"] == f"http://172.22.0.5:8000/oob/{TOKEN}"
    assert calls[0][calls[0].index("--network") + 1] == "isolated"
    assert "--cap-drop" in calls[0] and "--read-only" in calls[0]
    assert outcome.status == "success"
    assert outcome.matched_rule_names == ("oob_callback_observed",)
    assert calls[-1][:2] == ["docker", "stop"]


def test_oob_callback_from_another_source_is_not_evidence():
    probe = expectation()
    runner, _ = runner_for("172.22.0.99")
    collector = OobCallbackCollector(runner=runner)
    collector.start(run_id="run-1", network_name="isolated", expectation=probe)
    result = execution()
    rows = collector.collect(run_id="run-1", execution=result,
                             expectation=probe, target_host="172.22.0.4")
    assert rows == []


def test_oob_expectation_rejects_mismatched_token_path():
    with pytest.raises(ValidationError):
        OobExpectation(token=TOKEN, path="/oob/other_token_1234567890", source="README")
