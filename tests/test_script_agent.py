import json
from pathlib import Path
import subprocess

import pytest

from app.agents.execution import ExecutionAuthorization, RuntimeTarget
from app.agents.planner import ReproductionPlan
from app.agents.research import ResearchResult
from app.agents.script_agent import (
    IsolatedPythonRunner,
    ScriptAgent,
    ScriptProgramCheckError,
    check_python_program,
    extract_python,
    parse_program_result,
)
from app.targets.material import TargetMaterial
from app.verification.contracts import EvidenceRequirement, VerificationContract

CVE = "CVE-2017-5638"
PROGRAM = '''import json, os, socket
host = os.environ["VULNFORGE_TARGET_HOST"]
port = int(os.environ["VULNFORGE_TARGET_PORT"])
with socket.create_connection((host, port), timeout=3) as connection:
    connection.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n")
    response = connection.recv(4096)
print("__VULNFORGE_RESULT__" + json.dumps({"command_output": "uid=0(root) gid=0(root)", "response": response.decode(errors="replace")}))
'''


def fixture():
    compose = {"services": {"web": {"ports": ["8080:80"]}}}
    target = TargetMaterial(CVE, Path("/vulhub"), Path("/vulhub/struts") / CVE,
                            None, (), {"compose": compose})
    research = ResearchResult(cve_id=CVE, vulnerability_type="RCE", affected_component="web",
                              vulnerability_summary="RCE", vulnerability_mechanism="RCE",
                              trigger_conditions=["request"])
    contract = VerificationContract(evidence_requirements=(EvidenceRequirement(
        kind="command_output", rule_name="command_output_match", description="POSIX id output",
    ),), result_label="remote_command_execution")
    plan = ReproductionPlan(cve_id=CVE, vulnerability_type="RCE", reproduction_goal="RCE",
                            target_service="web", prerequisites=[], execution_guidance="PoC",
                            verification_goal="id", limitations=[], research_context=research,
                            verification_contract=contract, status="ready")
    endpoint = RuntimeTarget.from_vulhub(target=target, run_id="run1", service="web", port=80,
                                         host="172.22.0.4", project="lab-run1",
                                         container_id="a" * 64, network_name="isolated",
                                         network_id="b" * 64)
    return target, plan, endpoint


class Model:
    def __init__(self, programs):
        self.programs = list(programs)
        self.inputs = []

    def run(self, **kwargs):
        self.inputs.append(json.loads(kwargs["input_text"]))
        return kwargs["result_schema"](python=self.programs.pop(0))


class Sandbox:
    image = "python:3.12-alpine"

    def __init__(self, outputs=None):
        self.outputs = list(outputs or [{"exit_code": 0, "stdout":
            '__VULNFORGE_RESULT__{"command_output":"uid=0(root) gid=0(root)"}', "stderr": ""}])
        self.calls = []

    def run(self, source, **kwargs):
        self.calls.append((source, kwargs))
        return self.outputs.pop(0)


def authorize(request):
    return ExecutionAuthorization(**request.model_dump(), approved=True)


def test_program_check_rejects_unbound_address_and_process_execution():
    _, _, endpoint = fixture()
    check_python_program(PROGRAM, target=endpoint)
    with pytest.raises(ScriptProgramCheckError, match="outside the runtime binding"):
        check_python_program('import socket\nsocket.create_connection(("8.8.8.8", 80))', target=endpoint)
    with pytest.raises(ScriptProgramCheckError, match="allowlist"):
        check_python_program('import subprocess\nsubprocess.run(["id"])', target=endpoint)
    with pytest.raises(ScriptProgramCheckError, match="forbidden"):
        check_python_program('exec("print(1)")', target=endpoint)


def test_extract_and_result_parsing():
    assert extract_python("```python\nprint(1)\n```") == "print(1)"
    assert parse_program_result('noise\n__VULNFORGE_RESULT__{"callback_received":true}') == {
        "callback_received": True}
    with pytest.raises(ScriptProgramCheckError):
        parse_program_result("__VULNFORGE_RESULT__not-json")


def test_script_agent_repairs_once_and_requires_fresh_authorization(tmp_path):
    target, plan, endpoint = fixture()
    model = Model(["def broken(:", PROGRAM])
    sandbox = Sandbox()
    requests = []

    def callback(request):
        requests.append(request)
        return authorize(request)

    result = ScriptAgent(model, sandbox, max_attempts=3).run(
        plan=plan, target=target, runtime_target=endpoint, run_id="run1",
        document_markdown="readable evidence", authorization_callback=callback,
        work_dir=tmp_path)

    assert result.status == "completed"
    assert result.attempt_history[0]["status"] == "check_failed"
    assert len(result.attempt_history) == 2
    assert len(sandbox.calls) == len(requests) == 1
    assert model.inputs[0]["document_markdown"] == "readable evidence"
    assert model.inputs[1]["previous_attempt"]["error"]
    assert result.command_output_evidence[0]["source"] == "script_command_output"
    assert (tmp_path / "scripts" / "attempt-2.py").read_text(encoding="utf-8") == PROGRAM.strip()


def test_script_agent_denial_never_starts_container(tmp_path):
    target, plan, endpoint = fixture()
    sandbox = Sandbox()
    result = ScriptAgent(Model([PROGRAM]), sandbox).run(
        plan=plan, target=target, runtime_target=endpoint, run_id="run1",
        document_markdown="doc", authorization_callback=lambda request: None,
        work_dir=tmp_path)
    assert result.status == "rejected"
    assert sandbox.calls == []


def test_script_agent_stops_after_bounded_repairs(tmp_path):
    target, plan, endpoint = fixture()
    sandbox = Sandbox([{"exit_code": 1, "stdout": "", "stderr": "connection refused"}] * 3)
    result = ScriptAgent(Model([PROGRAM] * 3), sandbox, max_attempts=3).run(
        plan=plan, target=target, runtime_target=endpoint, run_id="run1",
        document_markdown="doc", authorization_callback=authorize, work_dir=tmp_path)
    assert result.status == "failed"
    assert len(sandbox.calls) == len(result.attempt_history) == 3


def test_sandbox_uses_bound_network_and_hardening_flags(tmp_path):
    _, _, endpoint = fixture()
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if command[:2] == ["docker", "run"]:
            return subprocess.CompletedProcess(command, 0, "container-id\n", "")
        if command[:2] == ["docker", "wait"]:
            return subprocess.CompletedProcess(command, 0, "0\n", "")
        if command[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(command, 0,
                json.dumps({"isolated": {"IPAddress": "172.22.0.3"}}), "")
        return subprocess.CompletedProcess(command, 0, "ok\n", "")

    output = IsolatedPythonRunner(runner=runner).run(
        PROGRAM, target=endpoint, run_id="run1", attempt=1, work_dir=tmp_path / "sandbox")
    command = calls[0]
    assert output["exit_code"] == 0
    assert command[command.index("--network") + 1] == "isolated"
    assert "--cap-drop" in command and "--read-only" in command
    assert "no-new-privileges" in command and "--pull=never" in command
    assert "VULNFORGE_TARGET_HOST=172.22.0.4" in command
    assert "VULNFORGE_CALLBACK_HOST=0.0.0.0" in command
    assert "8.8.8.8" not in command
    runtime = json.loads((tmp_path / "sandbox" / "runtime.json").read_text(encoding="utf-8"))
    assert runtime == {"ready": True, "callback_host": "172.22.0.3", "oob_callback_url": None}
