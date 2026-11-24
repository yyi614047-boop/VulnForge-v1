from pathlib import Path
from types import SimpleNamespace
import json
import sys
import pytest

import app.cli as cli
import app.workflow as workflow_module
from app.agents.execution import ExecutionAuthorizationRequest


VERIFICATION_CONTRACT = {
    "evidence_requirements": [
        {"kind": "command_output", "rule_name": "command_output_match", "required": True,
         "description": "Target-bound output matches the fixed POSIX id expectation."},
        {"kind": "session", "rule_name": "session_established", "required": False,
         "description": "An optional shell session is observed."},
    ],
    "acceptance_policy": "any", "result_label": "remote_command_execution",
}


class FakeWorkflow:
    last_grant = None
    last_context = None
    status_override = None

    def __init__(self, event_sink, language):
        self.sink, self.language = event_sink, language
        self.grant = None

    @classmethod
    def from_environment(cls, *, run_context, event_sink, language):
        cls.last_context = run_context
        return cls(event_sink, language)

    def run(self, cve_id, *, authorization_callback, run_id):
        self.sink({"type": "stage_started", "stage": "research", "run_id": run_id})
        self.sink({"type": "research_summary", "summary": {"vulnerability_type": "RCE", "vulnerability_mechanism": "quoted mechanism", "trigger_conditions": ["local request"]}})
        self.sink({"type": "stage_completed", "stage": "research", "run_id": run_id})
        self.sink({"type": "module_search_started", "run_id": run_id})
        self.sink({"type": "module_candidates_found", "run_id": run_id, "module_names": ["exploit/test/demo"]})
        self.sink({"type": "module_selected", "run_id": run_id, "module_name": "exploit/test/demo"})
        self.sink({"type": "exploit_started", "run_id": run_id, "module_name": "exploit/test/demo"})
        self.sink({"type": "session_detected", "run_id": run_id, "sessions": [1]})
        contract = VERIFICATION_CONTRACT
        request = ExecutionAuthorizationRequest(run_id=run_id, target_id="target-1", target_fingerprint="a"*64,
            plan_fingerprint="b"*64, module_name="exploit/test/demo", module_fingerprint="c"*64,
            configuration_fingerprint="d"*64, configuration_summary={"CMD": "id"},
            verification_policy_id="policy-1")
        self.sink({"type": "execution_authorization_requested", "run_id": run_id,
            "module_name": request.module_name, "runtime_target": {"host": "127.0.0.1", "port": 8080, "service": "web"},
            "reproduction_plan": {"cve_id": cve_id, "reproduction_goal": "verify", "verification_goal": "evidence",
                                  "verification_contract": contract, "limitations": []},
            "verification_contract": contract})
        self.grant = authorization_callback(request)
        type(self).last_grant = self.grant
        status = type(self).status_override or ("success" if self.grant and self.grant.approved else "execution_unauthorized")
        verification_status = status if status in {"success", "failed", "inconclusive", "verification_unsupported"} else "inconclusive"
        matched = verification_status == "success"
        rule_results = [
            {"rule_name": "command_output_match", "status": "success" if matched else "inconclusive",
             "reason": "mock command rule", "evidence_ids": ["command-evidence-1"]},
            {"rule_name": "session_established", "status": "inconclusive",
             "reason": "No session", "evidence_ids": []},
        ]
        self.sink({"type": "verification_completed", "run_id": run_id, "status": verification_status,
                   "verification_contract": contract, "result_label": "remote_command_execution",
                   "matched_rule_names": ["command_output_match"] if matched else [],
                   "matched_evidence_ids": ["command-evidence-1"] if matched else [], "rule_results": rule_results})
        return {"run_id": run_id, "cve_id": cve_id, "status": status, "errors": [],
            "target": SimpleNamespace(environment=Path("/tmp/vulhub/CVE-2020-1234")),
            "runtime_target": {"host": "127.0.0.1", "port": 8080, "service": "web"},
            "research_result": {"vulnerability_type": "RCE", "vulnerability_mechanism": "quoted mechanism", "trigger_conditions": ["local request"]},
            "reproduction_plan": {"cve_id": cve_id, "vulnerability_type": "RCE", "reproduction_goal": "verify",
                                  "target_service": "web", "verification_contract": contract, "limitations": []},
            "execution_result": {"status": "completed", "module_name": request.module_name, "console_output": "password=topsecret"},
            "verification_result": {"status": verification_status, "reason": "mock result",
                                    "result_label": "remote_command_execution",
                                    "matched_rule_names": ["command_output_match"] if matched else [],
                                    "matched_evidence_ids": ["command-evidence-1"] if matched else [],
                                    "rule_results": rule_results},
            "evidence": {"run_id": run_id, "target_id": "target-1", "execution_id": "exec-1", "evidence": [
                {"evidence_id": "console-1"}, {"evidence_id": "command-evidence-1"},
            ]}}


def setup(monkeypatch, tmp_path):
    FakeWorkflow.last_grant = None
    FakeWorkflow.last_context = None
    FakeWorkflow.status_override = None
    monkeypatch.setenv("VULNFORGE_RUNS_ROOT", str(tmp_path / "runs"))
    monkeypatch.setattr(workflow_module.VulnForgeWorkflow, "from_environment", FakeWorkflow.from_environment)
    monkeypatch.setattr(cli, "build_parser", cli.build_parser)
    import app.targets.vulhub.config as config
    import app.targets.vulhub.loader as loader
    monkeypatch.setattr(config.VulhubSettings, "from_environment", classmethod(lambda cls: SimpleNamespace(root=tmp_path)))
    monkeypatch.setattr(loader, "load_target", lambda root, cve: SimpleNamespace(identifier=cve.upper(), environment=tmp_path / cve.upper()))


def test_cli_zh_confirmation_artifacts_and_redaction(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "CVE-2020-1234"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    answers = iter(["yes"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert cli.main() == 0
    output = capsys.readouterr().out
    assert "漏洞摘要" in output and "exploit/test/demo" in output and "最终验证结论：成功" in output
    run_dir = next((tmp_path / "runs").iterdir())
    assert {"report.md", "result.json", "execution.log", "evidence"} <= {p.name for p in run_dir.iterdir()}
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "VulnForge 运行报告" in report
    assert "必需证据" in report and "可选证据" in report and "组合策略: any" in report
    assert "结果类型: 远程命令执行" in report
    assert "漏洞复现成功: 是" in report and "获得 Shell: 否" in report
    assert "实际命中的证据 ID: ['command-evidence-1']" in report
    assert "未获得的可选能力" in report and "session_established" in report
    assert json.loads((run_dir / "result.json").read_text(encoding="utf-8"))["status"] == "success"
    assert "topsecret" not in (run_dir / "execution.log").read_text(encoding="utf-8")
    assert FakeWorkflow.last_grant is not None and FakeWorkflow.last_grant.approved is True
    assert FakeWorkflow.last_grant.module_name == "exploit/test/demo"
    assert FakeWorkflow.last_context.run_dir == run_dir


def test_cli_en_decline_is_cancelled_and_noninteractive_denies(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "CVE-2020-1234", "--lang", "en"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    assert cli.main() == 0
    output = capsys.readouterr().out
    assert "Vulnerability summary" in output and "Continue?" not in output
    run_dir = next((tmp_path / "runs").iterdir())
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    assert result["status"] == "cancelled"
    assert FakeWorkflow.last_grant is None
    assert FakeWorkflow.last_context.run_dir == run_dir
    assert "VulnForge run report" in (run_dir / "report.md").read_text(encoding="utf-8")


def test_cli_rejects_invalid_cve_before_workflow(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "not-a-cve"])
    assert cli.main() == 2
    assert "格式无效" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_cli_passes_one_run_context_to_workflow(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "CVE-2020-1234"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    assert cli.main() == 0
    run_dir = next((tmp_path / "runs").iterdir())
    context = FakeWorkflow.last_context
    assert context.run_dir == run_dir
    assert context.evidence_dir == run_dir / "evidence"
    assert context.targets_dir == run_dir / "targets"
    assert not (tmp_path / ".vulnforge-runs").exists()
    capsys.readouterr()


def test_run_directories_are_unique_and_event_output_is_real(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path)
    for _ in range(2):
        monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "CVE-2020-1234", "--lang", "en"])
        monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
        assert cli.main() == 0
    output = capsys.readouterr().out
    assert "Session detected (not proof of success)" in output
    assert "Verification: inconclusive | type: remote_command_execution" in output
    dirs = list((tmp_path / "runs").iterdir())
    assert len(dirs) == 2 and dirs[0] != dirs[1]
    for run_dir in dirs:
        events = (run_dir / "execution.log").read_text(encoding="utf-8")
        assert "module_candidates_found" in events and "session_detected" in events


def test_redaction_covers_rpc_password_and_api_key():
    safe = cli._safe({"MSFRPC_PASS": "rpc-secret", "api_key": "key-secret", "message": "password=inline-secret"})
    rendered = json.dumps(safe)
    assert "rpc-secret" not in rendered and "key-secret" not in rendered and "inline-secret" not in rendered


@pytest.mark.parametrize("status,expected", [
    ("success", 0), ("failed", 3), ("inconclusive", 0),
    ("unsupported", 0), ("verification_unsupported", 0), ("execution_failed", 4),
])
def test_cli_status_exit_mapping_and_report(monkeypatch, tmp_path, capsys, status, expected):
    setup(monkeypatch, tmp_path)
    FakeWorkflow.status_override = status
    monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "CVE-2020-1234", "--lang", "en"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    assert cli.main() == expected
    run_dir = next((tmp_path / "runs").iterdir())
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    assert result["status"] == status
    assert "## Verification result" in (run_dir / "report.md").read_text(encoding="utf-8")


def test_early_workflow_failure_still_writes_artifacts(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path)
    def fail_configuration(cls, *, run_context, event_sink, language):
        raise RuntimeError("mock workflow setup failure")
    monkeypatch.setattr(workflow_module.VulnForgeWorkflow, "from_environment", classmethod(fail_configuration))
    monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "CVE-2020-1234"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    assert cli.main() == 3
    run_dir = next((tmp_path / "runs").iterdir())
    assert (run_dir / "report.md").exists() and (run_dir / "result.json").exists() and (run_dir / "execution.log").exists()
    assert json.loads((run_dir / "result.json").read_text(encoding="utf-8"))["failed_stage"] == "workflow"
