from pathlib import Path
from types import SimpleNamespace
import json
import sys
import pytest

import app.cli as cli
import app.workflow as workflow_module
from app.agents.execution import ExecutionAuthorizationRequest


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
        self.sink({"type": "stage_skipped", "run_id": run_id, "stage": "script",
                   "reason": "metasploit_execution_completed"})
        self.sink({"type": "evidence_collected", "run_id": run_id, "evidence_count": 1})
        request = ExecutionAuthorizationRequest(run_id=run_id, target_id="target-1", target_fingerprint="a"*64,
            plan_fingerprint="b"*64, module_name="exploit/test/demo", module_fingerprint="c"*64,
            configuration_fingerprint="d"*64, configuration_summary={"CMD": "id"},
            verification_policy_id="verification-disabled")
        self.sink({"type": "execution_authorization_requested", "run_id": run_id,
            "module_name": request.module_name, "runtime_target": {"host": "127.0.0.1", "port": 8080, "service": "web"},
            "reproduction_plan": {"cve_id": cve_id, "reproduction_goal": "execute",
                                  "verification_goal": "disabled", "limitations": []},
            "verification_contract": None})
        self.grant = authorization_callback(request)
        type(self).last_grant = self.grant
        status = type(self).status_override or ("completed" if self.grant and self.grant.approved else "execution_unauthorized")
        return {"run_id": run_id, "cve_id": cve_id, "status": status, "errors": [],
            "target": SimpleNamespace(environment=Path("/tmp/vulhub/CVE-2020-1234")),
            "runtime_target": {"host": "127.0.0.1", "port": 8080, "service": "web"},
            "research_result": {"vulnerability_type": "RCE", "vulnerability_mechanism": "quoted mechanism", "trigger_conditions": ["local request"]},
            "reproduction_plan": {"cve_id": cve_id, "vulnerability_type": "RCE", "reproduction_goal": "execute",
                                  "target_service": "web", "limitations": []},
            "execution_result": {"status": "completed", "module_name": request.module_name,
                                 "console_output": "password=topsecret",
                                 "session_after": [{"session_id": "1", "type": "shell"}]},
            "evidence": {"run_id": run_id, "target_id": "target-1", "execution_id": "exec-1", "evidence": [
                {"evidence_id": "session-1"},
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


def test_cli_help_defaults_to_chinese_and_supports_english(monkeypatch, capsys):
    with pytest.raises(SystemExit) as chinese_exit:
        cli.build_parser().parse_args(["--help"])
    assert chinese_exit.value.code == 0
    chinese_help = capsys.readouterr().out
    assert "用法：" in chinese_help and "本地 Vulhub 工作流" in chinese_help
    assert "show this help message" not in chinese_help

    monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--lang", "en", "--help"])
    with pytest.raises(SystemExit) as english_exit:
        cli.main()
    assert english_exit.value.code == 0
    english_help = capsys.readouterr().out
    assert "usage:" in english_help and "Run local Vulhub reproduction workflow." in english_help


def test_cli_argument_errors_default_to_chinese(capsys):
    with pytest.raises(SystemExit) as error:
        cli.build_parser().parse_args(["run"])
    assert error.value.code == 2
    message = capsys.readouterr().err
    assert "用法：" in message and "缺少必需参数：--cve" in message


def test_cli_reports_empty_module_candidates_and_execution_fallback(capsys):
    import io
    cli._event({"type": "module_candidates_found", "module_names": []}, "zh", io.StringIO())
    cli._event({"type": "stage_completed", "stage": "execution",
                "execution_status": "unsupported", "execution_errors": []}, "zh", io.StringIO())
    output = capsys.readouterr().out
    assert "未找到匹配的 Metasploit 模块" in output
    assert "候选模块：[]" not in output
    assert "没有可用的 Metasploit 模块" in output
    assert output.count("已完成") == 0


def test_cli_zh_auto_authorization_artifacts_and_redaction(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "CVE-2020-1234"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    def unexpected_input(prompt):
        raise AssertionError("interactive authorization prompt must stay disabled")
    monkeypatch.setattr("builtins.input", unexpected_input)
    assert cli.main() == 0
    output = capsys.readouterr().out
    assert "漏洞摘要" in output and "exploit/test/demo" in output and "最终执行结果：已完成" in output
    assert "[6/7]" in output and "跳过（第 5 步已执行完成）" in output
    assert "已采集证据：1 条" in output
    run_dir = next((tmp_path / "runs").iterdir())
    assert {"report.md", "result.json", "execution.log", "evidence"} <= {p.name for p in run_dir.iterdir()}
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "VulnForge 运行报告" in report
    assert "验证策略: 已禁用" in report
    assert "必需证据: 无" in report and "可选证据: 无" in report
    assert "结果类型: 未评估" in report
    assert "漏洞复现成功: 未评估" in report and "获得 Shell: 是" in report
    assert "全部证据引用: ['session-1']" in report
    assert json.loads((run_dir / "result.json").read_text(encoding="utf-8"))["status"] == "completed"
    assert "topsecret" not in (run_dir / "execution.log").read_text(encoding="utf-8")
    assert FakeWorkflow.last_grant is not None and FakeWorkflow.last_grant.approved is True
    assert FakeWorkflow.last_grant.module_name == "exploit/test/demo"
    assert FakeWorkflow.last_context.run_dir == run_dir


def test_cli_en_auto_authorizes_without_interactive_terminal(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "CVE-2020-1234", "--lang", "en"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    assert cli.main() == 0
    output = capsys.readouterr().out
    assert "Vulnerability summary" in output and "Continue?" not in output
    run_dir = next((tmp_path / "runs").iterdir())
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    assert result["status"] == "completed"
    assert FakeWorkflow.last_grant is not None and FakeWorkflow.last_grant.approved is True
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
    assert "Final execution: completed" in output
    assert "Verification: inconclusive" not in output
    dirs = list((tmp_path / "runs").iterdir())
    assert len(dirs) == 2 and dirs[0] != dirs[1]
    for run_dir in dirs:
        events = (run_dir / "execution.log").read_text(encoding="utf-8")
        assert "module_candidates_found" in events and "session_detected" in events


def test_job_display_uses_session_success_without_exposing_secondary_module_error():
    assert cli._display_job_status("errored", "session_established", "zh") == "completed"
    assert cli._display_job_status("errored", "session_established", "en") == "completed"
    assert cli._display_job_status("errored", "none", "zh") == "errored"


def test_redaction_covers_rpc_password_and_api_key():
    safe = cli._safe({"MSFRPC_PASS": "rpc-secret", "api_key": "key-secret", "message": "password=inline-secret"})
    rendered = json.dumps(safe)
    assert "rpc-secret" not in rendered and "key-secret" not in rendered and "inline-secret" not in rendered


@pytest.mark.parametrize("status,expected", [
    ("completed", 0), ("failed", 3), ("unsupported", 0),
    ("execution_failed", 4), ("plan_blocked", 0), ("cancelled", 0),
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
