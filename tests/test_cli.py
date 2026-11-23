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
    cleanup_calls = []
    status_override = None

    def __init__(self, event_sink, language):
        self.sink, self.language = event_sink, language
        self.target_runtime = SimpleNamespace(cleanup_target=self._cleanup)
        self.grant = None

    def _cleanup(self, **kw):
        type(self).cleanup_calls.append(kw)
        return {"cleaned": True}

    @classmethod
    def from_environment(cls, *, event_sink, language):
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
        request = ExecutionAuthorizationRequest(run_id=run_id, target_id="target-1", target_fingerprint="a"*64,
            plan_fingerprint="b"*64, module_name="exploit/test/demo", module_fingerprint="c"*64,
            verification_policy_id="policy-1")
        self.sink({"type": "execution_authorization_requested", "run_id": run_id,
            "module_name": request.module_name, "runtime_target": {"host": "127.0.0.1", "port": 8080, "service": "web"},
            "reproduction_plan": {"cve_id": cve_id, "reproduction_goal": "verify", "verification_goal": "evidence", "limitations": []}})
        self.grant = authorization_callback(request)
        type(self).last_grant = self.grant
        status = type(self).status_override or ("success" if self.grant and self.grant.approved else "execution_unauthorized")
        verification_status = status if status in {"success", "failed", "inconclusive", "verification_unsupported"} else "inconclusive"
        return {"run_id": run_id, "cve_id": cve_id, "status": status, "errors": [],
            "target": SimpleNamespace(environment=Path("/tmp/vulhub/CVE-2020-1234")),
            "runtime_target": {"host": "127.0.0.1", "port": 8080, "service": "web"},
            "research_result": {"vulnerability_type": "RCE", "vulnerability_mechanism": "quoted mechanism", "trigger_conditions": ["local request"]},
            "reproduction_plan": {"cve_id": cve_id, "reproduction_goal": "verify", "target_service": "web", "limitations": []},
            "execution_result": {"status": "completed", "module_name": request.module_name, "console_output": "password=topsecret"},
            "verification_result": {"status": verification_status, "reason": "mock result", "rule_results": []},
            "evidence": {"run_id": run_id, "target_id": "target-1", "execution_id": "exec-1", "evidence": []}}


def setup(monkeypatch, tmp_path):
    FakeWorkflow.last_grant = None
    FakeWorkflow.cleanup_calls = []
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
    answers = iter(["yes", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert cli.main() == 0
    output = capsys.readouterr().out
    assert "漏洞摘要" in output and "exploit/test/demo" in output and "最终验证结论：success" in output
    run_dir = next((tmp_path / "runs").iterdir())
    assert {"report.md", "result.json", "execution.log", "evidence"} <= {p.name for p in run_dir.iterdir()}
    assert "VulnForge 运行报告" in (run_dir / "report.md").read_text(encoding="utf-8")
    assert json.loads((run_dir / "result.json").read_text(encoding="utf-8"))["status"] == "success"
    assert "topsecret" not in (run_dir / "execution.log").read_text(encoding="utf-8")
    assert FakeWorkflow.last_grant is not None and FakeWorkflow.last_grant.approved is True
    assert FakeWorkflow.last_grant.module_name == "exploit/test/demo"
    assert FakeWorkflow.cleanup_calls == []


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
    assert FakeWorkflow.cleanup_calls == []
    assert "VulnForge run report" in (run_dir / "report.md").read_text(encoding="utf-8")


def test_cli_rejects_invalid_cve_before_workflow(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "not-a-cve"])
    assert cli.main() == 2
    assert "格式无效" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_cleanup_yes_is_scoped_to_this_run_target(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "CVE-2020-1234"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    answers = iter(["y", "yes"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert cli.main() == 0
    assert len(FakeWorkflow.cleanup_calls) == 1
    assert set(FakeWorkflow.cleanup_calls[0]) == {"run_id"}
    assert FakeWorkflow.cleanup_calls[0]["run_id"].endswith("CVE-2020-1234_" + FakeWorkflow.cleanup_calls[0]["run_id"].rsplit("_", 1)[-1])


def test_run_directories_are_unique_and_event_output_is_real(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path)
    for _ in range(2):
        monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "CVE-2020-1234", "--lang", "en"])
        monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
        assert cli.main() == 0
    output = capsys.readouterr().out
    assert "Session detected (not proof of success)" in output
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
    def fail_configuration(cls, *, event_sink, language):
        raise RuntimeError("mock workflow setup failure")
    monkeypatch.setattr(workflow_module.VulnForgeWorkflow, "from_environment", classmethod(fail_configuration))
    monkeypatch.setattr(sys, "argv", ["vulnforge", "run", "--cve", "CVE-2020-1234"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    assert cli.main() == 3
    run_dir = next((tmp_path / "runs").iterdir())
    assert (run_dir / "report.md").exists() and (run_dir / "result.json").exists() and (run_dir / "execution.log").exists()
    assert json.loads((run_dir / "result.json").read_text(encoding="utf-8"))["failed_stage"] == "workflow"
