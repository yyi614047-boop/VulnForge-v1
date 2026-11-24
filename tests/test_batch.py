import csv
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from app import batch
from app.targets.vulhub.loader import TargetError


def _entry(*, cves, path, tags=("RCE",), app="Example"):
    cve_values = ", ".join(json.dumps(cve) for cve in cves)
    tag_values = ", ".join(json.dumps(tag) for tag in tags)
    return (
        "[[environment]]\n"
        f"name = {json.dumps(path)}\n"
        f"cve = [{cve_values}]\n"
        f"app = {json.dumps(app)}\n"
        f"path = {json.dumps(path)}\n"
        f"tags = [{tag_values}]\n\n"
    )


def _environment(root: Path, path: str) -> None:
    directory = root / path
    directory.mkdir(parents=True)
    (directory / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")


@pytest.fixture
def vulhub(tmp_path):
    root = tmp_path / "vulhub"
    root.mkdir()
    _environment(root, "first")
    _environment(root, "rce")
    _environment(root, "duplicate")
    _environment(root, "no-cve")
    manifest = "".join([
        _entry(cves=["CVE-2020-0001"], path="first", tags=("SQL Injection",)),
        _entry(cves=["CVE-2020-0001"], path="rce"),
        _entry(cves=["CVE-2020-0002", "CVE-2020-0003"], path="rce", app="RCE App"),
        _entry(cves=["CVE-2020-0002"], path="duplicate"),
        _entry(cves=[], path="no-cve"),
    ])
    (root / "environments.toml").write_text(manifest, encoding="utf-8")
    return root


def test_discovery_selects_only_first_resolvable_rce_variants(vulhub):
    discovery = batch.discover_rce_targets(vulhub)
    assert [target.cve for target in discovery.selected] == ["CVE-2020-0002", "CVE-2020-0003"]
    assert all(target.environment == vulhub / "rce" for target in discovery.selected)
    reasons = [item.reason for item in discovery.skipped]
    assert "resolved_other_variant" in reasons
    assert "duplicate_cve" in reasons
    assert "no_cve" in reasons


def test_discovery_filters_requested_cves_and_reports_missing(vulhub):
    discovery = batch.discover_rce_targets(vulhub, only_cves=["cve-2020-0003", "CVE-2020-9999"])
    assert [target.cve for target in discovery.selected] == ["CVE-2020-0003"]
    assert any(item.cve == "CVE-2020-9999" and item.reason == "not_found"
               for item in discovery.skipped)


def test_discovery_rejects_unsafe_manifest_paths(vulhub):
    (vulhub / "environments.toml").write_text(
        _entry(cves=["CVE-2020-0004"], path="../outside"), encoding="utf-8",
    )
    with pytest.raises(TargetError, match="Unsafe environment path"):
        batch.discover_rce_targets(vulhub)


class FakeRunner:
    def __init__(self, statuses=(), *, write_results=True):
        self.statuses = list(statuses)
        self.write_results = write_results
        self.calls = []

    def __call__(self, command, *, env, check, timeout):
        self.calls.append({"command": command, "env": env, "check": check, "timeout": timeout})
        cve = command[command.index("--cve") + 1]
        if self.write_results:
            run_dir = Path(env["VULNFORGE_RUNS_ROOT"]) / f"run_{cve}"
            run_dir.mkdir()
            status = self.statuses.pop(0) if self.statuses else "completed"
            exit_code = {"completed": 0, "execution_failed": 4, "cancelled": 0}[status]
            result = {
                "run_id": run_dir.name,
                "cve_id": cve,
                "status": status,
                "verification_summary": {},
                "errors": ["mock failure"] if status == "execution_failed" else [],
            }
            (run_dir / "result.json").write_text(json.dumps(result), encoding="utf-8")
            (run_dir / "report.md").write_text("mock report", encoding="utf-8")
            return SimpleNamespace(returncode=exit_code)
        return SimpleNamespace(returncode=0)


def _execute_args(vulhub, batch_dir, *extra):
    return [
        "--vulhub-root", str(vulhub), "--execute", "--batch-dir", str(batch_dir),
        "--cve", "CVE-2020-0002", "--cve", "CVE-2020-0003", *extra,
    ]


def test_dry_run_lists_targets_without_creating_artifacts(vulhub, tmp_path, capsys):
    runner = FakeRunner()
    batch_dir = tmp_path / "batch"
    assert batch.main(["--vulhub-root", str(vulhub), "--batch-dir", str(batch_dir)],
                      runner=runner) == 0
    output = capsys.readouterr().out
    assert "CVE-2020-0002" in output and "CVE-2020-0003" in output
    assert "当前仅预演，未执行" in output and "--execute" in output
    assert runner.calls == []
    assert not batch_dir.exists()


def test_execute_runs_without_interactive_authorization(vulhub, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(batch.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    runner = FakeRunner()
    batch_dir = tmp_path / "batch"
    assert batch.main(_execute_args(vulhub, batch_dir), runner=runner) == 0
    output = capsys.readouterr().out
    assert "交互式终端" not in output
    assert len(runner.calls) == 2
    assert batch_dir.exists()


def test_execute_continues_after_failure_and_writes_summary(vulhub, tmp_path, monkeypatch):
    monkeypatch.setattr(batch.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    runner = FakeRunner(["completed", "execution_failed"])
    batch_dir = tmp_path / "batch"
    assert batch.main(_execute_args(vulhub, batch_dir), runner=runner) == 1
    assert len(runner.calls) == 2
    for call in runner.calls:
        assert "--no-cleanup-prompt" not in call["command"]
        assert call["env"]["VULNFORGE_VULHUB_ROOT"] == str(vulhub.resolve())
        assert call["env"]["VULNFORGE_RUNS_ROOT"] == str(batch_dir / "runs")
    summary = json.loads((batch_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["completed_count"] == 2 and summary["remaining_count"] == 0
    assert summary["status_counts"] == {"execution_failed": 1, "completed": 1}
    assert [row["status"] for row in csv.DictReader(
        (batch_dir / "summary.csv").read_text(encoding="utf-8-sig").splitlines(),
    )] == ["completed", "execution_failed"]
    assert [row["verification_status"] for row in summary["results"]] == ["disabled", "disabled"]


def test_stop_on_error_stops_before_next_target(vulhub, tmp_path, monkeypatch):
    monkeypatch.setattr(batch.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    runner = FakeRunner(["execution_failed", "completed"])
    batch_dir = tmp_path / "batch"
    assert batch.main(_execute_args(vulhub, batch_dir, "--stop-on-error"), runner=runner) == 1
    assert len(runner.calls) == 1
    summary = json.loads((batch_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["stopped_reason"] == "stop_on_error"
    assert summary["remaining_count"] == 1


def test_user_cancellation_stops_batch(vulhub, tmp_path, monkeypatch):
    monkeypatch.setattr(batch.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    runner = FakeRunner(["cancelled", "completed"])
    batch_dir = tmp_path / "batch"
    assert batch.main(_execute_args(vulhub, batch_dir), runner=runner) == 130
    assert len(runner.calls) == 1
    summary = json.loads((batch_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["stopped_reason"] == "user_cancelled"


def test_missing_result_artifact_is_a_hard_failure(vulhub, tmp_path, monkeypatch):
    monkeypatch.setattr(batch.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    runner = FakeRunner(write_results=False)
    batch_dir = tmp_path / "batch"
    assert batch.main(_execute_args(vulhub, batch_dir), runner=runner) == 1
    summary = json.loads((batch_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["status_counts"] == {"artifact_missing": 2}


def test_timeout_is_recorded_without_retrying(vulhub, tmp_path, monkeypatch):
    monkeypatch.setattr(batch.sys, "stdin", SimpleNamespace(isatty=lambda: True))

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 1)

    batch_dir = tmp_path / "batch"
    assert batch.main(_execute_args(vulhub, batch_dir, "--timeout", "1"), runner=timeout) == 1
    summary = json.loads((batch_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["status_counts"] == {"timeout": 2}
    assert all("exceeded 1 seconds" in result["errors"][0] for result in summary["results"])


def test_batch_artifacts_cannot_be_written_inside_vulhub(vulhub, tmp_path, monkeypatch):
    monkeypatch.setattr(batch.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    runner = FakeRunner()
    assert batch.main(_execute_args(vulhub, vulhub / "artifacts"), runner=runner) == 2
    assert runner.calls == []
    assert not (vulhub / "artifacts").exists()


def test_missing_vulhub_root_returns_configuration_error(tmp_path, capsys):
    assert batch.main(["--vulhub-root", str(tmp_path / "missing")]) == 2
    assert capsys.readouterr().err


def test_requested_cve_must_be_a_runnable_rce_variant(vulhub, capsys):
    assert batch.main([
        "--vulhub-root", str(vulhub), "--cve", "CVE-2020-9999",
    ]) == 2
    captured = capsys.readouterr()
    assert "已选择 0 个 RCE CVE" in captured.out
    assert "Skipped:" not in captured.out
    assert "指定的 CVE 均不是可运行的 RCE 清单条目" in captured.err


def test_batch_help_and_errors_default_to_chinese(capsys):
    with pytest.raises(SystemExit) as help_exit:
        batch.build_parser().parse_args(["--help"])
    assert help_exit.value.code == 0
    help_text = capsys.readouterr().out
    assert "用法：" in help_text and "逐个授权并按顺序运行" in help_text
    assert "show this help message" not in help_text

    with pytest.raises(SystemExit) as error:
        batch.build_parser().parse_args(["--limit", "0"])
    assert error.value.code == 2
    error_text = capsys.readouterr().err
    assert "参数 --limit：必须至少为 1" in error_text


def test_batch_explicit_english_output_is_preserved(vulhub, capsys):
    assert batch.main(["--vulhub-root", str(vulhub), "--lang", "en"]) == 0
    output = capsys.readouterr().out
    assert "Selected RCE CVEs: 2" in output
    assert "Dry run only. Re-run with --execute" in output


def test_batch_explicit_english_help_is_preserved(capsys):
    with pytest.raises(SystemExit) as help_exit:
        batch.build_parser("en").parse_args(["--help"])
    assert help_exit.value.code == 0
    help_text = capsys.readouterr().out
    assert "usage:" in help_text
    assert "Run local Vulhub RCE CVEs sequentially" in help_text
