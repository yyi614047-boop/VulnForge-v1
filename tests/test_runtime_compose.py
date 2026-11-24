from pathlib import Path

import pytest

from app.targets.material import TargetMaterial
from app.targets.vulhub.runtime import VulhubDockerRuntime, VulhubRuntimeError


def material(compose: dict) -> TargetMaterial:
    return TargetMaterial(
        identifier="CVE-2020-17526",
        root=Path("/vulhub"),
        environment=Path("/vulhub/airflow/CVE-2020-17526"),
        document=None,
        supporting_sources=(),
        attributes={"compose": compose},
    )


def test_compose_extensions_user_and_safe_interpolation_are_supported(monkeypatch):
    monkeypatch.setenv("AIRFLOW_UID", "1234")
    compose = {
        "version": "3",
        "x-common": {"image": "example/airflow:1", "user": "${AIRFLOW_UID:-50000}:50000"},
        "services": {
            "web": {
                "image": "example/airflow:1",
                "user": "${AIRFLOW_UID:-50000}:50000",
                "healthcheck": {
                    "test": ["CMD-SHELL", 'check "$${HOSTNAME}"'],
                },
            },
        },
    }

    config = VulhubDockerRuntime._validate_compose(material(compose))

    assert config["x-common"]["image"] == "example/airflow:1"
    assert config["services"]["web"]["user"] == "1234:50000"
    assert config["services"]["web"]["healthcheck"]["test"][1] == 'check "$${HOSTNAME}"'


def test_compose_default_interpolation_is_used_when_environment_is_empty(monkeypatch):
    monkeypatch.delenv("AIRFLOW_UID", raising=False)
    compose = {
        "services": {
            "web": {"image": "example/web:1", "user": "${AIRFLOW_UID:-50000}:50000"},
        },
    }

    config = VulhubDockerRuntime._validate_compose(material(compose))

    assert config["services"]["web"]["user"] == "50000:50000"


def test_compose_rejects_unresolved_interpolation():
    compose = {
        "services": {
            "web": {"image": "example/web:1", "environment": {"VALUE": "${MISSING_VALUE}"}},
        },
    }

    with pytest.raises(VulhubRuntimeError, match="interpolation"):
        VulhubDockerRuntime._validate_compose(material(compose))


def test_compose_rejects_resource_declarations_but_allows_x_extensions():
    compose = {
        "x-common": {"image": "example/web:1"},
        "services": {"web": {"image": "example/web:1"}},
        "secrets": {"token": {"file": "./token"}},
    }

    with pytest.raises(VulhubRuntimeError, match="top-level resource"):
        VulhubDockerRuntime._validate_compose(material(compose))


def test_start_recovers_exposed_service_without_waiting_for_auxiliary_health(tmp_path, monkeypatch):
    compose = {
        "services": {
            "init": {"image": "example/init:1"},
            "web": {"image": "example/web:1", "ports": ["8080:80"]},
            "worker": {
                "image": "example/worker:1",
                "healthcheck": {"test": ["CMD", "false"]},
            },
        },
    }
    calls = []
    inspections = 0

    def runner(argv, **kwargs):
        nonlocal inspections
        calls.append(list(argv))
        output = ""
        if argv[:3] == ["docker", "compose", "--project-name"]:
            if "ps" in argv:
                output = "web-id\n"
        elif argv[:2] == ["docker", "inspect"]:
            inspections += 1
            state = ({"Status": "exited", "Running": False, "ExitCode": 1}
                     if inspections == 1 else
                     {"Status": "running", "Running": True,
                      "Health": {"Status": "healthy", "Log": []}})
            output = __import__("json").dumps([{"Id": "web-id", "State": state}])
        return type("Result", (), {"returncode": 0, "stdout": output, "stderr": ""})()

    monkeypatch.setattr("app.targets.vulhub.runtime.time.sleep", lambda _: None)
    runtime = VulhubDockerRuntime(tmp_path / "workspace", metasploit_container="msf", runner=runner)

    started = runtime.start(target=material(compose), run_id="run-recovery")

    assert started["started"] is True
    assert inspections == 2
    assert any("start" in argv and argv[-1] == "web" for argv in calls)
    assert not any("--wait" in argv for argv in calls)
    assert not any("ps" in argv and argv[-1] == "worker" for argv in calls)


def test_start_failure_preserves_error_and_cleans_partial_project(tmp_path):
    compose = {"services": {"web": {"image": "example/web:1", "ports": ["8080:80"]}}}
    calls = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if "up" in argv:
            return type("Result", (), {"returncode": 1, "stdout": "", "stderr": "upstream failure"})()
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    runtime = VulhubDockerRuntime(tmp_path / "workspace", metasploit_container="msf", runner=runner)

    with pytest.raises(VulhubRuntimeError, match="upstream failure"):
        runtime.start(target=material(compose), run_id="run-failure")

    assert "run-failure" not in runtime._runs
    assert any("down" in argv for argv in calls)
