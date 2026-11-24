from types import SimpleNamespace

import pytest

from app.targets.vulhub.runtime import VulhubDockerRuntime, VulhubRuntimeError


class Runner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if "ps" in argv:
            return SimpleNamespace(returncode=0, stdout="container-1\n", stderr="")
        if argv[:2] == ["docker", "exec"]:
            return SimpleNamespace(
                returncode=0,
                stdout="/opt/activemq/webapps/api/vulnforge_probe.jsp\t118140\t" + "c" * 64 + "\n",
                stderr="",
            )
        raise AssertionError(argv)


def test_inspect_file_artifact_uses_target_container_and_safe_arguments(tmp_path):
    runner = Runner()
    runtime = VulhubDockerRuntime(tmp_path, metasploit_container="msf", runner=runner)
    runtime._runs["run-1"] = {
        "prefix": ["compose"],
        "target": SimpleNamespace(environment=tmp_path),
    }
    result = runtime.inspect_file_artifact(
        run_id="run-1", service="activemq",
        path_pattern="/opt/*/webapps/api/vulnforge_probe.jsp",
    )
    assert result["matches"] == [{
        "path": "/opt/activemq/webapps/api/vulnforge_probe.jsp",
        "size": 118140,
        "sha256": "c" * 64,
    }]
    exec_call = next(call for call in runner.calls if call[:2] == ["docker", "exec"])
    assert exec_call[-2:] == ["/opt", "/opt/*/webapps/api/vulnforge_probe.jsp"]


@pytest.mark.parametrize("pattern", ["/etc/passwd", "/opt/../etc/passwd", "/opt/a;id"])
def test_inspect_file_artifact_rejects_unsafe_patterns(tmp_path, pattern):
    runtime = VulhubDockerRuntime(tmp_path, metasploit_container="msf", runner=Runner())
    runtime._runs["run-1"] = {
        "prefix": ["compose"],
        "target": SimpleNamespace(environment=tmp_path),
    }
    with pytest.raises(VulhubRuntimeError):
        runtime.inspect_file_artifact(run_id="run-1", service="activemq", path_pattern=pattern)
