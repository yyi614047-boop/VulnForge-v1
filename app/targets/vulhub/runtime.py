"""Run-scoped Docker Compose lifecycle for local Vulhub environments."""
from __future__ import annotations
from contextlib import nullcontext

import ipaddress
import copy
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Callable

import yaml

from app.agents.execution import RuntimeTarget
from app.targets.material import TargetMaterial


class VulhubRuntimeError(RuntimeError):
    pass


_ENV_REFERENCE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:-|-)([^}]*))?\}"
)
_UNRESOLVED_ENV = re.compile(r"(?<!\$)\$(?:\{|[A-Za-z_])")


def _resolve_compose_value(value):
    if isinstance(value, dict):
        return {key: _resolve_compose_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_compose_value(item) for item in value]
    if not isinstance(value, str):
        return value
    sentinel = "\u0000VULNFORGE_DOLLAR\u0000"
    protected = value.replace("$$", sentinel)

    def replace(match: re.Match[str]) -> str:
        name, operator, default = match.groups()
        current = os.environ.get(name)
        if operator == ":-":
            return current if current not in {None, ""} else default
        if operator == "-":
            return current if current is not None else default
        if current is not None:
            return current
        return match.group(0)

    return _ENV_REFERENCE.sub(replace, protected).replace(sentinel, "$$")


def _has_unresolved_interpolation(value) -> bool:
    if isinstance(value, dict):
        return any(_has_unresolved_interpolation(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_unresolved_interpolation(item) for item in value)
    return isinstance(value, str) and bool(_UNRESOLVED_ENV.search(value))


class VulhubDockerRuntime:
    """Owns only one run-scoped Compose project and a temporary MSF network lease."""
    METASPLOIT_IMAGE = "metasploitframework/metasploit-framework:latest"
    METASPLOIT_RPC_EXECUTABLE = "/usr/src/metasploit-framework/msfrpcd"

    def __init__(self, workspace: Path, *, metasploit_container: str,
                 rpc_user: str = "msf", rpc_password: str = "", rpc_port: int = 55553,
                 runner: Callable = subprocess.run, timeout: int = 180):
        self.workspace = workspace.resolve()
        self.metasploit_container = metasploit_container
        self.rpc_user, self.rpc_password, self.rpc_port = rpc_user, rpc_password, rpc_port
        self.runner = runner
        self.timeout = timeout
        self.compose_progress = None
        self._runs: dict[str, dict] = {}

    def _call(self, argv: list[str], *, cwd: Path | None = None, live_progress=False,
              include_stderr=False) -> str:
        try:
            if live_progress:
                streams = {"stderr": subprocess.PIPE}
            else:
                streams = {"capture_output": True}
            result = self.runner(argv, **streams, text=True, encoding="utf-8",
                                 errors="replace", timeout=self.timeout, shell=False,
                                 cwd=str(cwd) if cwd else None)
        except Exception as exc:
            raise VulhubRuntimeError(f"Docker operation failed: {type(exc).__name__}: {exc}") from exc
        if result.returncode:
            raise VulhubRuntimeError(f"Docker operation failed ({result.returncode}): {(result.stderr or '')[-2000:]}")
        output = result.stdout or ""
        if include_stderr and result.stderr:
            output += ("\n" if output else "") + result.stderr
        return output

    @staticmethod
    def _validate_compose(material: TargetMaterial) -> dict:
        config = _resolve_compose_value(copy.deepcopy(material.attributes.get("compose")))
        if not isinstance(config, dict) or not isinstance(config.get("services"), dict) or not config["services"]:
            raise VulhubRuntimeError("Local Vulhub Compose services are missing or invalid")
        unsupported_top_level = {
            key for key in config
            if key not in {"version", "services", "networks"} and not key.startswith("x-")
        }
        if unsupported_top_level:
            raise VulhubRuntimeError("Compose contains unsupported top-level resource declarations")
        allowed_service_fields = {"image", "build", "volumes", "ports", "environment", "command",
                                  "entrypoint", "healthcheck", "depends_on", "networks", "expose", "user"}
        networks = config.get("networks", {})
        if not isinstance(networks, dict):
            raise VulhubRuntimeError("Compose networks must be a mapping")
        for name, network in networks.items():
            if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name)
                    or not isinstance(network, dict) or network.get("internal") is not True
                    or set(network) - {"internal"}):
                raise VulhubRuntimeError("Only unnamed Docker-internal Compose networks are permitted")
        for name, service in config["services"].items():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name) or not isinstance(service, dict):
                raise VulhubRuntimeError("Compose contains an invalid service declaration")
            if set(service) - allowed_service_fields:
                raise VulhubRuntimeError(f"Compose service {name} contains an unsafe or unsupported field")
            referenced_networks = service.get("networks", [])
            if isinstance(referenced_networks, dict):
                referenced_networks = list(referenced_networks)
            if (not isinstance(referenced_networks, list)
                    or any(item not in networks for item in referenced_networks)):
                raise VulhubRuntimeError(f"Compose service {name} references an undeclared or non-isolated network")
            for port in service.get("ports", []):
                if not isinstance(port, str):
                    raise VulhubRuntimeError("Compose ports must use the supported short string syntax")
                container_port = port.rsplit(":", 1)[-1]
                pieces = container_port.split("/", 1)
                if (not pieces[0].isdigit() or len(pieces) > 1 and pieces[1].lower() != "tcp"):
                    raise VulhubRuntimeError("Only single TCP container ports are supported")
            expose = service.get("expose", [])
            if not isinstance(expose, list) or any(not str(item).split("/", 1)[0].isdigit()
                                                    or len(str(item).split("/", 1)) > 1
                                                    and str(item).split("/", 1)[1].lower() != "tcp"
                                                    for item in expose):
                raise VulhubRuntimeError("Only single TCP exposed container ports are supported")
            volumes = service.get("volumes", [])
            if not isinstance(volumes, list):
                raise VulhubRuntimeError("Compose volumes must be a list")
            normalized_volumes = []
            for mount in volumes:
                if isinstance(mount, str):
                    parts = mount.split(":")
                    if len(parts) not in (2, 3) or not parts[0] or not parts[1]:
                        raise VulhubRuntimeError("Only project-relative short bind mounts are supported")
                    source_path, target_path = parts[:2]
                    if not (source_path in {".", ".."} or source_path.startswith(("./", "../"))):
                        raise VulhubRuntimeError("Named volumes and host-absolute bind mounts are not supported")
                    if len(parts) == 3 and parts[2] not in {"", "ro"}:
                        raise VulhubRuntimeError("Short bind mounts are forced read-only; use :ro or omit the mode")
                    mount = {"type": "bind", "source": source_path,
                             "target": target_path, "read_only": True}
                if not isinstance(mount, dict) or set(mount) != {"type", "source", "target", "read_only"}:
                    raise VulhubRuntimeError("Only explicit read-only project bind mounts are supported")
                source = (material.environment / mount["source"]).resolve()
                if (mount["type"] != "bind" or mount["read_only"] is not True
                        or not source.is_relative_to(material.environment.resolve()) or not source.exists()
                        or not isinstance(mount["target"], str) or not mount["target"].startswith("/")
                        or ".." in mount["target"].split("/")):
                    raise VulhubRuntimeError("Compose bind mounts must be read-only and inside the local Vulhub target")
                normalized_volumes.append(mount)
            if volumes:
                service["volumes"] = normalized_volumes
            build = service.get("build")
            if build is not None:
                build = {"context": build} if isinstance(build, str) else build
                if not isinstance(build, dict) or set(build) - {"context", "dockerfile", "args", "target"}:
                    raise VulhubRuntimeError("Compose build settings exceed the supported local subset")
                context = (material.environment / build.get("context", ".")).resolve()
                dockerfile = (context / build.get("dockerfile", "Dockerfile")).resolve()
                if (not context.is_relative_to(material.environment.resolve()) or not context.is_dir()
                        or not dockerfile.is_relative_to(context) or not dockerfile.is_file()):
                    raise VulhubRuntimeError("Compose build context and Dockerfile must stay inside the local target")
        if _has_unresolved_interpolation(config):
            raise VulhubRuntimeError("Compose environment interpolation must be resolved before this local run")
        return config

    def _service_container(self, run: dict, service: str) -> dict | None:
        listed = self._call([*run["prefix"], "ps", "-a", "-q", service],
                            cwd=run["target"].environment)
        ids = [line.strip() for line in listed.splitlines() if line.strip()]
        if not ids:
            return None
        if len(ids) != 1:
            raise VulhubRuntimeError(f"Expected exactly one container for Compose service {service}")
        rows = json.loads(self._call(["docker", "inspect", ids[0]]))
        if not isinstance(rows, list) or len(rows) != 1:
            raise VulhubRuntimeError(f"Could not inspect Compose service {service}")
        return rows[0]

    def _service_diagnostics(self, run: dict, service: str, row: dict | None) -> str:
        details = []
        if row:
            container_id = row.get("Id")
            state = row.get("State", {})
            details.append(f"state={state.get('Status')} exit_code={state.get('ExitCode')}")
            health = state.get("Health") or {}
            for entry in (health.get("Log") or [])[-3:]:
                output = str(entry.get("Output") or "").strip()
                if output:
                    details.append(f"health={output[-1000:]}")
            if container_id:
                try:
                    logs = self._call(["docker", "logs", "--tail", "80", container_id],
                                      include_stderr=True)
                except VulhubRuntimeError as exc:
                    details.append(f"logs_error={exc}")
                else:
                    details.append(f"logs=\n{logs[-4000:]}")
        return "\n".join(details)[-8000:]

    def _wait_for_service(self, run: dict, service: str) -> dict:
        deadline = time.monotonic() + min(self.timeout, 120)
        restarts = 0
        row = None
        while time.monotonic() < deadline:
            row = self._service_container(run, service)
            if row is None:
                time.sleep(1)
                continue
            state = row.get("State", {})
            if state.get("Running") is True:
                health = state.get("Health")
                if not health or health.get("Status") == "healthy":
                    return row
            elif state.get("Status") == "exited":
                if state.get("ExitCode") == 0:
                    raise VulhubRuntimeError(
                        f"Network-facing Compose service {service} exited successfully but must remain running"
                    )
                if restarts >= 10:
                    diagnostics = self._service_diagnostics(run, service, row)
                    raise VulhubRuntimeError(
                        f"Compose service {service} did not become ready after bounded restarts"
                        + (f"\n{diagnostics}" if diagnostics else "")
                    )
                self._call([*run["prefix"], "start", service], cwd=run["target"].environment)
                restarts += 1
                time.sleep(2)
                continue
            time.sleep(1)
        diagnostics = self._service_diagnostics(run, service, row)
        raise VulhubRuntimeError(
            f"Compose service {service} did not become ready before the startup deadline"
            + (f"\n{diagnostics}" if diagnostics else "")
        )

    def _wait_for_network_services(self, run: dict, config: dict) -> None:
        for name, service in config["services"].items():
            if service.get("ports") or service.get("expose"):
                self._wait_for_service(run, name)

    def start(self, *, target: TargetMaterial, run_id: str) -> dict:
        config = self._validate_compose(target)
        project = "lab-" + re.sub(r"[^a-z0-9_-]", "-", run_id.lower())[:48].strip("-_")
        if not re.fullmatch(r"lab-[a-z0-9][a-z0-9_-]{0,48}", project):
            raise VulhubRuntimeError("Run ID cannot be represented as a safe Docker project")
        run_dir = self.workspace / project
        run_dir.mkdir(parents=True, exist_ok=True)
        override = run_dir / "vulhub-isolation.override.yml"
        sanitized_path = run_dir / "vulhub-internal-only.compose.yml"
        sanitized = copy.deepcopy(config)
        for service in sanitized["services"].values():
            published = service.pop("ports", [])
            exposed = [str(value) for value in service.get("expose", [])]
            for declaration in published:
                container_port = declaration.rsplit(":", 1)[-1]
                if "/" in container_port:
                    port, protocol = container_port.split("/", 1)
                else:
                    port, protocol = container_port, "tcp"
                if protocol.lower() == "tcp" and port not in exposed:
                    exposed.append(port)
            if exposed:
                service["expose"] = exposed
        sanitized_path.write_text(yaml.safe_dump(sanitized, sort_keys=True), encoding="utf-8")
        overlay = {"services": {name: {"networks": ["vulnforge_internal"]}
                                 for name in config["services"]},
                   "networks": {"vulnforge_internal": {"internal": True}}}
        override.write_text(yaml.safe_dump(overlay, sort_keys=True), encoding="utf-8")
        prefix = ["docker", "compose", "--project-name", project,
                  "--project-directory", str(target.environment), "--file",
                  str(sanitized_path), "--file", str(override)]
        network_name = f"{project}_vulnforge_internal"
        run = {"project": project, "prefix": prefix, "target": target,
               "network_name": network_name, "override": override,
               "metasploit_attached": False}
        self._runs[run_id] = run
        try:
            with self.compose_progress() if self.compose_progress else nullcontext():
                self._call([*prefix, "up", "-d"], cwd=target.environment,
                           live_progress=self.compose_progress is not None)
            self._wait_for_network_services(run, config)
        except Exception as exc:
            try:
                self.cleanup_target(run_id=run_id)
            except Exception as cleanup_exc:
                raise VulhubRuntimeError(f"{exc}; target cleanup also failed: {cleanup_exc}") from exc
            finally:
                self._runs.pop(run_id, None)
            raise
        return {"project": project, "network_name": network_name,
                "compose_sha256": __import__("hashlib").sha256(
                    json.dumps(config, sort_keys=True).encode()).hexdigest(),
                "started": True}

    def prepare_metasploit(self, *, run_id: str) -> dict:
        run = self._runs[run_id]
        existing = self._call(["docker", "container", "ls", "-a", "--filter",
                               f"name=^/{self.metasploit_container}$", "--format", "{{.Names}}"])
        if self.metasploit_container not in existing.splitlines():
            self._create_metasploit(run)
        else:
            rows = json.loads(self._call(["docker", "inspect", self.metasploit_container]))
            if rows[0].get("Config", {}).get("Image") != self.METASPLOIT_IMAGE:
                raise VulhubRuntimeError("Configured Metasploit container uses an unexpected image")
            if rows[0].get("State", {}).get("Running") is not True:
                try:
                    self._call(["docker", "start", self.metasploit_container])
                except VulhubRuntimeError:
                    self._call(["docker", "rm", "-f", self.metasploit_container])
                    self._create_metasploit(run)
                else:
                    run["metasploit_started"] = True
        network = json.loads(self._call(["docker", "network", "inspect", run["network_name"]]))
        if (not isinstance(network, list) or len(network) != 1
                or network[0].get("Name") != run["network_name"]
                or network[0].get("Internal") is not True
                or not re.fullmatch(r"[0-9a-f]{64}", str(network[0].get("Id", "")))):
            raise VulhubRuntimeError("Vulhub runtime network is not isolated")
        run["network_id"] = network[0]["Id"]
        rows = json.loads(self._call(["docker", "inspect", self.metasploit_container]))
        if len(rows) != 1 or rows[0].get("State", {}).get("Running") is not True:
            raise VulhubRuntimeError("Configured Metasploit container did not start")
        attached = rows[0].get("NetworkSettings", {}).get("Networks") or {}
        if not isinstance(attached, dict) or not attached:
            raise VulhubRuntimeError("Metasploit container must have at least one existing Docker network")
        original_networks = {}
        for name, details in attached.items():
            network_id = details.get("NetworkID") if isinstance(details, dict) else None
            if not isinstance(name, str) or not name or not re.fullmatch(r"[0-9a-f]{64}", str(network_id or "")):
                raise VulhubRuntimeError("Could not snapshot Metasploit's existing Docker network identities")
            original_networks[name] = {
                "network_id": network_id,
                "aliases": list(details.get("Aliases") or []),
                "ipam_config": dict(details.get("IPAMConfig") or {}),
            }
        container_id = rows[0].get("Id")
        if not isinstance(container_id, str) or not container_id:
            raise VulhubRuntimeError("Could not identify the running Metasploit container")
        run["metasploit_container_id"] = container_id
        run["metasploit_original_networks"] = original_networks
        # Mark the lease before disconnecting so partial failures still restore prior networks.
        run["metasploit_changed"] = True
        try:
            for original_name in original_networks:
                self._call(["docker", "network", "disconnect", original_name, container_id])
            self._call(["docker", "network", "connect", run["network_name"], container_id])
            self._call(["docker", "restart", container_id])
            check = json.loads(self._call(["docker", "inspect", container_id]))
            networks = check[0].get("NetworkSettings", {}).get("Networks") or {}
            if (set(networks) != {run["network_name"]}
                    or networks[run["network_name"]].get("NetworkID") != run["network_id"]
                    or check[0].get("State", {}).get("Running") is not True):
                raise VulhubRuntimeError("Could not verify isolated Metasploit network attachment")
            callback_ip = ipaddress.ip_address(
                networks[run["network_name"]].get("IPAddress", "")
            )
            if callback_ip.version != 4 or not callback_ip.is_private or callback_ip.is_loopback or callback_ip.is_link_local:
                raise VulhubRuntimeError("Metasploit did not receive an isolated private IPv4 callback address")
            run["metasploit_ip"] = str(callback_ip)
            run["metasploit_attached"] = True
            run["metasploit_container_id"] = check[0].get("Id")
            return {"network_name": run["network_name"], "container_id": check[0].get("Id"),
                    "callback_host": run["metasploit_ip"]}
        except Exception:
            self.restore_metasploit(run_id=run_id)
            raise

    def _create_metasploit(self, run: dict) -> None:
        if not self.rpc_password:
            raise VulhubRuntimeError("MSFRPC_PASS is required to start the managed Metasploit container")
        self._call(["docker", "run", "-d", "--name", self.metasploit_container,
                    "--label", "io.vulnforge.managed=metasploit", self.METASPLOIT_IMAGE,
                    self.METASPLOIT_RPC_EXECUTABLE,
                    "-P", self.rpc_password, "-U", self.rpc_user,
                    "-a", "127.0.0.1", "-p", str(self.rpc_port), "-S", "-f"])
        run["metasploit_created"] = True

    def resolve_target(self, *, run_id: str, service: str, port: int | None = None) -> RuntimeTarget:
        run = self._runs[run_id]
        config = run["target"].attributes["compose"]
        if service not in config["services"]:
            raise VulhubRuntimeError("Planner-selected service is not in the local Compose file")
        self._wait_for_service(run, service)
        listed = self._call([*run["prefix"], "ps", "-q", service], cwd=run["target"].environment)
        ids = [line.strip() for line in listed.splitlines() if line.strip()]
        if len(ids) != 1:
            raise VulhubRuntimeError("Expected exactly one running target service container")
        rows = json.loads(self._call(["docker", "inspect", ids[0]]))
        row = rows[0]
        if row.get("State", {}).get("Running") is not True:
            raise VulhubRuntimeError("Selected target service is not running")
        network = row.get("NetworkSettings", {}).get("Networks", {}).get(run["network_name"])
        if not network:
            raise VulhubRuntimeError("Target container is not attached to this run's isolated network")
        if set(row.get("NetworkSettings", {}).get("Networks", {})) != {run["network_name"]}:
            raise VulhubRuntimeError("Target container has an unexpected additional network attachment")
        address = ipaddress.ip_address(network.get("IPAddress", ""))
        if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
            raise VulhubRuntimeError("Target container did not receive a private isolated IPv4 address")
        # Cross-check the requested container port against the source Compose service.
        declared = set()
        for item in config["services"][service].get("ports", []):
            parts = item.split(":")[-1].split("/")
            try:
                if len(parts) == 1 or parts[1].lower() == "tcp": declared.add(int(parts[0]))
            except (ValueError, AttributeError): pass
        for item in config["services"][service].get("expose", []):
            parts = str(item).split("/")
            try:
                if len(parts) == 1 or parts[1].lower() == "tcp": declared.add(int(parts[0]))
            except ValueError: pass
        if port is None:
            if len(declared) != 1:
                raise VulhubRuntimeError("Target port is ambiguous; provide the module RPORT explicitly")
            port = next(iter(declared))
        if port not in declared:
            raise VulhubRuntimeError("Resolved port is not declared for the selected Compose service")
        callback_host = run.get("metasploit_ip")
        if not callback_host:
            raise VulhubRuntimeError("Metasploit callback address was not resolved")
        image = json.loads(self._call(["docker", "image", "inspect", row["Image"]]))[0]
        return RuntimeTarget.from_vulhub(target=run["target"], run_id=run_id, service=service,
                                         port=port, host=str(address), callback_host=callback_host,
                                         project=run["project"],
                                         container_id=row.get("Id", ids[0]),
                                         network_name=run["network_name"], network_id=network.get("NetworkID"),
                                         os=image.get("Os"), architecture=image.get("Architecture"))

    def inspect_file_artifact(self, *, run_id: str, service: str,
                              path_pattern: str) -> dict:
        if (not isinstance(path_pattern, str) or not path_pattern.startswith("/")
                or len(path_pattern) > 500 or ".." in path_pattern.split("/")
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in path_pattern)
                or any(ch in path_pattern for ch in ";|&$`")):
            raise VulhubRuntimeError("Unsafe file artifact pattern")
        root = "/" + path_pattern.lstrip("/").split("/", 1)[0]
        if root not in {"/opt", "/tmp", "/var", "/home", "/usr/local", "/etc"}:
            raise VulhubRuntimeError("File artifact root is outside the allowed local target paths")
        run = self._runs.get(run_id)
        if not run:
            raise VulhubRuntimeError("Target runtime is not active for this run")
        listed = self._call([*run["prefix"], "ps", "-q", service], cwd=run["target"].environment)
        ids = [line.strip() for line in listed.splitlines() if line.strip()]
        if len(ids) != 1:
            raise VulhubRuntimeError("Expected exactly one running target service container")
        script = (
            'root=$1; pattern=$2; base=${pattern##*/}; '
            'find "$root" -type f \\( -path "$pattern" -o -name "$base" \\) -print 2>/dev/null | '
            'while IFS= read -r file; do '
            'size=$(stat -c %s "$file" 2>/dev/null || printf 0); '
            'hash=$(sha256sum "$file" 2>/dev/null || printf 0); hash=${hash%% *}; '
            'printf "%s\\t%s\\t%s\\n" "$file" "$size" "$hash"; done'
        )
        output = self._call(["docker", "exec", ids[0], "sh", "-c", script, "sh", root, path_pattern])
        matches = []
        for line in output.splitlines()[-200:]:
            parts = line.split("\t", 2)
            if len(parts) != 3:
                continue
            path, size, digest = parts
            matches.append({
                "path": path,
                "size": int(size) if size.isdigit() else None,
                "sha256": digest if re.fullmatch(r"[0-9a-f]{64}", digest) else None,
            })
        return {"path_pattern": path_pattern, "matches": matches}

    def collect_target_logs(self, *, run_id: str, service: str, tail: int = 80) -> dict:
        run = self._runs.get(run_id)
        if not run:
            return {}
        listed = self._call([*run["prefix"], "ps", "-q", service], cwd=run["target"].environment)
        ids = [line.strip() for line in listed.splitlines() if line.strip()]
        if len(ids) != 1:
            return {"target_log_error": "Expected exactly one target service container for diagnostics"}
        output = self._call(["docker", "logs", "--tail", str(max(1, min(tail, 500))), ids[0]],
                            include_stderr=True)
        diagnostics = {"target_log_tail": output[-8000:]}
        statuses = re.findall(r"(?:badMessage:\s*|HTTP/\d(?:\.\d)?\"\s+)(4\d\d|5\d\d)\b", output)
        if statuses:
            diagnostics["http_status"] = int(statuses[-1])
        return diagnostics

    def restore_metasploit(self, *, run_id: str) -> dict:
        run = self._runs.get(run_id)
        if not run:
            return {"restored": True, "changed": False}
        if run.get("metasploit_changed"):
            rows = json.loads(self._call(["docker", "inspect", self.metasploit_container]))
            networks = rows[0].get("NetworkSettings", {}).get("Networks") or {}
            if rows[0].get("Id") != run.get("metasploit_container_id"):
                raise VulhubRuntimeError("Metasploit container identity changed; refusing to alter a replacement container")
            if run["network_name"] in networks:
                self._call(["docker", "network", "disconnect", run["network_name"], run["metasploit_container_id"]])
            original_networks = run.get("metasploit_original_networks") or {}
            for original_name, original in original_networks.items():
            # Check the exact network identity before reconnecting: never attach to a
            # different network that reused a prior network's name during the lease.
                inspected = json.loads(self._call(["docker", "network", "inspect", original_name]))
                if (not isinstance(inspected, list) or len(inspected) != 1
                        or inspected[0].get("Id") != original["network_id"]):
                    raise VulhubRuntimeError(f"Original Metasploit network identity changed: {original_name}")
                current = networks.get(original_name)
                if current and current.get("NetworkID") != original["network_id"]:
                    raise VulhubRuntimeError(f"Unexpected network identity is attached to Metasploit: {original_name}")
                if not current:
                    args = ["docker", "network", "connect"]
                    ipam = original.get("ipam_config") or {}
                    if ipam.get("IPv4Address"):
                        args.extend(["--ip", ipam["IPv4Address"]])
                    if ipam.get("IPv6Address"):
                        args.extend(["--ip6", ipam["IPv6Address"]])
                    for alias in original.get("aliases", []):
                        if alias:
                            args.extend(["--alias", alias])
                    self._call([*args, original_name, run["metasploit_container_id"]])
            self._call(["docker", "restart", run["metasploit_container_id"]])
            rows = json.loads(self._call(["docker", "inspect", run["metasploit_container_id"]]))
            networks = rows[0].get("NetworkSettings", {}).get("Networks") or {}
            if set(networks) != set(original_networks) or any(
                    networks[name].get("NetworkID") != original["network_id"]
                    for name, original in original_networks.items()):
                raise VulhubRuntimeError("Metasploit container's original network set could not be restored")
            run["metasploit_attached"] = False
            run["metasploit_changed"] = False
        if run.get("metasploit_created"):
            self._call(["docker", "rm", "-f", self.metasploit_container])
            run["metasploit_created"] = False
        elif run.get("metasploit_started"):
            self._call(["docker", "stop", self.metasploit_container])
            run["metasploit_started"] = False
        return {"restored": True, "changed": True}

    def cleanup_target(self, *, run_id: str) -> dict:
        run = self._runs.get(run_id)
        if not run:
            return {"cleaned": False, "reason": "not_started"}
        self._call([*run["prefix"], "down", "--timeout", "10"], cwd=run["target"].environment)
        return {"cleaned": True, "project": run["project"]}
