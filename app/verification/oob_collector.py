"""Token-bound OOB callback collector isolated on the active lab network."""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import uuid

from app.verification.contracts import OobExpectation


_MARKER = "__VULNFORGE_OOB__"
_LISTENER = r'''
import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def handle_callback(self):
        if self.path == os.environ["VULNFORGE_OOB_PATH"]:
            print("__VULNFORGE_OOB__" + json.dumps({
                "path": self.path, "method": self.command,
                "remote_host": self.client_address[0], "remote_port": self.client_address[1],
            }), flush=True)
        self.send_response(204)
        self.end_headers()
    do_GET = handle_callback
    do_POST = handle_callback
    do_PUT = handle_callback
    do_PATCH = handle_callback
    do_DELETE = handle_callback
    do_HEAD = handle_callback
    def log_message(self, *args):
        pass
HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
'''


class OobCallbackCollector:
    def __init__(self, *, runner=subprocess.run, image="python:3.12-alpine", port=8000):
        self.runner, self.image, self.port = runner, image, port
        self._active: dict[str, dict] = {}

    def start(self, *, run_id: str, network_name: str,
              expectation: OobExpectation) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", network_name):
            raise ValueError("Invalid isolated network name")
        if run_id in self._active:
            raise RuntimeError("An OOB collector is already active for this run")
        safe_run = re.sub(r"[^A-Za-z0-9_.-]", "-", run_id)[:48]
        container = f"vulnforge-oob-{safe_run}-{uuid.uuid4().hex[:8]}"
        command = [
            "docker", "run", "-d", "--rm", "--name", container,
            "--network", network_name, "--user", "65534:65534",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--pids-limit", "64", "--memory", "128m", "--cpus", "0.5",
            "--pull=never", "--env", f"VULNFORGE_OOB_PATH={expectation.path}",
            self.image, "python", "-I", "-c", _LISTENER,
        ]
        started = self.runner(command, capture_output=True, text=True, timeout=30)
        if started.returncode != 0 or not started.stdout.strip():
            raise RuntimeError(started.stderr or "OOB collector container did not start")
        container_id = started.stdout.strip()
        try:
            inspected = self.runner(
                ["docker", "inspect", container_id, "--format", "{{json .NetworkSettings.Networks}}"],
                capture_output=True, text=True, timeout=30)
            networks = json.loads(inspected.stdout)
            host = networks[network_name]["IPAddress"]
            address = ipaddress.ip_address(host)
            if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
                raise RuntimeError("OOB collector address is outside the private lab network")
        except Exception:
            self.runner(["docker", "stop", "--time", "2", container_id],
                        capture_output=True, text=True, timeout=10)
            raise
        binding = {
            "container_id": container_id, "callback_host": host, "callback_port": self.port,
            "callback_url": f"http://{host}:{self.port}{expectation.path}",
            "token": expectation.token, "path": expectation.path,
        }
        self._active[run_id] = binding
        return binding

    def collect(self, *, run_id: str, execution, expectation: OobExpectation,
                target_host: str) -> list[dict]:
        binding = self._active.get(run_id)
        if binding is None:
            return []
        logs = self.runner(["docker", "logs", binding["container_id"]],
                           capture_output=True, text=True, timeout=30)
        rows = []
        for line in logs.stdout.splitlines():
            if not line.startswith(_MARKER):
                continue
            try:
                callback = json.loads(line[len(_MARKER):])
            except json.JSONDecodeError:
                continue
            if (callback.get("path") == expectation.path
                    and callback.get("remote_host") == target_host):
                rows.append({
                    "source": "vulnforge_oob_collector",
                    "execution_id": execution.execution_id, "target_id": execution.target_id,
                    "target_host": target_host,
                    "expectation": expectation.model_dump(mode="json"),
                    "token": expectation.token, "path": callback.get("path"),
                    "method": callback.get("method"),
                    "remote_host": callback.get("remote_host"),
                    "remote_port": callback.get("remote_port"),
                })
        return rows

    def stop(self, *, run_id: str) -> None:
        binding = self._active.pop(run_id, None)
        if binding is None:
            return
        self.runner(["docker", "stop", "--time", "2", binding["container_id"]],
                    capture_output=True, text=True, timeout=15)
