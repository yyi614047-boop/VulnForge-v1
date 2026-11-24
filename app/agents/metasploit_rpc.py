"""Metasploit MessagePack RPC transports and allowlisted client."""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from urllib.request import Request, urlopen

from app.runtime.config import ConfigurationError


class MetasploitRpcError(RuntimeError):
    def __init__(self, message: str, *, method: str, response: dict):
        super().__init__(message)
        self.method = method
        self.response = response


class MessagePackTransport:
    def __init__(self, host="127.0.0.1", port=55553, timeout=60, opener=urlopen):
        ip = ipaddress.ip_address(host)
        if not ip.is_loopback:
            raise ValueError("RPC connection must use loopback")
        self.host, self.port, self.timeout, self.opener = host, port, timeout, opener

    def call(self, method, *params):
        import msgpack
        req = Request(f"http://{self.host}:{self.port}/api/",
                      data=msgpack.packb([method, *params], use_bin_type=True),
                      headers={"Content-Type": "binary/message-pack"}, method="POST")
        try:
            with self.opener(req, timeout=self.timeout, context=None) as response:
                result = _rpc_normalize(
                    msgpack.unpackb(response.read(), raw=False, strict_map_key=False)
                )
        except Exception as exc:
            raise RuntimeError(f"Metasploit RPC transport failed: {exc}") from exc
        if isinstance(result, dict) and rpc_field(result, "error"):
            error = (rpc_field(result, "error_message") or rpc_field(result, "error_class")
                     or rpc_field(result, "error"))
            raise MetasploitRpcError(rpc_text(error), method=method, response=result)
        return result


class DockerExecMessagePackTransport:
    """Use the legacy loopback RPC endpoint inside the already-running MSF container."""

    def __init__(self, container: str, port=55553, timeout=60, runner=subprocess.run):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", container):
            raise ValueError("Invalid Metasploit container name")
        self.container, self.port, self.timeout, self.runner = container, port, timeout, runner

    def call(self, method, *params):
        import base64
        import msgpack
        payload = msgpack.packb([method, *params], use_bin_type=True)
        ruby = ("require 'base64'; require 'net/http'; require 'uri'; "
                f"u=URI('http://127.0.0.1:{self.port}/api/'); "
                "r=Net::HTTP::Post.new(u); r['Content-Type']='binary/message-pack'; "
                "r['Accept']='binary/message-pack'; r.body=STDIN.read; "
                f"h=Net::HTTP.new(u.host,u.port,nil); h.open_timeout={self.timeout}; "
                f"h.read_timeout={self.timeout}; x=h.start{{|c|c.request(r)}}; "
                "STDOUT.write(Base64.strict_encode64(x.body))")
        try:
            result = self.runner(["docker", "exec", "-i", self.container, "ruby", "-e", ruby],
                                 input=payload, capture_output=True, timeout=self.timeout + 5, check=False)
            if result.returncode:
                stderr = result.stderr
                if isinstance(stderr, bytes):
                    stderr = stderr.decode("utf-8", errors="replace")
                detail = (stderr or "").strip()[-2000:]
                suffix = f": {detail}" if detail else " (no stderr output)"
                raise RuntimeError(
                    f"Docker Exec RPC command failed with exit code {result.returncode}{suffix}"
                )
            raw = result.stdout.decode("ascii") if isinstance(result.stdout, bytes) else result.stdout
            response = _rpc_normalize(
                msgpack.unpackb(base64.b64decode(raw), raw=False, strict_map_key=False)
            )
        except Exception as exc:
            raise RuntimeError(f"Metasploit Docker Exec RPC failed: {exc}") from exc
        if isinstance(response, dict) and rpc_field(response, "error"):
            error = (rpc_field(response, "error_message") or rpc_field(response, "error_class")
                     or rpc_field(response, "error"))
            raise MetasploitRpcError(rpc_text(error), method=method, response=response)
        return response


def rpc_field(mapping: dict, name: str):
    """Read a MessagePack map field whether its key was decoded as text or bytes."""
    value = mapping.get(name)
    return value if value is not None else mapping.get(name.encode("utf-8"))


def _rpc_normalize(value):
    """Decode UTF-8 MessagePack bytes while preserving non-text binary values."""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value
    if isinstance(value, dict):
        return {_rpc_normalize(key): _rpc_normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_rpc_normalize(item) for item in value]
    return value


def rpc_text(value):
    """Convert protocol text returned as either bytes or str into str."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


class MetasploitRpc:
    ALLOWED = {
        "module.execute", "module.results", "module.compatible_payloads", "job.list", "job.stop",
        "session.list", "session.shell_read", "session.shell_write",
        "console.create", "console.read", "console.destroy",
    }

    def __init__(self, transport, username: str, password: str):
        if not username or not password:
            raise ConfigurationError("MSFRPC_USER and MSFRPC_PASS are required")
        self.transport, self.username, self.password, self.token = transport, username, password, None

    @classmethod
    def from_env(cls):
        container = os.getenv("MSF_CONTAINER_NAME", "vulnforge-metasploit").strip()
        if not container:
            container = "vulnforge-metasploit"
        timeout = int(os.getenv("MSFRPC_TIMEOUT", "60"))
        transport = (DockerExecMessagePackTransport(
                         container, int(os.getenv("MSFRPC_CONTAINER_PORT", "55553")), timeout=timeout
                     )
                     if os.getenv("MSFRPC_TRANSPORT", "docker-exec") == "docker-exec" and container
                     else MessagePackTransport(os.getenv("MSFRPC_HOST", "127.0.0.1"),
                                               int(os.getenv("MSFRPC_PORT", "55553")), timeout=timeout))
        return cls(transport,
                   os.getenv("MSFRPC_USER", ""), os.getenv("MSFRPC_PASS", ""))

    def call(self, method, *args):
        if method not in self.ALLOWED:
            raise PermissionError("RPC method is not exposed")
        if self.token is None:
            auth = self.transport.call("auth.login", self.username, self.password)
            result = rpc_field(auth, "result") if isinstance(auth, dict) else None
            token = rpc_field(auth, "token") if isinstance(auth, dict) else None
            if rpc_text(result) != "success" or not token:
                raise RuntimeError("Metasploit RPC authentication failed")
            self.token = rpc_text(token)
        return self.transport.call(method, self.token, *args)
