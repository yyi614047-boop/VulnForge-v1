"""Read-only Metasploit module search and metadata parsing."""
from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field


class ModuleOption(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    required: bool = False
    current_value: str | None = None
    description: str = ""


class ModuleDelivery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact: Literal["jar", "war", "executable", "raw", "unknown"] = "unknown"
    required_entry_class: str | None = Field(default=None, max_length=200)
    trigger: Literal["http_request", "unknown"] = "unknown"
    callback_options: list[str] = Field(default_factory=list)


class PayloadMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    artifact: Literal["jar", "jsp", "command", "executable", "raw", "unknown"] = "unknown"
    entry_class: str | None = Field(default=None, max_length=200)
    session_type: str | None = Field(default=None, max_length=100)
    transport: str | None = Field(default=None, max_length=50)
    staged: bool | None = None


class ModuleMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    module_name: str
    module_type: Literal["exploit", "auxiliary"]
    name: str = ""
    description: str = ""
    platforms: list[str] = Field(default_factory=list)
    architectures: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    target_ids: list[int] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    session_capable: bool = False
    delivery: ModuleDelivery = Field(default_factory=ModuleDelivery)
    options: list[ModuleOption] = Field(default_factory=list)
    raw_output: str = ""


def parse_module_delivery(source: str) -> ModuleDelivery:
    if not source.strip():
        return ModuleDelivery()
    artifact = "unknown"
    for marker, value in (
        ("payload.encoded_jar", "jar"),
        ("payload.encoded_war", "war"),
        ("payload.encoded_exe", "executable"),
        ("payload.encoded", "raw"),
    ):
        if marker in source:
            artifact = value
            break
    entry = re.search(r"loadClass\(\s*[\"']([^\"']+)[\"']", source)
    http_server = "Msf::Exploit::Remote::HttpServer" in source
    trigger = "http_request" if http_server or "send_request" in source else "unknown"
    callback_options = ["SRVHOST"] if any(
        marker in source for marker in ("Msf::Exploit::Remote::HttpServer", "Msf::Exploit::Remote::SocketServer")
    ) else []
    return ModuleDelivery(artifact=artifact, required_entry_class=entry.group(1) if entry else None,
                          trigger=trigger, callback_options=callback_options)


def parse_payload_metadata(name: str, source: str, mixins: dict[str, str] | None = None) -> PayloadMetadata:
    if not name or not source.strip():
        return PayloadMetadata(name=name)
    combined = source + "\n" + "\n".join((mixins or {}).values())
    if "Msf::Payload::JSP" in combined:
        artifact = "jsp"
    elif "Msf::Payload::Java" in combined:
        artifact = "jar"
    elif name.startswith("cmd/"):
        artifact = "command"
    elif name.startswith(("linux/", "windows/", "osx/", "bsd/", "solaris/")):
        artifact = "executable"
    else:
        artifact = "raw"
    stageless = re.search(r"STAGELESS_MAIN_CLASS\s*=\s*[\"']([^\"']+)[\"']", combined)
    main_class = re.search(r"main_class\s*:\s*[\"']([^\"']+)[\"']", combined)
    entry = stageless or main_class
    if artifact == "jar" and entry is None:
        entry_class = "metasploit.Payload"
    else:
        entry_class = entry.group(1) if entry else None
    session = re.search(r"[\"']Session[\"']\s*=>\s*(?:Msf::Sessions::)?([A-Za-z0-9_:]+)", source)
    transport = None
    for candidate in ("reverse_tcp", "reverse_http", "reverse_https", "bind_tcp"):
        if candidate in name:
            transport = candidate
            break
    if transport is None:
        handler = re.search(r"Msf::Handler::([A-Za-z0-9_:]+)", source)
        if handler:
            transport = re.sub(r"(?<!^)(?=[A-Z])", "_", handler.group(1)).lower()
    staged = False if "stageless" in combined else None
    return PayloadMetadata(name=name, artifact=artifact, entry_class=entry_class,
                           session_type=session.group(1) if session else None,
                           transport=transport, staged=staged)


class MetasploitSearch:
    """Read-only msfconsole CVE search and module inspection, compatible with v0."""
    MODULE_RE = re.compile(r"(?:exploit|auxiliary)/[A-Za-z0-9_./-]+")
    CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

    def __init__(self, *, container: str | None = None, executable: str = "msfconsole",
                 runner: Callable = subprocess.run, timeout: int = 180):
        self.container, self.executable, self.runner, self.timeout = container, executable, runner, timeout
        self._payload_cache: dict[str, PayloadMetadata] = {}

    @classmethod
    def from_env(cls):
        container = os.getenv("MSF_CONTAINER_NAME", "vulnforge-metasploit").strip()
        return cls(container=container or "vulnforge-metasploit")

    def _console(self, command: str) -> str:
        argv = (["docker", "exec", self.container,
                 "/usr/src/metasploit-framework/msfconsole", "-q", "-x", command]
                if self.container else [self.executable, "-q", "-x", command])
        result = self.runner(argv, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=self.timeout, shell=False)
        output = ((result.stdout or "") + "\n" + (result.stderr or ""))[-32000:]
        if result.returncode:
            raise RuntimeError(f"Metasploit search failed ({result.returncode}): {output[-2000:]}")
        return output

    def _read_sources(self, requests: list[tuple[str, str]]) -> dict[str, dict]:
        if not self.container or not requests:
            return {}
        script = r'''
import json, os, re, sys
root = sys.argv[1]
requests = json.load(sys.stdin)
result = {}
for kind, name in requests:
    if kind == 'module':
        category, remainder = name.split('/', 1)
        directory = {'exploit': 'exploits', 'auxiliary': 'auxiliaries'}[category]
        candidates = [f'{root}/modules/{directory}/{remainder}.rb']
    else:
        candidates = [f'{root}/modules/payloads/singles/{name}.rb',
                      f'{root}/modules/payloads/stages/{name}.rb',
                      f'{root}/modules/payloads/{name}.rb']
    path = next((item for item in candidates if os.path.isfile(item)), None)
    if not path:
        continue
    with open(path, encoding='utf-8', errors='replace') as handle:
        source = handle.read(200000)
    mixins = {}
    for mixin in set(re.findall(r'include\s+(Msf::Payload::[A-Za-z0-9_:]+)', source)):
        parts = mixin.removeprefix('Msf::Payload::').split('::')
        relative = 'payload/' + '/'.join([parts[0].lower()] + [
            re.sub(r'(?<!^)(?=[A-Z])', '_', part).lower() for part in parts[1:]
        ])
        mixin_path = f'{root}/lib/msf/core/{relative}.rb'
        if os.path.isfile(mixin_path):
            with open(mixin_path, encoding='utf-8', errors='replace') as handle:
                mixins[relative] = handle.read(200000)
    result[name] = {'source': source, 'mixins': mixins}
print(json.dumps(result))
'''
        argv = ["docker", "exec", "-i", self.container, "python3", "-c", script,
                "/usr/src/metasploit-framework"]
        result = self.runner(argv, input=json.dumps(requests), capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=self.timeout, shell=False)
        if result.returncode:
            raise RuntimeError(f"Metasploit source inspection failed ({result.returncode}): {result.stderr[-1000:]}")
        return json.loads(result.stdout or "{}")

    def inspect_payloads(self, names: list[str]) -> dict[str, PayloadMetadata]:
        pattern = re.compile(r"^[a-z0-9_+-]+(?:/[a-z0-9_+-]+)+$")
        if any(not pattern.fullmatch(name) or ".." in name.split("/") for name in names):
            raise ValueError("Invalid Metasploit payload name")
        missing = list(dict.fromkeys(name for name in names if name not in self._payload_cache))
        if missing:
            sources = self._read_sources([("payload", name) for name in missing[:200]])
            for name in missing[:200]:
                item = sources.get(name, {})
                self._payload_cache[name] = parse_payload_metadata(
                    name, item.get("source", ""), item.get("mixins", {}),
                )
        return {name: self._payload_cache[name] for name in names}

    def search(self, cve_id: str) -> list[str]:
        if not self.CVE_RE.fullmatch(cve_id):
            raise ValueError("Invalid CVE identifier")
        found = self.MODULE_RE.findall(self._console(f"search cve:{cve_id.upper()}; exit"))
        return list(dict.fromkeys(x for x in found if all(p not in {"", ".", ".."} for p in x.split("/"))))

    def inspect(self, cve_id: str, module_name: str) -> ModuleMetadata:
        if not self.MODULE_RE.fullmatch(module_name) or ".." in module_name.split("/"):
            raise ValueError("Invalid Metasploit module name")
        raw = self._console(f"info {module_name}; exit")

        def field(label):
            m = re.search(rf"^\s*{label}\s*:\s*(.+)$", raw, re.I | re.M)
            return m.group(1).strip() if m else ""

        refs = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d{4,}", raw, re.I)))
        platforms = [item.strip() for item in field("Platform").split(",") if item.strip()]
        architectures = [item.strip() for item in field("Arch").split(",") if item.strip()]
        options = []
        targets = []
        target_ids = []
        in_options = False
        in_targets = False
        for line in raw.splitlines():
            if re.match(r"\s*Available targets\s*:", line, re.I):
                in_targets = True
                continue
            if in_targets and re.match(r"\s*(Check supported|Payload information|Description|References)\s*:", line, re.I):
                in_targets = False
            if in_targets:
                target = re.match(r"^\s*(?:=>\s*)?(\d+)\s+(.+?)\s*$", line)
                if target:
                    targets.append(target.group(2).strip())
                    target_ids.append(int(target.group(1)))
            if re.match(r"\s*(Basic|Advanced) Options\s*:?", line, re.I):
                in_options = True
                continue
            if in_options and re.match(r"\s*(Description|References|Targets|Payload information)\s*:?", line, re.I):
                in_options = False
            if in_options:
                m = re.match(r"^\s*([A-Z][A-Z0-9_]*)\s+(.*?)\s+(yes|no)\s{2,}(.+)$", line, re.I)
                if m:
                    options.append(ModuleOption(name=m.group(1), current_value=m.group(2).strip() or None,
                                                required=m.group(3).lower() == "yes", description=m.group(4).strip()))
        delivery = ModuleDelivery()
        try:
            source = self._read_sources([("module", module_name)]).get(module_name, {}).get("source", "")
            delivery = parse_module_delivery(source)
        except Exception:
            pass
        return ModuleMetadata(module_name=module_name, module_type=module_name.split("/", 1)[0],
                              name=field("Name"), description=raw[-12000:], references=refs,
                              platforms=platforms, architectures=architectures,
                              targets=targets, target_ids=target_ids, raw_output=raw, options=options,
                              delivery=delivery,
                              session_capable=(any(o.name == "PAYLOAD" for o in options)
                                               or bool(re.search(r"^\s*Payload information\s*:", raw, re.I | re.M))))
