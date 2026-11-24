"""Read-only Metasploit module search and metadata parsing."""
from __future__ import annotations

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


class ModuleMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    module_name: str
    module_type: Literal["exploit", "auxiliary"]
    name: str = ""
    description: str = ""
    platforms: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    session_capable: bool = False
    options: list[ModuleOption] = Field(default_factory=list)
    raw_output: str = ""


class MetasploitSearch:
    """Read-only msfconsole CVE search and module inspection, compatible with v0."""
    MODULE_RE = re.compile(r"(?:exploit|auxiliary)/[A-Za-z0-9_./-]+")
    CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

    def __init__(self, *, container: str | None = None, executable: str = "msfconsole",
                 runner: Callable = subprocess.run, timeout: int = 180):
        self.container, self.executable, self.runner, self.timeout = container, executable, runner, timeout

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
        options = []
        in_options = False
        for line in raw.splitlines():
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
        return ModuleMetadata(module_name=module_name, module_type=module_name.split("/", 1)[0],
                              name=field("Name"), description=raw[-12000:], references=refs,
                              raw_output=raw, options=options,
                              session_capable=(any(o.name == "PAYLOAD" for o in options)
                                               or bool(re.search(r"^\s*Payload information\s*:", raw, re.I | re.M))))
