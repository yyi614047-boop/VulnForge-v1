"""Extract lightweight, source-grounded PoC snippets without executing them."""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.targets.material import LocalSource, TargetMaterial


_HTTP_START = re.compile(
    r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/\d(?:\.\d)?(?:\s*)$",
    re.IGNORECASE | re.MULTILINE,
)
_CONSOLE_COMMAND = re.compile(
    r"^(?:use|set|setg|unset|unsetg|show\s+(?:options|payloads|advanced)|check|exploit|run|exit)\b",
    re.IGNORECASE | re.MULTILINE,
)
_POC_COMMAND = re.compile(
    r"^(?:curl|wget|python(?:3)?|java|nc|ncat|bash|sh|powershell|pwsh)\b",
    re.IGNORECASE | re.MULTILINE,
)
_CONSOLE_START = re.compile(r"^\s*use\s+(?:exploit|auxiliary)/", re.IGNORECASE)
_FENCE = re.compile(
    r"(?ms)^[ \t]*(?:```+|~~~+)[^\n]*\n(.*?)^[ \t]*(?:```+|~~~+)[ \t]*$"
)


_PAYLOAD_SETTING = re.compile(
    r"^\s*(?:set|setg)\s+PAYLOAD\s+([a-z0-9_+-]+(?:/[a-z0-9_+-]+)+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_PAYLOAD_NAME = re.compile(r"^[a-z0-9_+-]+(?:/[a-z0-9_+-]+)+$")


@dataclass(frozen=True)
class PocHint:
    kind: str
    content: str
    source: str
    quote: str
    payload_name: str | None = None
    platform: str | None = None
    architecture: str | None = None

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "content": self.content,
            "source": self.source,
            "quote": self.quote,
            "payload_name": self.payload_name,
            "platform": self.platform,
            "architecture": self.architecture,
        }


def _kind(content: str) -> str | None:
    if _HTTP_START.search(content):
        return "http_request"
    if _CONSOLE_COMMAND.search(content):
        return "metasploit_console"
    if _POC_COMMAND.search(content):
        return "poc_command"
    return None


def _clean_block(block: str) -> str:
    lines = block.strip("\n\r").splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines).strip()


def _raw_http_blocks(content: str) -> list[str]:
    blocks = []
    for match in _HTTP_START.finditer(content):
        remainder = content[match.start():]
        lines = remainder.splitlines()
        selected = []
        for line in lines:
            if selected and (not line.strip() or line.strip().startswith("```")):
                break
            selected.append(line)
            if len(selected) >= 40:
                break
        block = _clean_block("\n".join(selected))
        if block:
            blocks.append(block)
    return blocks


def _payload_clue(content: str) -> tuple[str | None, str | None, str | None]:
    explicit = _PAYLOAD_SETTING.search(content)
    if explicit:
        return explicit.group(1).lower(), *_payload_platform(explicit.group(1).lower())
    lowered = content.lower()
    if re.search(r"\b(?:powershell|pwsh|cmd(?:\.exe)?)\b", lowered):
        return None, "windows", None
    if (re.search(r"\b(?:bash|sh|/dev/tcp|ncat|netcat|nc)\b", lowered)
            and not re.search(r"\b(?:powershell|pwsh)\b", lowered)):
        return None, "linux", None
    if re.search(r"\b(?:jsp|webshell)\b", lowered):
        return None, "java", None
    return None, None, None


def _payload_platform(name: str) -> tuple[str | None, str | None]:
    parts = name.split("/")
    platform = None
    architecture = None
    if parts[0] == "cmd" and len(parts) > 1 and parts[1] in {"unix", "linux", "windows"}:
        platform = parts[1]
    elif parts[0] in {"linux", "windows", "unix", "java", "python", "ruby", "php"}:
        platform = parts[0]
    for part in parts:
        if part in {"x64", "x86", "aarch64", "armle", "armbe", "java"}:
            architecture = part
            break
    return platform, architecture


def _raw_command_blocks(content: str, start: re.Pattern[str],
                       continuation: re.Pattern[str] | None = None) -> list[str]:
    blocks = []
    lines = content.splitlines()
    index = 0
    while index < len(lines):
        if not start.match(lines[index]):
            index += 1
            continue
        selected = []
        while index < len(lines) and (continuation or start).match(lines[index]):
            selected.append(lines[index])
            index += 1
        block = _clean_block("\n".join(selected))
        if block:
            blocks.append(block)
    return blocks


def extract_poc_hints(target: TargetMaterial, *, max_hints: int = 16,
                      max_chars: int = 4000) -> tuple[PocHint, ...]:
    """Return exact snippets from local Markdown; no commands are interpreted or run."""
    sources: list[LocalSource] = []
    if target.document is not None:
        sources.append(target.document)
    sources.extend(target.supporting_sources)

    hints: list[PocHint] = []
    seen: set[str] = set()
    for source in sources:
        if source.path.suffix.lower() not in {".md", ".markdown"}:
            continue
        blocks = [_clean_block(match.group(1)) for match in _FENCE.finditer(source.content)]
        blocks.extend(_raw_http_blocks(source.content))
        blocks.extend(_raw_command_blocks(source.content, _CONSOLE_START, _CONSOLE_COMMAND))
        blocks.extend(_raw_command_blocks(source.content, _POC_COMMAND))
        for block in blocks:
            kind = _kind(block)
            if kind is None or block in seen:
                continue
            seen.add(block)
            quote = block[:max_chars]
            hints.append(PocHint(
                kind=kind,
                content=quote,
                source=source.path.as_posix(),
                quote=quote,
            ))
            payload_name, platform, architecture = _payload_clue(block)
            if payload_name or platform:
                hints.append(PocHint(
                    kind="payload",
                    content=quote,
                    source=source.path.as_posix(),
                    quote=quote,
                    payload_name=payload_name,
                    platform=platform,
                    architecture=architecture,
                ))
            if len(hints) >= max_hints:
                return tuple(hints)
    return tuple(hints)
