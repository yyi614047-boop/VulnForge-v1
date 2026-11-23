"""Load local Vulhub files as source-neutral target material."""
from hashlib import sha256
from pathlib import Path
import re

import yaml

from app.targets.material import LocalSource, TargetMaterial


_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class TargetError(ValueError):
    """Raised when a local target cannot be resolved safely."""


def resolve_cve(root: Path, cve: str) -> Path:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise TargetError("Vulhub root must be a directory.")
    if not _CVE_PATTERN.fullmatch(cve):
        raise TargetError("Expected a CVE identifier such as CVE-2017-5638.")

    normalized_cve = cve.upper()
    matches = []
    for compose_file in root.glob("*/*/docker-compose.yml"):
        environment = compose_file.parent
        resolved_environment = environment.resolve(strict=True)
        if not resolved_environment.is_relative_to(root):
            continue
        if resolved_environment.name.upper() != normalized_cve:
            continue
        if compose_file.is_symlink() or not compose_file.is_file():
            continue
        matches.append(resolved_environment)

    if not matches:
        raise TargetError(f"No local Vulhub environment found for {normalized_cve}.")
    if len(matches) != 1:
        raise TargetError(f"More than one local Vulhub environment matches {normalized_cve}.")
    return matches[0]


def load_target(root: Path, cve: str, *, max_document_chars: int = 32_000) -> TargetMaterial:
    root = root.resolve(strict=True)
    environment = resolve_cve(root, cve)
    compose_path = environment / "docker-compose.yml"
    compose_text = _read_in_root(compose_path, root)
    try:
        compose = yaml.safe_load(compose_text)
    except yaml.YAMLError as exc:
        raise TargetError(f"Invalid docker-compose.yml: {exc}") from exc
    if not isinstance(compose, dict) or not isinstance(compose.get("services"), dict):
        raise TargetError("Compose file must define a services mapping.")

    markdown_files = sorted(
        (path for path in environment.glob("*.md") if path.is_file() and not path.is_symlink()),
        key=lambda path: path.name.casefold(),
    )
    readme_path = next(
        (path for path in markdown_files if path.name.casefold() == "readme.md"), None
    )
    document = None
    document_truncated = False
    if readme_path:
        document_path = readme_path
        document_text = _read_in_root(document_path, root)
        document_truncated = len(document_text) > max_document_chars
        document = LocalSource(
            path=document_path,
            content=document_text[:max_document_chars],
            sha256=sha256(document_text.encode("utf-8")).hexdigest(),
        )
    compose_source = LocalSource(
        path=compose_path,
        content=compose_text,
        sha256=sha256(compose_text.encode("utf-8")).hexdigest(),
    )
    supporting_sources = [compose_source]
    for source_path in markdown_files:
        if source_path == readme_path:
            continue
        source_text = _read_in_root(source_path, root)
        supporting_sources.append(LocalSource(
            path=source_path,
            content=source_text[:max_document_chars],
            sha256=sha256(source_text.encode("utf-8")).hexdigest(),
        ))
    return TargetMaterial(
        identifier=cve.upper(),
        root=root,
        environment=environment,
        document=document,
        supporting_sources=tuple(supporting_sources),
        attributes={"compose": compose, "document_truncated": document_truncated},
    )


def _read_in_root(path: Path, root: Path) -> str:
    if path.is_symlink():
        raise TargetError(f"Target input must not be a symbolic link: {path.name}")
    resolved_path = path.resolve(strict=True)
    if not resolved_path.is_relative_to(root.resolve()):
        raise TargetError("Target input resolves outside the configured Vulhub root.")
    if not resolved_path.is_file():
        raise TargetError(f"Target input is not a regular file: {path.name}")
    try:
        return resolved_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise TargetError(f"Target input is not UTF-8 text: {path.name}") from exc
