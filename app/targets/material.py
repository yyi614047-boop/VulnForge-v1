"""Source-neutral local material passed from target loaders to agents."""
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LocalSource:
    path: Path
    content: str
    sha256: str


@dataclass(frozen=True)
class TargetMaterial:
    identifier: str
    root: Path
    environment: Path
    document: LocalSource | None
    supporting_sources: tuple[LocalSource, ...]
    attributes: dict
