"""Vulhub source configuration, separate from shared model settings."""
import os
from dataclasses import dataclass
from pathlib import Path

from app.runtime.config import ConfigurationError


@dataclass(frozen=True)
class VulhubSettings:
    root: Path

    @classmethod
    def from_environment(cls) -> "VulhubSettings":
        root_value = os.environ.get("VULNFORGE_VULHUB_ROOT")
        if not root_value:
            raise ConfigurationError("Set VULNFORGE_VULHUB_ROOT to a local Vulhub checkout.")
        root = Path(root_value).expanduser().resolve()
        if not root.is_dir():
            raise ConfigurationError(f"Vulhub root is not a directory: {root}")
        return cls(root=root)
