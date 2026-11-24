"""Explicit environment-backed configuration for one VulnForge run."""
from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import uuid


class ConfigurationError(ValueError):
    """Raised when required runtime configuration is absent or invalid."""


@dataclass(frozen=True)
class Settings:
    model_name: str | None
    model_base_url: str | None
    model_api_key: str | None

    @classmethod
    def from_environment(cls) -> "Settings":
        return cls(
            model_name=os.environ.get("VULNFORGE_MODEL"),
            model_base_url=os.environ.get("VULNFORGE_MODEL_BASE_URL"),
            model_api_key=os.environ.get("VULNFORGE_MODEL_API_KEY") or os.environ.get("OPENAI_API_KEY"),
        )


@dataclass(frozen=True)
class RunContext:
    root: Path
    run_id: str

    @classmethod
    def create(cls, cve_id: str) -> "RunContext":
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        run_id = f"{stamp}_{cve_id.upper()}_{uuid.uuid4().hex[:8]}"
        root = Path(os.getenv("VULNFORGE_RUNS_ROOT", "runs")).expanduser().resolve()
        context = cls(root=root, run_id=run_id)
        context.run_dir.mkdir(parents=True, exist_ok=False)
        return context

    @property
    def run_dir(self) -> Path:
        return self.root / self.run_id

    @property
    def evidence_dir(self) -> Path:
        return self.run_dir / "evidence"

    @property
    def targets_dir(self) -> Path:
        return self.run_dir / "targets"
