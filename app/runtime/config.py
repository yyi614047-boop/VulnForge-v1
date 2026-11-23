"""Explicit environment-backed configuration for one VulnForge run."""
from dataclasses import dataclass
import os


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
