"""Immutable, backend-neutral verification contracts."""
from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FileArtifactExpectation(FrozenModel):
    """A target file pattern frozen before execution."""
    path_pattern: str = Field(min_length=1, max_length=500)
    source: str = Field(min_length=1, max_length=200)

    @field_validator("path_pattern")
    @classmethod
    def validate_path_pattern(cls, value: str) -> str:
        path = PurePosixPath(value)
        if not value.startswith("/") or ".." in path.parts:
            raise ValueError("File artifact pattern must be absolute and cannot traverse parents")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("File artifact pattern cannot contain control characters")
        if any(ch in value for ch in ";|&$`"):
            raise ValueError("File artifact pattern contains unsupported shell characters")
        return value


class EvidenceRequirement(FrozenModel):
    kind: str = Field(min_length=1, max_length=100)
    rule_name: str = Field(min_length=1, max_length=100)
    required: bool = True
    description: str = Field(min_length=1, max_length=500)


class VerificationContract(FrozenModel):
    evidence_requirements: tuple[EvidenceRequirement, ...] = Field(min_length=1, max_length=10)
    acceptance_policy: Literal["any", "all"] = "any"
    result_label: str = Field(min_length=1, max_length=100)
    file_artifacts: tuple[FileArtifactExpectation, ...] = Field(default=(), max_length=10)

    @model_validator(mode="after")
    def validate_requirements(self) -> Self:
        if not any(requirement.required for requirement in self.evidence_requirements):
            raise ValueError("A verification contract requires at least one required evidence rule.")
        names = [requirement.rule_name for requirement in self.evidence_requirements]
        if len(names) != len(set(names)):
            raise ValueError("A verification contract cannot repeat the same evidence rule.")
        return self
