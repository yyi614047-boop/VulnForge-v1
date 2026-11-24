"""Immutable, backend-neutral verification contracts."""
import json
from pathlib import PurePosixPath
import re
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


StateValue = str | bool | int | float


class StateChangeExpectation(FrozenModel):
    """A concrete state transition frozen before execution."""
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    indicator: str = Field(min_length=1, max_length=100)
    before: StateValue
    after: StateValue
    source: str = Field(min_length=1, max_length=200)

    @field_validator("indicator")
    @classmethod
    def validate_indicator(cls, value: str) -> str:
        if not value.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("State indicator must be non-empty and contain no control characters")
        return value

    @field_validator("before", "after")
    @classmethod
    def validate_value(cls, value: StateValue) -> StateValue:
        if isinstance(value, str):
            if not value.strip() or len(value) > 200 or any(
                    ord(ch) < 32 or ord(ch) == 127 for ch in value):
                raise ValueError("State values must be non-empty bounded scalars")
        elif isinstance(value, float) and (value != value or value in {float("inf"), float("-inf")}):
            raise ValueError("State values must be finite")
        return value

    @model_validator(mode="after")
    def validate_transition(self) -> Self:
        before = json.dumps(self.before, ensure_ascii=False, sort_keys=True)
        after = json.dumps(self.after, ensure_ascii=False, sort_keys=True)
        if before == after:
            raise ValueError("A state-change expectation must describe different before and after values")
        return self


class HttpExpectation(FrozenModel):
    """A source-grounded request and exact response match frozen before execution."""

    scheme: Literal["http", "https"] = "http"
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET"
    path: str = Field(min_length=1, max_length=2048)
    headers: tuple[tuple[str, str], ...] = Field(default=(), max_length=20)
    body: str = Field(default="", max_length=8192)
    expected_status: int = Field(ge=100, le=599)
    body_contains: str | None = Field(default=None, min_length=1, max_length=500)
    header_name: str | None = Field(default=None, min_length=1, max_length=100)
    header_contains: str | None = Field(default=None, min_length=1, max_length=500)
    source: str = Field(min_length=1, max_length=200)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not re.fullmatch(r"^/(?!/)[^\s\x00-\x1f\x7f]{0,2047}$", value):
            raise ValueError("HTTP path must be a bounded origin-form path")
        return value

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, value: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
        seen = set()
        for name, header_value in value:
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                raise ValueError("HTTP header name is invalid")
            if name.casefold() in {"host", "content-length", "connection"}:
                raise ValueError("HTTP collector owns host, content-length and connection headers")
            if name.casefold() in seen or any(ord(ch) < 32 or ord(ch) == 127 for ch in header_value):
                raise ValueError("HTTP headers must be unique and contain no control characters")
            seen.add(name.casefold())
        return value

    @field_validator("body")
    @classmethod
    def validate_body(cls, value: str) -> str:
        if any(ord(ch) < 32 and ch not in "\t\r\n" for ch in value):
            raise ValueError("HTTP request body contains unsupported control characters")
        return value

    @model_validator(mode="after")
    def validate_match(self) -> Self:
        if self.body_contains is None and self.header_contains is None:
            raise ValueError("HTTP verification requires an exact body or header match")
        if (self.header_name is None) != (self.header_contains is None):
            raise ValueError("Header matching requires both header_name and header_contains")
        return self


class DatabaseResultExpectation(FrozenModel):
    """An exact database result carried by an independently probed HTTP response."""

    probe: HttpExpectation
    result_contains: str = Field(min_length=1, max_length=500)
    source: str = Field(min_length=1, max_length=200)


class OobExpectation(FrozenModel):
    """A random callback token and exact collector path frozen before execution."""

    token: str = Field(pattern=r"^[A-Za-z0-9_-]{16,64}$")
    path: str = Field(pattern=r"^/oob/[A-Za-z0-9_-]{16,64}$")
    source: str = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def validate_token_path(self) -> Self:
        if self.path != f"/oob/{self.token}":
            raise ValueError("OOB path must contain the exact callback token")
        return self


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
    state_changes: tuple[StateChangeExpectation, ...] = Field(default=(), max_length=10)
    http_expectations: tuple[HttpExpectation, ...] = Field(default=(), max_length=10)
    oob_expectations: tuple[OobExpectation, ...] = Field(default=(), max_length=10)
    database_results: tuple[DatabaseResultExpectation, ...] = Field(default=(), max_length=10)

    @model_validator(mode="after")
    def validate_requirements(self) -> Self:
        if not any(requirement.required for requirement in self.evidence_requirements):
            raise ValueError("A verification contract requires at least one required evidence rule.")
        names = [requirement.rule_name for requirement in self.evidence_requirements]
        if len(names) != len(set(names)):
            raise ValueError("A verification contract cannot repeat the same evidence rule.")
        if (any(requirement.rule_name == "state_change_observed"
                and requirement.kind == "state_change"
                for requirement in self.evidence_requirements)
                and not self.state_changes):
            raise ValueError("State-change verification requires a frozen state transition expectation.")
        if (any(requirement.rule_name == "http_response_observed"
                for requirement in self.evidence_requirements)
                and not self.http_expectations):
            raise ValueError("HTTP response verification requires a frozen request and response expectation.")
        if (any(requirement.rule_name == "oob_callback_observed"
                for requirement in self.evidence_requirements)
                and not self.oob_expectations):
            raise ValueError("OOB callback verification requires a frozen token and path expectation.")
        if (any(requirement.rule_name == "database_result_observed"
                for requirement in self.evidence_requirements)
                and not self.database_results):
            raise ValueError("Database result verification requires a frozen probe and exact result.")
        return self
