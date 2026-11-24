"""Structured, backend-neutral observations from one execution attempt."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ObservationStage = Literal[
    "module_catalog",
    "runtime_target",
    "configuration",
    "authorization",
    "execution",
    "session",
    "state_change",
    "file_artifact",
    "diagnostics",
]


class ExecutionObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    execution_id: str
    attempt: int
    stage: ObservationStage
    source: str = Field(min_length=1, max_length=120)
    status: Literal["observed", "error"] = "observed"
    summary: str = Field(default="", max_length=500)
    data: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def for_agent(self) -> dict:
        return {
            "stage": self.stage,
            "source": self.source,
            "status": self.status,
            "summary": self.summary,
            "data": self.data,
        }


class ExecutionObservationJournal:
    def __init__(self, *, run_id: str, execution_id: str, attempt: int):
        self.run_id = run_id
        self.execution_id = execution_id
        self.attempt = attempt
        self.items: list[ExecutionObservation] = []

    def add(self, stage: ObservationStage, source: str, *, data: dict | None = None,
            status: Literal["observed", "error"] = "observed", summary: str = "") -> None:
        self.items.append(ExecutionObservation(
            run_id=self.run_id,
            execution_id=self.execution_id,
            attempt=self.attempt,
            stage=stage,
            source=source,
            status=status,
            summary=summary[:500],
            data=data or {},
        ))

    def for_agent(self) -> list[dict]:
        return [item.for_agent() for item in self.items]
