"""Shared, data-only state for one LangGraph pipeline run."""
from typing import Any, NotRequired, TypedDict


class PipelineState(TypedDict):
    run_id: str
    cve_id: str
    target: NotRequired[Any]
    runtime_target: NotRequired[dict]
    document_markdown: NotRequired[str]
    research_result: NotRequired[Any]
    reproduction_plan: NotRequired[Any]
    verification_policy: NotRequired[Any]
    execution_result: NotRequired[Any]
    evidence: NotRequired[Any]
    verification_result: NotRequired[Any]
    failed_stage: NotRequired[str]
    errors: NotRequired[list[str]]
    status: NotRequired[str]
