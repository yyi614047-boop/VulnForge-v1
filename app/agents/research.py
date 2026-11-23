"""Research a vulnerability using only supplied local target material."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.agents.runner import AgentRunner
from app.runtime.config import Settings
from app.runtime.model import create_model
from app.targets.material import TargetMaterial


ResearchField = Literal[
    "vulnerability_type",
    "affected_component",
    "vulnerability_summary",
    "vulnerability_mechanism",
    "trigger_conditions",
    "prerequisites",
    "limitations",
]


class ResearchEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: ResearchField
    claim: str
    source: str
    quote: str
    basis: Literal["explicit", "analysis"]


class ResearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str
    vulnerability_type: Literal["RCE", "SQLi", "File Write", "Unknown"] = "Unknown"
    affected_component: str | None = None
    vulnerability_summary: str | None = None
    vulnerability_mechanism: str | None = None
    trigger_conditions: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    evidence: list[ResearchEvidence] = Field(default_factory=list)


_INSTRUCTIONS = """Research the vulnerability using only the source material in the user message.
Do not use remembered CVE details or infer facts from the CVE identifier alone. Do not search
the web, fetch URLs, call external services, run tools, or probe targets. Separate facts stated
by a source from analysis inferred from a quoted source excerpt. For every non-empty finding,
provide an evidence entry with the exact source label and an exact quote from that source.
Use basis 'explicit' only when the quote directly states the claim, otherwise use 'analysis'.
If a detail is not supported, leave it null, use 'Unknown', or list it as a limitation. Preserve
conflicts between sources and do not silently choose one version. Do not create a reproduction
plan, select modules, define verification rules, or claim successful exploitation."""


class ResearchAgentError(ValueError):
    """Raised when the research call or its structured result is invalid."""


class ResearchAgent:
    def __init__(self, runner: AgentRunner):
        self.runner = runner

    @classmethod
    def from_environment(cls) -> "ResearchAgent":
        return cls(AgentRunner(create_model(Settings.from_environment())))

    def run(self, *, cve_id: str, document_markdown: str,
            target: TargetMaterial | None = None) -> ResearchResult:
        if target is not None and target.identifier.casefold() != cve_id.casefold():
            raise ResearchAgentError("Research target identifier does not match cve_id.")

        source_texts = self._source_texts(document_markdown, target)
        input_text = self._build_input(cve_id, document_markdown, target)
        try:
            result = self.runner.run(
                agent_name="Research Agent",
                instructions=_INSTRUCTIONS,
                input_text=input_text,
                result_schema=ResearchResult,
            )
        except Exception as exc:
            raise ResearchAgentError(f"Research Agent model call failed: {exc}") from exc
        return self._ground_result(result, cve_id, source_texts)

    @staticmethod
    def _source_texts(document_markdown: str,
                      target: TargetMaterial | None) -> dict[str, str]:
        sources = {"Document Agent Markdown": document_markdown} if document_markdown else {}
        if target:
            for source in target.supporting_sources:
                sources[source.path.as_posix()] = source.content
        return sources

    @staticmethod
    def _build_input(cve_id: str, document_markdown: str,
                     target: TargetMaterial | None) -> str:
        sections = [f"CVE identifier supplied by the caller: {cve_id}"]
        if document_markdown.strip():
            sections.append(
                "Document Agent Markdown (source label: Document Agent Markdown):\n"
                + document_markdown
            )
        else:
            sections.append("Document Agent Markdown is missing or empty.")

        if target:
            if target.identifier.casefold() != cve_id.casefold():
                raise ResearchAgentError("Research target identifier does not match cve_id.")
            sections.append("Local target information is included below as supporting evidence.")
            compose = target.attributes.get("compose", {})
            services = compose.get("services", {}) if isinstance(compose, dict) else {}
            if isinstance(services, dict):
                details = []
                for name, service in services.items():
                    if not isinstance(service, dict):
                        continue
                    details.append(f"service: {name}")
                    for key in ("image", "build", "ports", "expose"):
                        if key in service:
                            details.append(f"  {key}: {service[key]}")
                if details:
                    sections.append("Compose service summary:\n" + "\n".join(details))
            for source in target.supporting_sources:
                sections.append(
                    f"Local source (cite with this exact label): {source.path.as_posix()}\n"
                    f"{source.content}"
                )
        else:
            sections.append("No additional local target information was supplied.")
        return "\n\n".join(sections)

    @staticmethod
    def _ground_result(result: ResearchResult, cve_id: str,
                       source_texts: dict[str, str]) -> ResearchResult:
        valid_evidence = []
        for item in result.evidence:
            source = source_texts.get(item.source)
            if source is None or not item.quote or item.quote not in source:
                continue
            if item.basis == "explicit" and item.claim.casefold() not in item.quote.casefold():
                continue
            valid_evidence.append(item)

        supported_claims = {(item.field, item.claim) for item in valid_evidence}
        unsupported_fields = set()

        vulnerability_type = result.vulnerability_type
        if vulnerability_type != "Unknown" and (
            "vulnerability_type", vulnerability_type
        ) not in supported_claims:
            vulnerability_type = "Unknown"
            unsupported_fields.add("vulnerability_type")

        scalar_values = {}
        for field in ("affected_component", "vulnerability_summary", "vulnerability_mechanism"):
            value = getattr(result, field)
            if value and (field, value) not in supported_claims:
                scalar_values[field] = None
                unsupported_fields.add(field)
            else:
                scalar_values[field] = value

        list_values = {}
        for field in ("trigger_conditions", "prerequisites", "limitations"):
            original = getattr(result, field)
            supported = [
                claim for claim in original if (field, claim) in supported_claims
            ]
            if len(supported) != len(original):
                unsupported_fields.add(field)
            list_values[field] = supported

        limitations = list(result.limitations)
        if not source_texts.get("Document Agent Markdown", "").strip():
            limitations.append("Document Agent Markdown was missing or empty.")
        if not any(key != "Document Agent Markdown" for key in source_texts):
            limitations.append("No additional local target information was supplied.")
        for field in sorted(unsupported_fields):
            note = f"Some {field.replace('_', ' ')} claims lacked a matching source quote and were omitted."
            if note not in limitations:
                limitations.append(note)

        return result.model_copy(update={
            "cve_id": cve_id,
            "vulnerability_type": vulnerability_type,
            **scalar_values,
            **list_values,
            "limitations": limitations,
            "evidence": valid_evidence,
        })
