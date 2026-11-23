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
by a source from analysis inferred from a quoted source excerpt. For every supported non-empty
claim, fill the matching ResearchResult field and add a ResearchEvidence entry to the evidence list.
Use only the defined ResearchResult fields. Do not add top-level fields such as findings,
research_scope, or sources_used. Each evidence entry must use the matching field name, exact
source label, and an exact quote from that source.
Use basis 'explicit' only when the quote directly states the claim, otherwise use 'analysis'.
If a detail is not supported, leave it null, use 'Unknown', or list it as a limitation. Preserve
conflicts between sources and do not silently choose one version. Do not create a reproduction
plan, select modules, define verification rules, or claim successful exploitation.
Write for readers who may not know vulnerability jargon. Keep vulnerability_summary to one or two
short sentences. Explain the mechanism in a few clear steps, briefly define specialized terms the
first time they appear, and avoid repeating facts across summary, conditions, prerequisites and
limitations. Keep each condition specific and concise."""


class ResearchAgentError(ValueError):
    """Raised when the research call or its structured result is invalid."""


class ResearchAgent:
    def __init__(self, runner: AgentRunner):
        self.runner = runner

    @classmethod
    def from_environment(cls) -> "ResearchAgent":
        return cls(AgentRunner(create_model(Settings.from_environment())))

    def run(self, *, cve_id: str, document_markdown: str,
            target: TargetMaterial | None = None, language: str = "zh") -> ResearchResult:
        if language not in {"zh", "en"}:
            raise ValueError("language must be 'zh' or 'en'.")
        if target is not None and target.identifier.casefold() != cve_id.casefold():
            raise ResearchAgentError("Research target identifier does not match cve_id.")

        input_text = self._build_input(cve_id, document_markdown, target)
        try:
            result = self.runner.run(
                agent_name="Research Agent",
                instructions=(
                    _INSTRUCTIONS
                    + (" Write all claim, summary, mechanism, condition, prerequisite and limitation text in Chinese."
                       " Keep exact source quotes and source labels unchanged."
                       if language == "zh" else
                       " Write all natural-language fields in English. Keep exact source quotes and source labels unchanged.")
                ),
                input_text=input_text,
                result_schema=ResearchResult,
            )
        except Exception as exc:
            raise ResearchAgentError(f"Research Agent model call failed: {exc}") from exc
        if result.cve_id.casefold() != cve_id.casefold():
            raise ResearchAgentError("Research result CVE does not match the requested CVE.")
        return result

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
