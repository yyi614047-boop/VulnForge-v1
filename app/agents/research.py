"""Research a vulnerability using only supplied local target material."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.agents.runner import AgentRunner
from app.targets.material import TargetMaterial
from app.verification.contracts import DatabaseResultExpectation, HttpExpectation, StateChangeExpectation, StateValue
from app.verification.registry import EVIDENCE_RULES, VULNERABILITY_TYPES


VulnerabilityType = Literal[
    "RCE", "SQLi", "File Read", "File Write", "SSRF", "Auth Bypass", "Unknown",
]

_CANONICAL_VULNERABILITY_TYPES = {
    value.casefold(): value for value in VulnerabilityType.__args__
}

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


class ResearchHttpProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scheme: Literal["http", "https"] = "http"
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET"
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    expected_status: int
    body_contains: str | None = None
    header_name: str | None = None
    header_contains: str | None = None


class ResearchDatabaseProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    http_probe: ResearchHttpProbe
    result_contains: str


class ResearchObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    effect: str
    evidence_kind: str
    artifact_path: str | None = None
    state_indicator: str | None = None
    state_before: StateValue | None = None
    state_after: StateValue | None = None
    http_probe: ResearchHttpProbe | None = None
    database_probe: ResearchDatabaseProbe | None = None
    summary: str
    source: str
    quote: str
    basis: Literal["explicit", "analysis"]


class ResearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str
    vulnerability_type: VulnerabilityType = "Unknown"
    affected_component: str | None = None
    vulnerability_summary: str | None = None
    vulnerability_mechanism: str | None = None
    trigger_conditions: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    evidence: list[ResearchEvidence] = Field(default_factory=list)
    observations: list[ResearchObservation] = Field(default_factory=list)

    @field_validator("vulnerability_type", mode="before")
    @classmethod
    def normalize_vulnerability_type(cls, value):
        if isinstance(value, str):
            stripped = value.strip()
            return _CANONICAL_VULNERABILITY_TYPES.get(stripped.casefold(), stripped)
        return value


_EVIDENCE_KINDS = ", ".join(sorted(EVIDENCE_RULES.kinds))
_EVIDENCE_KINDS_BY_TYPE = "\n".join(
    f"- {name}: {', '.join(sorted(VULNERABILITY_TYPES.allowed_evidence_kinds(name)))}"
    for name in VulnerabilityType.__args__ if name != "Unknown"
)

_INSTRUCTIONS = f"""Research the vulnerability using only the source material in the user message.
Do not use remembered CVE details or infer facts from the CVE identifier alone. Do not search
the web, fetch URLs, call external services, run tools, or probe targets. Separate facts stated
by a source from analysis inferred from a quoted source excerpt. For every supported non-empty
claim, fill the matching ResearchResult field and add a ResearchEvidence entry to the evidence list.
Use only the defined ResearchResult fields. Do not add top-level fields such as findings,
research_scope, or sources_used. vulnerability_type must be exactly one of: RCE, SQLi, File Read,
File Write, SSRF, Auth Bypass, Unknown. It is a canonical machine-readable category: do not
translate, expand, or describe it in natural language. Put descriptive wording in the other
fields. Each evidence entry must use the matching field name, exact source label, and an exact
quote from that source.
Extract observable effects into observations: state what would be observed if the vulnerability
were present, the evidence channel used to observe it, and a short summary. evidence_kind must be
one of: {_EVIDENCE_KINDS}, and must be allowed for the selected vulnerability_type:
{_EVIDENCE_KINDS_BY_TYPE}
The evidence kind 'session' means an interactive Metasploit shell session, never a web login session.
The evidence kind 'command_output' means output from a command executed on the target, never output
from an offline cracking or signing tool. For Auth Bypass, use 'state_change' for a documented
transition from unauthenticated or unauthorized to authenticated or authorized; a login page or
Set-Cookie header alone is not proof of bypass. For every 'state_change' observation, also set
state_indicator, state_before and state_after to the concrete documented transition using short
scalar values; leave them null when the material does not support the transition. An observation is
an expected effect, not proof that this target has already been exploited. Every observation must
use an exact source label and exact quote from that source. For an uploaded, created, replaced or
written file, use evidence_kind 'file_artifact' and set artifact_path to the exact absolute filesystem
path inside the target container stated in the quote; otherwise leave it null. A URL route such as
/admin/shell.jsp is not a filesystem path unless the source explicitly identifies it as one.
For an 'http_response' observation, set http_probe only when the quote contains a concrete request
path and an exact expected status plus body or header match. Preserve encoded path segments exactly.
Use body_contains for literal response-body evidence, or header_name plus header_contains for literal
response-header evidence. Never invent a probe from the CVE identifier or general vulnerability knowledge.
For a 'database_result' observation, set database_probe only when the quote contains a concrete
HTTP request and an exact database-derived value returned in the response. database_probe must
contain http_probe plus result_contains; both the request path and result value must be grounded
in the exact quote. Do not treat a generic error, login page or timing change as a database result.
Never infer or invent artifact_path. Use basis 'explicit' only when the quote
directly states the observation, otherwise use 'analysis'. Do not create a reproduction plan, select Metasploit modules or payloads, define
acceptance policy or verification rules, or claim successful exploitation.
If a detail is not supported, leave it null, use 'Unknown', or list it as a limitation. Preserve
conflicts between sources and do not silently choose one version.
Write for readers who may not know vulnerability jargon. Keep vulnerability_summary to one or two
short sentences. Explain the mechanism in a few clear steps, briefly define specialized terms the
first time they appear, and avoid repeating facts across summary, conditions, prerequisites and
limitations. Keep each condition specific and concise."""


class ResearchAgentError(ValueError):
    """Raised when the research call or its structured result is invalid."""


class ResearchAgent:
    def __init__(self, runner: AgentRunner):
        self.runner = runner

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
        return self._validate_grounding(
            result, self._source_texts(document_markdown, target), language
        )

    @staticmethod
    def _source_texts(document_markdown: str,
                      target: TargetMaterial | None) -> dict[str, str]:
        sources = {}
        if document_markdown.strip():
            sources["Document Agent Markdown"] = document_markdown
        if target is not None:
            if target.document is not None:
                sources[target.document.path.as_posix()] = target.document.content
            for source in target.supporting_sources:
                sources[source.path.as_posix()] = source.content
        return sources

    @staticmethod
    def _validate_grounding(result: ResearchResult, sources: dict[str, str],
                            language: str) -> ResearchResult:
        def grounded(source: str, quote: str) -> bool:
            return bool(source and quote.strip() and source in sources and quote in sources[source])

        valid_evidence = []
        invalid_fields = set()
        for item in result.evidence:
            if grounded(item.source, item.quote):
                valid_evidence.append(item)
            else:
                invalid_fields.add(item.field)

        valid_observations = []
        invalid_observations = 0
        invalid_kinds = 0
        invalid_type_kinds = 0
        invalid_state_expectations = 0
        invalid_artifact_paths = 0
        invalid_http_probes = 0
        invalid_database_probes = 0
        definition = VULNERABILITY_TYPES.get(result.vulnerability_type)
        allowed_kinds = definition.allowed_evidence_kinds if definition else frozenset()
        for observation in result.observations:
            if observation.evidence_kind not in EVIDENCE_RULES.kinds:
                invalid_kinds += 1
            elif observation.evidence_kind not in allowed_kinds:
                invalid_type_kinds += 1
            elif grounded(observation.source, observation.quote):
                if observation.evidence_kind == "state_change":
                    try:
                        StateChangeExpectation(
                            indicator=observation.state_indicator,
                            before=observation.state_before,
                            after=observation.state_after,
                            source=observation.source,
                        )
                    except ValidationError:
                        invalid_state_expectations += 1
                        continue
                if observation.evidence_kind == "database_result" and observation.database_probe is not None:
                    database = observation.database_probe
                    probe_data = database.http_probe.model_dump()
                    probe_data["headers"] = tuple(database.http_probe.headers.items())
                    if probe_data.get("body_contains") is None and probe_data.get("header_contains") is None:
                        probe_data["body_contains"] = database.result_contains
                    try:
                        expectation = HttpExpectation(**probe_data, source=observation.source)
                        DatabaseResultExpectation(
                            probe=expectation, result_contains=database.result_contains,
                            source=observation.source,
                        )
                        match_text = expectation.body_contains or expectation.header_contains or ""
                        probe_grounded = (
                            expectation.path in observation.quote
                            and str(expectation.expected_status) in observation.quote
                            and match_text in observation.quote
                            and database.result_contains in observation.quote
                            and (not expectation.body or expectation.body in observation.quote)
                        )
                        if not probe_grounded:
                            raise ValueError("Database probe is not fully grounded in the exact quote")
                    except (ValidationError, ValueError):
                        valid_observations.append(observation.model_copy(update={"database_probe": None}))
                        invalid_database_probes += 1
                        continue
                if observation.evidence_kind == "http_response" and observation.http_probe is not None:
                    probe = observation.http_probe
                    try:
                        probe_data = probe.model_dump()
                        probe_data["headers"] = tuple(probe.headers.items())
                        expectation = HttpExpectation(
                            **probe_data, source=observation.source,
                        )
                        match_text = expectation.body_contains or expectation.header_contains or ""
                        probe_grounded = (
                            expectation.path in observation.quote
                            and str(expectation.expected_status) in observation.quote
                            and match_text in observation.quote
                            and (not expectation.body or expectation.body in observation.quote)
                        )
                        if not probe_grounded:
                            raise ValueError("HTTP probe is not fully grounded in the exact quote")
                    except (ValidationError, ValueError):
                        valid_observations.append(observation.model_copy(update={"http_probe": None}))
                        invalid_http_probes += 1
                        continue
                if observation.artifact_path and observation.artifact_path not in observation.quote:
                    valid_observations.append(observation.model_copy(update={"artifact_path": None}))
                    invalid_artifact_paths += 1
                else:
                    valid_observations.append(observation)
            else:
                invalid_observations += 1

        valid_fields = {item.field for item in valid_evidence}
        updates = {"evidence": valid_evidence, "observations": valid_observations}
        for field in invalid_fields - valid_fields:
            if field in {"affected_component", "vulnerability_summary", "vulnerability_mechanism"}:
                updates[field] = None
            elif field in {"trigger_conditions", "prerequisites"}:
                updates[field] = []

        limitations = list(result.limitations)
        unsupported_fields = invalid_fields - valid_fields
        if unsupported_fields:
            fields = ", ".join(sorted(field.replace("_", " ") for field in unsupported_fields))
            limitations.append(
                f"Removed evidence without an exact source/quote match for: {fields}."
                if language == "en" else
                f"已移除缺乏精确 source/quote 匹配的证据字段：{fields}。"
            )
        if invalid_observations:
            limitations.append(
                f"Removed {invalid_observations} observation(s) without an exact source/quote match."
                if language == "en" else
                f"已移除 {invalid_observations} 条 source/quote 与原始材料不精确匹配的观察。"
            )
        if invalid_kinds:
            limitations.append(
                f"Removed {invalid_kinds} observation(s) with an unregistered evidence kind."
                if language == "en" else
                f"已移除 {invalid_kinds} 条使用未注册证据种类的观察。"
            )
        if invalid_type_kinds:
            limitations.append(
                f"Removed {invalid_type_kinds} observation(s) whose evidence kind is not allowed for "
                f"{result.vulnerability_type}."
                if language == "en" else
                f"已移除 {invalid_type_kinds} 条证据种类与 {result.vulnerability_type} 不匹配的观察。"
            )
        if invalid_state_expectations:
            limitations.append(
                f"Removed {invalid_state_expectations} state-change observation(s) without a concrete "
                "indicator/before/after expectation."
                if language == "en" else
                f"已移除 {invalid_state_expectations} 条缺少明确 indicator/before/after 的状态变化观察。"
            )
        if invalid_database_probes:
            limitations.append(
                f"Removed {invalid_database_probes} database probe(s) not fully grounded in the exact quote."
                if language == "en" else
                f"已移除 {invalid_database_probes} 个未在精确引用中完整溯源的数据库结果探针。"
            )
        if invalid_http_probes:
            limitations.append(
                f"Removed {invalid_http_probes} HTTP probe(s) that were not fully grounded in the exact quote."
                if language == "en" else
                f"已移除 {invalid_http_probes} 个未在精确引用中完整溯源的 HTTP 验证探针。"
            )
        if invalid_artifact_paths:
            limitations.append(
                f"Removed {invalid_artifact_paths} artifact path(s) not present in the exact quote."
                if language == "en" else
                f"已移除 {invalid_artifact_paths} 条未出现在精确引用中的文件路径。"
            )
        if result.vulnerability_type == "Unknown" and not limitations:
            limitations.append(
                "The supplied material does not identify a vulnerability type."
                if language == "en" else
                "现有材料不足以识别漏洞类型。"
            )
        updates["limitations"] = list(dict.fromkeys(limitations))
        return result.model_copy(update=updates, deep=True)

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
            local_sources = ((target.document,) if target.document is not None else ()) + target.supporting_sources
            for source in local_sources:
                sections.append(
                    f"Local source (cite with this exact label): {source.path.as_posix()}\n"
                    f"{source.content}"
                )
        else:
            sections.append("No additional local target information was supplied.")
        return "\n\n".join(sections)
