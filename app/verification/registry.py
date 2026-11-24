"""Extensible registries for vulnerability types and trusted evidence rules."""
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from app.verification.contracts import VerificationContract
from app.verification.models import RuleResult
from app.verification.rules.database_result import verify_database_result_observed
from app.verification.rules.file_write import verify_file_artifact_observed
from app.verification.rules.http_response import verify_http_response_observed
from app.verification.rules.oob_callback import verify_oob_callback_observed
from app.verification.rules.rce import verify_command_output_match, verify_session_established
from app.verification.rules.state_change import verify_state_change_observed


@dataclass(frozen=True)
class VulnerabilityTypeDefinition:
    name: str
    known: bool
    allowed_evidence_kinds: frozenset[str]
    unsupported_reason: str | None = None


@dataclass(frozen=True)
class EvidenceRuleDefinition:
    kind: str
    rule_name: str
    verifier: Callable[..., RuleResult] | None
    implemented: bool
    unsupported_reason: str | None = None
    requires_execution_id: bool = False


class VulnerabilityTypeRegistry:
    def __init__(self, definitions: Iterable[VulnerabilityTypeDefinition] = ()):
        self._definitions = {definition.name.casefold(): definition for definition in definitions}

    def register(self, definition: VulnerabilityTypeDefinition) -> None:
        self._definitions[definition.name.casefold()] = definition

    def get(self, name: str) -> VulnerabilityTypeDefinition | None:
        return self._definitions.get(name.casefold())

    @property
    def definitions(self) -> tuple[VulnerabilityTypeDefinition, ...]:
        return tuple(self._definitions.values())

    def allowed_evidence_kinds(self, name: str) -> frozenset[str]:
        definition = self.get(name)
        return definition.allowed_evidence_kinds if definition else frozenset()


class EvidenceRuleRegistry:
    def __init__(self, definitions: Iterable[EvidenceRuleDefinition] = ()):
        self._definitions = {definition.rule_name: definition for definition in definitions}

    def register(self, definition: EvidenceRuleDefinition) -> None:
        self._definitions[definition.rule_name] = definition

    def get(self, rule_name: str) -> EvidenceRuleDefinition | None:
        return self._definitions.get(rule_name)

    @property
    def definitions(self) -> tuple[EvidenceRuleDefinition, ...]:
        return tuple(self._definitions.values())

    @property
    def kinds(self) -> frozenset[str]:
        return frozenset(definition.kind for definition in self._definitions.values())

    def for_kind(self, kind: str) -> EvidenceRuleDefinition | None:
        return next((definition for definition in self._definitions.values() if definition.kind == kind), None)


VULNERABILITY_TYPES = VulnerabilityTypeRegistry((
    VulnerabilityTypeDefinition("RCE", True, frozenset({
        "command_output", "session", "http_response", "oob_callback", "file_artifact",
    })),
    VulnerabilityTypeDefinition("SQLi", True, frozenset({
        "database_result", "http_response", "oob_callback", "state_change",
    })),
    VulnerabilityTypeDefinition("File Read", True, frozenset({
        "file_artifact", "http_response",
    })),
    VulnerabilityTypeDefinition("File Write", True, frozenset({
        "file_artifact", "state_change", "http_response",
    })),
    VulnerabilityTypeDefinition("SSRF", True, frozenset({
        "http_response", "oob_callback", "state_change",
    })),
    VulnerabilityTypeDefinition("Auth Bypass", True, frozenset({
        "http_response", "state_change",
    })),
    VulnerabilityTypeDefinition("Unknown", False, frozenset(),
                                "The supplied material does not identify a vulnerability type."),
))


EVIDENCE_RULES = EvidenceRuleRegistry((
    EvidenceRuleDefinition("session", "session_established", verify_session_established, True),
    EvidenceRuleDefinition("command_output", "command_output_match", verify_command_output_match, True,
                           requires_execution_id=True),
    EvidenceRuleDefinition("http_response", "http_response_observed", verify_http_response_observed,
                           True, requires_execution_id=True),
    EvidenceRuleDefinition("oob_callback", "oob_callback_observed", verify_oob_callback_observed,
                           True, requires_execution_id=True),
    EvidenceRuleDefinition("file_artifact", "file_artifact_observed", verify_file_artifact_observed, True,
                           requires_execution_id=True),
    EvidenceRuleDefinition("database_result", "database_result_observed", verify_database_result_observed,
                           True, requires_execution_id=True),
    EvidenceRuleDefinition("state_change", "state_change_observed", verify_state_change_observed, True,
                           requires_execution_id=True),
))


_DEFAULT_RESULT_LABELS = {
    ("RCE", "command_output"): "remote_command_execution",
    ("RCE", "session"): "session_access",
    ("SQLi", "database_result"): "sql_injection_confirmed",
    ("File Read", "file_artifact"): "file_read_confirmed",
    ("File Write", "file_artifact"): "file_write_confirmed",
    ("SSRF", "http_response"): "ssrf_confirmed",
    ("Auth Bypass", "state_change"): "auth_bypass_confirmed",
}


def default_result_label(vulnerability_type: str, evidence_kinds: Iterable[str]) -> str:
    kinds = tuple(dict.fromkeys(evidence_kinds))
    for kind in kinds:
        label = _DEFAULT_RESULT_LABELS.get((vulnerability_type, kind))
        if label:
            return label
    normalized = vulnerability_type.casefold().replace(" ", "_")
    return f"{normalized or 'vulnerability'}_confirmed"


def validate_contract(*, vulnerability_type: str, contract: VerificationContract,
                      type_registry: VulnerabilityTypeRegistry = VULNERABILITY_TYPES,
                      rule_registry: EvidenceRuleRegistry = EVIDENCE_RULES) -> str | None:
    definition = type_registry.get(vulnerability_type)
    if definition is None or not definition.known:
        return definition.unsupported_reason if definition else f"Unrecognized vulnerability type: {vulnerability_type}."
    for requirement in contract.evidence_requirements:
        if requirement.kind not in definition.allowed_evidence_kinds:
            return f"Evidence kind {requirement.kind} is not allowed for {vulnerability_type}."
        rule = rule_registry.get(requirement.rule_name)
        if rule is None:
            return f"Unregistered evidence rule: {requirement.rule_name}."
        if rule.kind != requirement.kind:
            return f"Evidence rule {requirement.rule_name} does not collect {requirement.kind}."
        if not rule.implemented or rule.verifier is None:
            return rule.unsupported_reason or f"Evidence rule {requirement.rule_name} is not implemented."
    return None


def copy_rule_registry(registry: EvidenceRuleRegistry = EVIDENCE_RULES) -> EvidenceRuleRegistry:
    return EvidenceRuleRegistry(registry.definitions)
