import pytest

from app.verification.contracts import EvidenceRequirement, VerificationContract
from app.verification.models import CommandExpectation
from app.verification.policy import build_verification_policy


@pytest.fixture
def verification_contracts():
    session = EvidenceRequirement(
        kind="session",
        rule_name="session_established",
        description="A new supported session is observed on the target.",
    )
    command = EvidenceRequirement(
        kind="command_output",
        rule_name="command_output_match",
        description="Target-bound output matches the fixed POSIX id expectation.",
    )
    return {
        "session": VerificationContract(
            evidence_requirements=(session,),
            result_label="session_access",
        ),
        "command": VerificationContract(
            evidence_requirements=(command,),
            result_label="remote_command_execution",
        ),
        "command_optional_session": VerificationContract(
            evidence_requirements=(command, session.model_copy(update={"required": False})),
            result_label="remote_command_execution",
        ),
        "all": VerificationContract(
            evidence_requirements=(command, session),
            acceptance_policy="all",
            result_label="remote_command_execution",
        ),
        "http": VerificationContract(
            evidence_requirements=(EvidenceRequirement(
                kind="http_response",
                rule_name="http_response_observed",
                description="A target-bound HTTP response is observed.",
            ),),
            result_label="ssrf_confirmed",
        ),
    }


@pytest.fixture
def command_expectation():
    return CommandExpectation(
        pattern=r"(?m)^uid=\d+\([^\r\n)]+\)\s+gid=\d+\([^\r\n)]+\)",
        match_mode="regex",
        source="builtin:posix-id",
    )


@pytest.fixture
def policy_factory(command_expectation):
    def make(contract, *, category="RCE", session_capable=True,
             command_output_supported=True, expectations=None):
        return build_verification_policy(
            run_id="run-1",
            target_id="container-1",
            vulnerability_type=category,
            contract=contract,
            module_type="exploit",
            module_name="exploit/multi/http/example",
            session_capable=session_capable,
            command_output_supported=command_output_supported,
            command_expectations=(
                (command_expectation,) if expectations is None else tuple(expectations)
            ),
        )
    return make
