from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest
from pydantic import ValidationError

from app.agents.execution import ExecutionResult, RuntimeTarget
from app.verification.collector import EvidenceCollector
from app.verification.contracts import EvidenceRequirement, HttpExpectation, VerificationContract
from app.verification.engine import VerificationEngine
from app.verification.http_collector import HttpResponseCollector
from app.verification.policy import build_verification_policy


class Handler(BaseHTTPRequestHandler):
    paths = []
    status = 200
    body = b"root:x:0:0:root:/root:/bin/bash\n"
    header = "internal-ok"

    def do_GET(self):
        type(self).paths.append(self.path)
        self.send_response(type(self).status)
        self.send_header("X-Evidence", type(self).header)
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    Handler.paths = []
    Handler.status = 200
    Handler.body = b"root:x:0:0:root:/root:/bin/bash\n"
    Handler.header = "internal-ok"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_port
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def execution(port):
    target = RuntimeTarget(
        run_id="run-1", cve_id="CVE-2021-41773", project="lab-run1", service="apache",
        host="127.0.0.1", callback_host="127.0.0.2", port=port,
        container_id="a" * 64, network_name="isolated", network_id="b" * 64,
        compose_sha256="c" * 64, local_vulhub=True,
    )
    return ExecutionResult(run_id="run-1", target_id=target.container_id,
                           cve_id=target.cve_id, target=target.model_dump(), status="completed")


def policy_for(expectation):
    contract = VerificationContract(
        evidence_requirements=(EvidenceRequirement(
            kind="http_response", rule_name="http_response_observed",
            description="The documented file content is returned.",
        ),),
        result_label="file_read_confirmed", http_expectations=(expectation,),
    )
    return build_verification_policy(
        run_id="run-1", target_id="a" * 64, vulnerability_type="File Read",
        contract=contract, module_type="exploit", module_name="exploit/multi/http/example",
    )


def test_http_probe_preserves_encoded_path_and_verifies_exact_body(server):
    expectation = HttpExpectation(
        path="/icons/.%2e/%2e%2e/%2e%2e/etc/passwd", expected_status=200,
        body_contains="root:x:0:0:root:/root:/bin/bash", source="README",
    )
    result = execution(server)
    policy = policy_for(expectation)
    result = result.model_copy(update={"verification_policy": policy})
    rows = HttpResponseCollector().collect(result, (expectation,))
    result = result.model_copy(update={"http_response_evidence": rows})
    bundle = EvidenceCollector().collect(result)
    outcome = VerificationEngine().verify(policy=policy, execution=result, evidence=bundle)

    assert Handler.paths == ["/icons/.%2e/%2e%2e/%2e%2e/etc/passwd"]
    assert outcome.status == "success"
    assert outcome.matched_rule_names == ("http_response_observed",)
    assert rows[0]["body_sha256"]


def test_http_status_or_content_mismatch_is_inconclusive(server):
    expectation = HttpExpectation(
        path="/fetch", expected_status=200, header_name="X-Evidence",
        header_contains="internal-ok", source="README",
    )
    result = execution(server)
    policy = policy_for(expectation)
    result = result.model_copy(update={"verification_policy": policy})
    Handler.status = 404
    rows = HttpResponseCollector().collect(result, (expectation,))
    result = result.model_copy(update={"http_response_evidence": rows})
    outcome = VerificationEngine().verify(
        policy=policy, execution=result, evidence=EvidenceCollector().collect(result))
    assert outcome.status == "inconclusive"


def test_http_expectation_rejects_target_override_and_unbounded_content():
    with pytest.raises(ValidationError):
        HttpExpectation(path="http://example.com/", expected_status=200,
                        body_contains="ok", source="README")
    with pytest.raises(ValidationError):
        HttpExpectation(path="/fetch", expected_status=200, body_contains="ok",
                        headers=(("Host", "example.com"),), source="README")
    with pytest.raises(ValidationError):
        HttpExpectation(path="/fetch", expected_status=200, source="README")
