from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

from app.agents.execution import ExecutionResult, RuntimeTarget
from app.verification.collector import EvidenceCollector
from app.verification.contracts import DatabaseResultExpectation, EvidenceRequirement, HttpExpectation, VerificationContract
from app.verification.engine import VerificationEngine
from app.verification.http_collector import HttpResponseCollector
from app.verification.policy import build_verification_policy


class Handler(BaseHTTPRequestHandler):
    body = b'{"users":[{"email":"admin@example.test"}]}'

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, *args):
        pass


def setup_case(server):
    probe = HttpExpectation(path="/api/users?id=1%27", expected_status=200,
                            body_contains="admin@example.test", source="README")
    expectation = DatabaseResultExpectation(
        probe=probe, result_contains="admin@example.test", source="README")
    contract = VerificationContract(
        evidence_requirements=(EvidenceRequirement(
            kind="database_result", rule_name="database_result_observed",
            description="A documented database value is returned.",
        ),), result_label="sql_injection_confirmed", database_results=(expectation,),
    )
    policy = build_verification_policy(
        run_id="run-1", target_id="a" * 64, vulnerability_type="SQLi", contract=contract,
        module_type="exploit", module_name="exploit/multi/http/example",
    )
    target = RuntimeTarget(
        run_id="run-1", cve_id="CVE-2021-41773", project="lab-run1", service="web",
        host="127.0.0.1", callback_host="127.0.0.2", port=server.server_port,
        container_id="a" * 64, network_name="isolated", network_id="b" * 64,
        compose_sha256="c" * 64, local_vulhub=True,
    )
    result = ExecutionResult(run_id="run-1", target_id=target.container_id, cve_id=target.cve_id,
                             target=target.model_dump(), status="completed", verification_policy=policy)
    return expectation, policy, result


def test_database_result_requires_independent_response_and_exact_value():
    Handler.body = b'{"users":[{"email":"admin@example.test"}]}'
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        expectation, policy, result = setup_case(httpd)
        rows = HttpResponseCollector().collect(result, (expectation.probe,))
        result = result.model_copy(update={"http_response_evidence": rows})
        outcome = VerificationEngine().verify(
            policy=policy, execution=result, evidence=EvidenceCollector().collect(result))
        assert outcome.status == "success"
        assert outcome.matched_rule_names == ("database_result_observed",)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def test_generic_database_error_is_not_database_result_evidence():
    Handler.body = b"database error"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        expectation, policy, result = setup_case(httpd)
        rows = HttpResponseCollector().collect(result, (expectation.probe,))
        result = result.model_copy(update={"http_response_evidence": rows})
        outcome = VerificationEngine().verify(
            policy=policy, execution=result, evidence=EvidenceCollector().collect(result))
        assert outcome.status == "inconclusive"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)
