"""Independent, target-bound HTTP evidence probes."""
from __future__ import annotations

import hashlib
import http.client
import ssl

from app.agents.execution import RuntimeTarget
from app.verification.contracts import HttpExpectation


class HttpResponseCollector:
    def __init__(self, *, timeout=10, max_response_bytes=1024 * 1024):
        self.timeout, self.max_response_bytes = timeout, max_response_bytes

    def collect(self, execution, expectations: tuple[HttpExpectation, ...]) -> list[dict]:
        target = RuntimeTarget.model_validate(execution.target)
        rows = []
        for expectation in expectations:
            row = {
                "source": "vulnforge_http_probe",
                "execution_id": execution.execution_id,
                "target_id": execution.target_id,
                "expectation": expectation.model_dump(mode="json"),
                "status": None,
                "headers": [],
                "body": "",
                "body_sha256": None,
                "truncated": False,
                "error": None,
            }
            connection = None
            try:
                if expectation.scheme == "https":
                    connection = http.client.HTTPSConnection(
                        target.host, target.port, timeout=self.timeout, context=ssl.create_default_context())
                else:
                    connection = http.client.HTTPConnection(target.host, target.port, timeout=self.timeout)
                connection.request(
                    expectation.method, expectation.path,
                    body=expectation.body.encode("utf-8"), headers=dict(expectation.headers),
                )
                response = connection.getresponse()
                body = response.read(self.max_response_bytes + 1)
                truncated = len(body) > self.max_response_bytes
                body = body[:self.max_response_bytes]
                row.update(
                    status=response.status,
                    headers=[(name, value) for name, value in response.getheaders()],
                    body=body.decode("utf-8", errors="replace"),
                    body_sha256=hashlib.sha256(body).hexdigest(),
                    truncated=truncated,
                )
            except Exception as exc:
                row["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                if connection is not None:
                    connection.close()
            rows.append(row)
        return rows
