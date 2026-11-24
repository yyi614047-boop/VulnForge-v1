"""Normalize evidence already captured by the Metasploit execution adapter."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from app.verification.models import Evidence, EvidenceBundle


class EvidenceCollector:
    """Collects only structured RPC artifacts; console prose is retained as non-proof."""
    def __init__(self, evidence_dir: Path | None = None):
        self.evidence_dir = evidence_dir

    def collect(self, execution) -> EvidenceBundle:
        target = execution.target
        target_id = execution.target_id
        evidence = []
        now = datetime.now(timezone.utc)

        def add(kind, source, metadata, raw=None):
            canonical = json.dumps(metadata, sort_keys=True, default=str)
            digest = hashlib.sha256(f"{execution.run_id}:{execution.execution_id}:{kind}:{canonical}".encode()).hexdigest()[:24]
            evidence.append(Evidence(evidence_id=f"{kind}-{digest}", evidence_type=kind,
                                     run_id=execution.run_id, target_id=target_id, source=source,
                                     collected_at=now, raw_reference=raw, metadata=metadata))

        execution_ref = None
        if self.evidence_dir is not None:
            execution_ref = str((self.evidence_dir / "execution-result.json").resolve())

        if execution.rpc_session_snapshot_collected:
            add("metasploit_session_delta", "metasploit_rpc", {
                "execution_id": execution.execution_id,
                "job_uuid": execution.job_uuid,
                "baseline_session_ids": execution.session_baseline,
                "sessions_after": execution.session_after,
                "target_host": target.get("host"),
                "target_port": target.get("port"),
                "module_name": execution.module_name,
            })
        if execution.rpc_job_result_collected:
            add("metasploit_job", "metasploit_rpc", {
                "execution_id": execution.execution_id, "job_id": execution.job_id,
                "job_uuid": execution.job_uuid, "status": execution.job_status,
                "is_success_evidence": False,
            }, raw=execution_ref)
        if execution.console_output:
            add("metasploit_console", "metasploit_console", {
                "execution_id": execution.execution_id,
                "is_success_evidence": False,
            }, raw=execution_ref)
        for row in execution.command_output_evidence:
            if not isinstance(row, dict) or row.get("source") not in {
                "metasploit_rpc_command_output", "script_command_output",
            }:
                continue
            if row.get("execution_id") != execution.execution_id or row.get("target_id") != target_id:
                continue
            metadata = {
                "execution_id": execution.execution_id, "target_id": target_id,
                "output": row.get("output", ""), "source_detail": row.get("source_detail", "module result")
            }
            if row.get("session_id"):
                metadata["session_id"] = str(row["session_id"])
            add("metasploit_command_output", "metasploit_rpc_command_output", metadata)
        for row in execution.http_response_evidence:
            if not isinstance(row, dict) or row.get("source") != "vulnforge_http_probe":
                continue
            if row.get("execution_id") != execution.execution_id or row.get("target_id") != target_id:
                continue
            add("http_response", "vulnforge_http_probe", {
                "execution_id": execution.execution_id,
                "target_id": target_id,
                "expectation": row.get("expectation"),
                "status": row.get("status"),
                "headers": row.get("headers", []),
                "body": row.get("body", ""),
                "body_sha256": row.get("body_sha256"),
                "truncated": row.get("truncated", False),
                "error": row.get("error"),
            })
        for row in execution.oob_callback_evidence:
            if not isinstance(row, dict) or row.get("source") != "vulnforge_oob_collector":
                continue
            if row.get("execution_id") != execution.execution_id or row.get("target_id") != target_id:
                continue
            add("oob_callback", "vulnforge_oob_collector", {
                "execution_id": execution.execution_id,
                "target_id": target_id,
                "target_host": row.get("target_host"),
                "expectation": row.get("expectation"),
                "token": row.get("token"),
                "path": row.get("path"),
                "method": row.get("method"),
                "remote_host": row.get("remote_host"),
                "remote_port": row.get("remote_port"),
            })
        for row in execution.file_artifact_evidence:
            if not isinstance(row, dict) or row.get("source") != "vulhub_runtime_file_artifact":
                continue
            if row.get("execution_id") != execution.execution_id or row.get("target_id") != target_id:
                continue
            add("target_file_artifact", "vulhub_runtime_file_artifact", {
                "execution_id": execution.execution_id,
                "target_id": target_id,
                "path_pattern": row.get("path_pattern", ""),
                "existed_before": row.get("existed_before"),
                "exists_after": row.get("exists_after"),
                "new_files": row.get("new_files", []),
            })
        for row in execution.state_change_evidence:
            if not isinstance(row, dict) or row.get("source") != "metasploit_rpc_state_change":
                continue
            if row.get("execution_id") != execution.execution_id or row.get("target_id") != target_id:
                continue
            add("metasploit_state_change", "metasploit_rpc_state_change", {
                "execution_id": execution.execution_id,
                "target_id": target_id,
                "job_uuid": execution.job_uuid,
                "module_name": execution.module_name,
                "indicator": row.get("indicator"),
                "before": row.get("before"),
                "after": row.get("after"),
                "source_detail": row.get("source_detail", "module.results.state_change"),
            })
        bundle = EvidenceBundle(run_id=execution.run_id, target_id=target_id,
                                execution_id=execution.execution_id, evidence=tuple(evidence))
        if self.evidence_dir is not None:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            (self.evidence_dir / "evidence-bundle.json").write_text(
                bundle.model_dump_json(indent=2), encoding="utf-8"
            )
        return bundle
