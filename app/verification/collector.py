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
            execution_ref = str((self.evidence_dir / execution.run_id / "execution-result.json").resolve())

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
            }, raw=execution_ref)
        if execution.console_output:
            add("metasploit_console", "metasploit_console", {
                "execution_id": execution.execution_id,
                "is_success_evidence": False,
            }, raw=execution_ref)
        for row in execution.command_output_evidence:
            if not isinstance(row, dict) or row.get("source") != "metasploit_rpc_command_output":
                continue
            if row.get("execution_id") != execution.execution_id or row.get("target_id") != target_id:
                continue
            add("metasploit_command_output", "metasploit_rpc_command_output", {
                "execution_id": execution.execution_id, "target_id": target_id,
                "output": row.get("output", ""), "source_detail": row.get("source_detail", "module result")
            })
        bundle = EvidenceBundle(run_id=execution.run_id, target_id=target_id,
                                execution_id=execution.execution_id, evidence=tuple(evidence))
        if self.evidence_dir is not None:
            path = self.evidence_dir / execution.run_id
            path.mkdir(parents=True, exist_ok=True)
            (path / "evidence-bundle.json").write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
        return bundle
