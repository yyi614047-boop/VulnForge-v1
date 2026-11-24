"""Sequential, per-target-authorized runs for local Vulhub RCE CVEs."""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import tomllib
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from app.runtime.config import ConfigurationError
from app.targets.vulhub.config import VulhubSettings
from app.targets.vulhub.loader import TargetError, resolve_cve


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
HARD_FAILURE_STATUSES = {
    "artifact_invalid", "artifact_missing", "config_error", "execution_failed",
    "failed", "launch_failed", "plan_blocked", "process_failed", "timeout",
}


@dataclass(frozen=True)
class RceTarget:
    cve: str
    app: str
    environment: Path
    source_path: str


@dataclass(frozen=True)
class SkippedTarget:
    cve: str | None
    app: str
    source_path: str
    reason: str


@dataclass(frozen=True)
class RceDiscovery:
    selected: tuple[RceTarget, ...]
    skipped: tuple[SkippedTarget, ...]


def _read_manifest(root: Path) -> list[dict]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise TargetError("Vulhub root must be a directory.")
    manifest = root / "environments.toml"
    if manifest.is_symlink() or not manifest.is_file():
        raise TargetError("Vulhub environments.toml is missing or is not a regular file.")
    try:
        with manifest.open("rb") as stream:
            index = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise TargetError(f"Could not read Vulhub environments.toml: {exc}") from exc
    entries = index.get("environment")
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise TargetError("Vulhub environments.toml must contain an environment table array.")
    return entries


def _resolve_environment(root: Path, entry: dict) -> Path | None:
    relative_value = entry.get("path")
    if not isinstance(relative_value, str) or not relative_value.strip():
        return None
    relative = Path(relative_value)
    if relative.is_absolute() or ".." in relative.parts:
        raise TargetError(f"Unsafe environment path in Vulhub manifest: {relative_value}")
    try:
        environment = (root / relative).resolve(strict=True)
    except OSError:
        return None
    if not environment.is_relative_to(root) or not environment.is_dir():
        return None
    compose = environment / "docker-compose.yml"
    if compose.is_symlink() or not compose.is_file():
        return None
    return environment


def _entry_cves(entry: dict) -> list[str]:
    values = entry.get("cve", [])
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return []
    return [value.upper() for value in values if isinstance(value, str) and CVE_RE.fullmatch(value)]


def discover_rce_targets(root: Path, *, only_cves: Sequence[str] = ()) -> RceDiscovery:
    root = root.resolve(strict=True)
    entries = _read_manifest(root)
    requested = {cve.upper() for cve in only_cves}
    selected: list[RceTarget] = []
    skipped: list[SkippedTarget] = []
    seen: set[str] = set()
    encountered: set[str] = set()

    for entry in entries:
        tags = entry.get("tags", [])
        if not isinstance(tags, list) or "RCE" not in tags:
            continue
        app = str(entry.get("app", ""))
        source_path = str(entry.get("path", ""))
        cves = _entry_cves(entry)
        if requested:
            cves = [cve for cve in cves if cve in requested]
            if not cves:
                continue
        if not cves:
            skipped.append(SkippedTarget(None, app, source_path, "no_cve"))
            continue
        environment = _resolve_environment(root, entry)
        if environment is None:
            skipped.append(SkippedTarget(";".join(cves), app, source_path, "missing_environment"))
            continue
        for cve in cves:
            encountered.add(cve)
            if cve in seen:
                skipped.append(SkippedTarget(cve, app, source_path, "duplicate_cve"))
                continue
            try:
                resolved = resolve_cve(root, cve)
            except TargetError:
                skipped.append(SkippedTarget(cve, app, source_path, "unresolved_cve"))
                continue
            # The single-run CLI resolves the first usable manifest entry. Do not
            # silently run a different variant than the RCE entry listed here.
            if resolved != environment:
                skipped.append(SkippedTarget(cve, app, source_path, "resolved_other_variant"))
                continue
            seen.add(cve)
            selected.append(RceTarget(cve, app, environment, source_path))
    for cve in sorted(requested - encountered):
        skipped.append(SkippedTarget(cve, "", "", "not_found"))
    return RceDiscovery(tuple(selected), tuple(skipped))


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnforge-batch-rce",
        description="Run local Vulhub RCE CVEs sequentially with per-target authorization.",
    )
    parser.add_argument("--vulhub-root", type=Path)
    parser.add_argument("--cve", action="append", dest="cves", default=[],
                        help="Run only this CVE; may be repeated.")
    parser.add_argument("--limit", type=_positive_int,
                        help="Run only the first N selected CVEs.")
    parser.add_argument("--lang", choices=("zh", "en"), default="zh")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="List selected CVEs without running them (default).")
    mode.add_argument("--execute", action="store_true", help="Execute after interactive authorization for each target.")
    parser.add_argument("--batch-dir", type=Path,
                        help="Artifact directory for this batch; defaults under the runs root.")
    parser.add_argument("--stop-on-error", action="store_true",
                        help="Stop on the first failed run instead of continuing.")
    parser.add_argument("--timeout", type=_positive_int,
                        help="Optional timeout in seconds for each single-CVE run.")
    return parser


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_directories(root: Path) -> set[Path]:
    if not root.is_dir():
        return set()
    return {path for path in root.iterdir() if path.is_dir()}


def _status_from_exit_code(exit_code: int | None) -> str:
    return {
        0: "artifact_missing",
        2: "config_error",
        3: "failed",
        4: "execution_failed",
    }.get(exit_code, "process_failed")


def _read_run_result(new_directories: set[Path]) -> tuple[dict | None, Path | None, str | None]:
    candidates = sorted(
        (directory / "result.json" for directory in new_directories
         if (directory / "result.json").is_file()),
        key=lambda path: path.stat().st_mtime,
    )
    if len(candidates) != 1:
        return None, None, "artifact_missing" if not candidates else "artifact_invalid"
    result_path = candidates[0]
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, result_path.parent, "artifact_invalid"
    if not isinstance(result, dict):
        return None, result_path.parent, "artifact_invalid"
    return result, result_path.parent, None


def _summary_payload(*, batch_id: str, root: Path, batch_dir: Path,
                     selected: Sequence[RceTarget], skipped: Sequence[SkippedTarget],
                     results: Sequence[dict], stopped_reason: str | None) -> dict:
    statuses = Counter(str(result["status"]) for result in results)
    verification = Counter(
        str(result.get("verification_status") or "unknown") for result in results
    )
    return {
        "batch_id": batch_id,
        "updated_at": _now(),
        "vulhub_root": str(root),
        "batch_dir": str(batch_dir),
        "selected_count": len(selected),
        "completed_count": len(results),
        "remaining_count": len(selected) - len(results),
        "stopped_reason": stopped_reason,
        "status_counts": dict(sorted(statuses.items())),
        "verification_counts": dict(sorted(verification.items())),
        "targets": [
            {"cve": target.cve, "app": target.app, "environment": target.source_path}
            for target in selected
        ],
        "skipped": [
            {"cve": item.cve, "app": item.app, "environment": item.source_path,
             "reason": item.reason}
            for item in skipped
        ],
        "results": list(results),
    }


def _write_json(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def _write_summary(batch_dir: Path, payload: dict) -> None:
    _write_json(batch_dir / "summary.json", payload)
    path = batch_dir / "summary.csv"
    fields = [
        "cve", "app", "environment", "status", "verification_status", "exit_code",
        "run_id", "duration_seconds", "result_path", "report_path", "errors",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for result in payload["results"]:
            writer.writerow({
                "cve": result["cve"],
                "app": result["app"],
                "environment": result["environment"],
                "status": result["status"],
                "verification_status": result.get("verification_status"),
                "exit_code": result.get("exit_code"),
                "run_id": result.get("run_id"),
                "duration_seconds": result.get("duration_seconds"),
                "result_path": result.get("result_path"),
                "report_path": result.get("report_path"),
                "errors": json.dumps(result.get("errors", []), ensure_ascii=False),
            })


def _print_discovery(selected: Sequence[RceTarget]) -> None:
    print(f"Selected RCE CVEs: {len(selected)}")
    for target in selected:
        print(f"  {target.cve}\t{target.app}\t{target.source_path}")


def main(argv: Sequence[str] | None = None, *,
         runner: Callable[..., subprocess.CompletedProcess] | None = None) -> int:
    args = build_parser().parse_args(argv)
    invalid = [cve for cve in args.cves if not CVE_RE.fullmatch(cve)]
    if invalid:
        print("Invalid CVE identifier: " + ", ".join(invalid), file=sys.stderr)
        return 2
    try:
        root = (args.vulhub_root.expanduser().resolve() if args.vulhub_root
                else VulhubSettings.from_environment().root)
        discovery = discover_rce_targets(root, only_cves=args.cves)
    except (ConfigurationError, TargetError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    selected = list(discovery.selected[:args.limit] if args.limit else discovery.selected)
    _print_discovery(selected)
    if args.cves and not discovery.selected:
        print("None of the requested CVEs is a runnable RCE manifest variant.", file=sys.stderr)
        return 2
    if not args.execute:
        print("Dry run only. Re-run with --execute to authorize and run each target.")
        return 0
    if not selected:
        print("No runnable RCE CVEs selected.")
        return 0
    if not sys.stdin.isatty():
        print("Batch execution requires an interactive terminal for per-target authorization.",
              file=sys.stderr)
        return 2

    if args.batch_dir:
        batch_dir = args.batch_dir.expanduser().resolve()
    else:
        runs_root = Path(os.getenv("VULNFORGE_RUNS_ROOT", "runs")).expanduser().resolve()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        batch_dir = runs_root / "rce-batches" / f"{stamp}_{uuid.uuid4().hex[:8]}"
    if batch_dir.is_relative_to(root):
        print("Batch artifacts must be outside the read-only Vulhub root.", file=sys.stderr)
        return 2
    try:
        batch_dir.mkdir(parents=True, exist_ok=False)
        child_runs_root = batch_dir / "runs"
        child_runs_root.mkdir()
    except OSError as exc:
        print(f"Could not create batch artifact directory: {exc}", file=sys.stderr)
        return 2
    batch_id = batch_dir.name
    child_env = os.environ.copy()
    child_env["VULNFORGE_VULHUB_ROOT"] = str(root)
    child_env["VULNFORGE_RUNS_ROOT"] = str(child_runs_root)
    run = runner or subprocess.run
    results: list[dict] = []
    stopped_reason = None

    def persist() -> None:
        payload = _summary_payload(
            batch_id=batch_id, root=root, batch_dir=batch_dir, selected=selected,
            skipped=discovery.skipped, results=results, stopped_reason=stopped_reason,
        )
        _write_summary(batch_dir, payload)

    persist()
    for index, target in enumerate(selected, 1):
        print(f"\n[{index}/{len(selected)}] {target.cve} — {target.app}")
        before = _run_directories(child_runs_root)
        started = datetime.now(timezone.utc)
        exit_code: int | None = None
        launch_error = None
        try:
            completed = run(
                [sys.executable, "-m", "app.cli", "run", "--cve", target.cve,
                 "--lang", args.lang],
                env=child_env, check=False, timeout=args.timeout,
            )
            exit_code = completed.returncode
        except KeyboardInterrupt:
            stopped_reason = "user_cancelled"
            launch_error = "Batch interrupted before the single run completed."
        except subprocess.TimeoutExpired:
            exit_code = None
            launch_error = f"Single run exceeded {args.timeout} seconds."
        except OSError as exc:
            launch_error = f"Could not start single run: {exc}"

        result, run_dir, artifact_error = _read_run_result(_run_directories(child_runs_root) - before)
        if stopped_reason == "user_cancelled":
            status = "cancelled"
        elif launch_error:
            status = "timeout" if "exceeded" in launch_error else "launch_failed"
        else:
            status = artifact_error or str((result or {}).get("status") or _status_from_exit_code(exit_code))
        verification = (result or {}).get("verification_summary") or {}
        errors = list((result or {}).get("errors") or [])
        if launch_error:
            errors.append(launch_error)
        record = {
            "cve": target.cve,
            "app": target.app,
            "environment": target.source_path,
            "status": status,
            "verification_status": verification.get("status") if isinstance(verification, dict) else None,
            "exit_code": exit_code,
            "run_id": (result or {}).get("run_id"),
            "started_at": started.isoformat(),
            "finished_at": _now(),
            "duration_seconds": round((datetime.now(timezone.utc) - started).total_seconds(), 3),
            "result_path": str(run_dir / "result.json") if run_dir else None,
            "report_path": str(run_dir / "report.md") if run_dir and (run_dir / "report.md").is_file() else None,
            "errors": errors,
        }
        results.append(record)
        persist()
        print(f"Result: {status} | verification: {record['verification_status'] or 'unknown'}")
        if stopped_reason == "user_cancelled":
            break
        if status in {"cancelled", "execution_unauthorized"}:
            stopped_reason = "user_cancelled"
            persist()
            break
        hard_failure = status in HARD_FAILURE_STATUSES or exit_code not in {0, None}
        if args.stop_on_error and hard_failure:
            stopped_reason = "stop_on_error"
            persist()
            break

    payload = _summary_payload(
        batch_id=batch_id, root=root, batch_dir=batch_dir, selected=selected,
        skipped=discovery.skipped, results=results, stopped_reason=stopped_reason,
    )
    print(f"\nCompleted: {len(results)}/{len(selected)}")
    print("Status counts: " + json.dumps(payload["status_counts"], ensure_ascii=False))
    print(f"Batch summary: {(batch_dir / 'summary.json').resolve()}")
    print(f"Batch CSV: {(batch_dir / 'summary.csv').resolve()}")
    if stopped_reason == "user_cancelled":
        return 130
    return 1 if any(
        result["status"] in HARD_FAILURE_STATUSES or result["exit_code"] not in {0, None}
        for result in results
    ) else 0


if __name__ == "__main__":
    raise SystemExit(main())
