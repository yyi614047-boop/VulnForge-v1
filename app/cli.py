"""VulnForge command-line entry point."""
from __future__ import annotations
import argparse, json, os, re, sys, uuid
from datetime import datetime
from pathlib import Path

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
STAGES = {"target_preparation": 1, "document": 2, "research": 3, "planner": 4, "execution": 6, "evidence_collection": 7, "verification": 7}


def build_parser():
    parser = argparse.ArgumentParser(prog="vulnforge")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Run local Vulhub reproduction workflow.")
    run.add_argument("--cve", required=True)
    run.add_argument("--lang", choices=("zh", "en"), default="zh")
    return parser


def _json(v):
    return v.model_dump(mode="json") if hasattr(v, "model_dump") else v


def _safe(v):
    if isinstance(v, dict):
        return {k: "[REDACTED]" if re.search(r"pass(?:word)?|secret|token|api.?key|credential", k, re.I) else _safe(x) for k, x in v.items()}
    if isinstance(v, list): return [_safe(x) for x in v]
    if isinstance(v, str):
        v = re.sub(r"(?i)(pass(?:word)?|token|api[_-]?key|secret)(\s*[:=]\s*)[^\s,;]+", r"\1\2[REDACTED]", v)
        return re.sub(r"(?i)(https?://[^:/\s]+:)[^@/\s]+@", r"\1[REDACTED]@", v)
    return v


def _ask(prompt):
    if not sys.stdin.isatty(): return False
    try: return input(prompt).strip().lower() in {"y", "yes"}
    except (EOFError, KeyboardInterrupt): return False


def _summary(obj):
    val = _json(obj) if obj is not None else {}
    return val if isinstance(val, dict) else {}


def _event(event, lang, log):
    log.write(json.dumps(_safe(_json(event)), ensure_ascii=False) + "\n"); log.flush()
    kind, stage = event.get("type"), event.get("stage")
    if kind == "stage_started":
        names = {"target_preparation": "\u51c6\u5907\u672c\u5730 Vulhub \u73af\u5883", "document": "\u5206\u6790\u6f0f\u6d1e\u6587\u6863", "research": "\u7814\u7a76\u6f0f\u6d1e\u539f\u7406", "planner": "\u751f\u6210\u590d\u73b0\u8ba1\u5212", "execution": "\u641c\u7d22\u5e76\u6267\u884c Metasploit \u6a21\u5757", "evidence_collection": "\u6536\u96c6\u8bc1\u636e", "verification": "\u9a8c\u8bc1\u7ed3\u8bba"}
        en = {"target_preparation": "Prepare local Vulhub", "document": "Analyze vulnerability documents", "research": "Research vulnerability", "planner": "Build reproduction plan", "execution": "Search and run Metasploit", "evidence_collection": "Collect evidence", "verification": "Verify result"}
        print(f"[{STAGES.get(stage, '?')}/7] {(en if lang == 'en' else names).get(stage, stage)}")
    elif kind == "stage_completed": print("  completed" if lang == "en" else "  \u5df2\u5b8c\u6210")
    elif kind == "research_summary":
        r = event.get("summary", {})
        unavailable = "Insufficient evidence" if lang == "en" else "\u4fe1\u606f\u4e0d\u8db3"
        details = [r.get("vulnerability_type", "Unknown"), r.get("affected_component") or unavailable,
                   r.get("vulnerability_mechanism") or r.get("vulnerability_summary") or unavailable,
                   "; ".join(r.get("trigger_conditions", [])) or unavailable]
        print(("Vulnerability summary: " if lang == "en" else "\u6f0f\u6d1e\u6458\u8981\uff1a") + "\n  " + "\n  ".join(map(str, details)))
    elif kind == "execution_authorization_requested":
        plan, target = event.get("reproduction_plan", {}), event.get("runtime_target", {})
        print(f"CVE: {plan.get('cve_id')} | Target: {target.get('host')}:{target.get('port')} | Service: {target.get('service')} | Module: {event.get('module_name')} | Policy: {event.get('verification_policy_id')}")
        print(("Goal: " if lang == "en" else "\u590d\u73b0\u76ee\u6807\uff1a") + str(plan.get("reproduction_goal", "")))
        print(("Verification: " if lang == "en" else "\u9884\u671f\u9a8c\u8bc1\uff1a") + str(plan.get("verification_goal", "")))
        print(("Limitations: " if lang == "en" else "\u4e3b\u8981\u9650\u5236\uff1a") + "; ".join(plan.get("limitations", [])))
    elif kind == "stage_failed": print(f"  failed: {event.get('error', event.get('errors', 'unknown'))}", file=sys.stderr)
    else:
        phrases = {"module_search_started": ("Searching Metasploit modules", "\u6b63\u5728\u641c\u7d22 Metasploit \u6a21\u5757"), "module_candidates_found": (f"Candidates: {event.get('module_names', [])}", f"\u5019\u9009\u6a21\u5757\uff1a{event.get('module_names', [])}"), "module_selected": (f"Selected: {event.get('module_name')}", f"\u5df2\u9009\u62e9\uff1a{event.get('module_name')}"), "module_configuration_completed": ("Module configured", "\u6a21\u5757\u914d\u7f6e\u5b8c\u6210"), "exploit_started": ("Exploit started", "\u5f00\u59cb\u6267\u884c"), "exploit_completed": (f"Job status: {event.get('job_status', 'finished')}", f"Job \u72b6\u6001\uff1a{event.get('job_status', 'finished')}"), "session_detected": ("Session detected (not proof of success)", "\u68c0\u6d4b\u5230 Session\uff08\u4e0d\u4ee3\u8868\u9a8c\u8bc1\u6210\u529f\uff09"), "execution_failed": (f"Execution failed: {event.get('error', 'unknown')}", f"\u6267\u884c\u5931\u8d25\uff1a{event.get('error', 'unknown')}" )}
        if kind in phrases: print("  " + phrases[kind][lang != "en"])


def _report(state, cve, run_time, lang):
    r, p = _summary(state.get("research_result")), _summary(state.get("reproduction_plan"))
    x, v = _summary(state.get("execution_result")), _summary(state.get("verification_result"))
    target = state.get("target"); runtime = state.get("runtime_target") or {}
    en = lang == "en"
    title = "VulnForge run report" if en else "VulnForge \u8fd0\u884c\u62a5\u544a"
    headings = ("Basic information", "Vulnerability analysis", "Reproduction plan", "Execution", "Verification result", "Summary") if en else ("\u57fa\u672c\u4fe1\u606f", "\u6f0f\u6d1e\u5206\u6790", "\u590d\u73b0\u8ba1\u5212", "\u6267\u884c\u8fc7\u7a0b", "\u9a8c\u8bc1\u7ed3\u679c", "\u603b\u7ed3")
    f = {"cve": "CVE" if en else "CVE", "time": "Run time" if en else "\u8fd0\u884c\u65f6\u95f4", "target": "Local target" if en else "\u672c\u5730\u76ee\u6807", "status": "Status" if en else "\u72b6\u6001", "category": "Category" if en else "\u6f0f\u6d1e\u7c7b\u522b", "component": "Affected component" if en else "\u53d7\u5f71\u54cd\u7ec4\u4ef6", "mechanism": "Mechanism" if en else "\u6f0f\u6d1e\u673a\u5236", "trigger": "Trigger conditions" if en else "\u89e6\u53d1\u6761\u4ef6", "sources": "Sources / limitations" if en else "\u6765\u6e90\u4e0e\u5c40\u9650", "goal": "Goal" if en else "\u590d\u73b0\u76ee\u6807", "module": "Module" if en else "Metasploit \u6a21\u5757", "service": "Target service" if en else "\u76ee\u6807\u670d\u52a1", "strategy": "Verification strategy" if en else "\u9a8c\u8bc1\u7b56\u7565", "limits": "Limitations" if en else "\u6267\u884c\u9650\u5236", "job": "Job" if en else "Job \u72b6\u6001", "sessions": "Sessions" if en else "Session \u6458\u8981", "errors": "Errors" if en else "\u9519\u8bef", "rules": "Rules" if en else "\u9a8c\u8bc1\u89c4\u5219", "evidence": "Evidence references" if en else "\u8bc1\u636e\u5f15\u7528", "reason": "Reason" if en else "\u7ed3\u8bba\u539f\u56e0"}
    unknown = "unknown" if en else "\u4fe1\u606f\u4e0d\u8db3"
    mech = r.get("vulnerability_mechanism") or r.get("vulnerability_summary") or ("Insufficient evidence" if en else "\u8bc1\u636e\u4e0d\u8db3")
    return _safe(f"""# {title}

## {headings[0]}
- {f['cve']}: {cve}
- {f['time']}: {run_time}
- {f['target']}: {getattr(target, 'environment', 'local Vulhub')} {runtime.get('host', '')}:{runtime.get('port', '')}
- {f['status']}: {state.get('status', 'failed')}
- Failed stage: {state.get('failed_stage', '')}

## {headings[1]}
- {f['category']}: {r.get('vulnerability_type', unknown)}
- {f['component']}: {r.get('affected_component') or unknown}
- {f['mechanism']}: {mech}
- {f['trigger']}: {r.get('trigger_conditions', unknown)}
- {f['sources']}: {r.get('evidence', r.get('limitations', unknown))}

## {headings[2]}
- {f['goal']}: {p.get('reproduction_goal', '')}
- {f['module']}: {x.get('module_name', 'not selected')}
- {f['service']}: {runtime.get('service', p.get('target_service', ''))}:{runtime.get('port', '')}
- {f['strategy']}: {p.get('verification_goal', '')}
- {f['limits']}: {'; '.join(p.get('limitations', []))}

## {headings[3]}
- {f['status']}: {x.get('status', 'not started')}; {f['job']}: {x.get('job_status', 'unknown')}; {f['sessions']}: {x.get('session_after', [])}
- {f['errors']}: {state.get('errors', [])}
- Full RPC log: execution.log

## {headings[4]}
- Status: {v.get('status', 'not run')}
- {f['rules']}: {v.get('rule_results', [])}
- {f['evidence']}: {[e.get('evidence_id') for e in _summary(state.get('evidence')).get('evidence', [])]}
- {f['reason']}: {v.get('reason', 'Verification not reached')}

## {headings[5]}
{v.get('reason', state.get('status', 'failed'))}
""")

def main():
    args = build_parser().parse_args()
    if not CVE_RE.fullmatch(args.cve):
        print("Invalid CVE identifier." if args.lang == "en" else "CVE \u7f16\u53f7\u683c\u5f0f\u65e0\u6548\u3002", file=sys.stderr); return 2
    from app.runtime.config import ConfigurationError
    from app.targets.vulhub.config import VulhubSettings
    from app.targets.vulhub.loader import TargetError, load_target
    try:
        settings = VulhubSettings.from_environment(); target = load_target(settings.root, args.cve)
        from app.workflow import VulnForgeWorkflow
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        run_id = f"{stamp}_{args.cve.upper()}_{uuid.uuid4().hex[:8]}"
        run_dir = Path(os.getenv("VULNFORGE_RUNS_ROOT", "runs")) / run_id
        run_dir.mkdir(parents=True, exist_ok=False)
    except (ConfigurationError, TargetError) as exc:
        print(str(exc), file=sys.stderr); return 2
    except Exception as exc:
        print(f"Workflow configuration failed: {exc}", file=sys.stderr); return 2
    state = {"run_id": run_id, "cve_id": args.cve.upper(), "status": "failed", "errors": []}
    run_time = datetime.now().astimezone().isoformat(); workflow = None
    try:
        with (run_dir / "execution.log").open("w", encoding="utf-8") as log:
            def sink(e): _event(e, args.lang, log)
            workflow = VulnForgeWorkflow.from_environment(event_sink=sink, language=args.lang)
            def authorize(req):
                print("About to run Metasploit against the current local Vulhub target." if args.lang == "en" else "\u5373\u5c06\u5bf9\u5f53\u524d\u672c\u5730 Vulhub \u73af\u5883\u6267\u884c Metasploit \u6f0f\u6d1e\u590d\u73b0\u3002")
                yes = _ask("Continue? [y/N]: " if args.lang == "en" else "\u662f\u5426\u7ee7\u7eed\uff1f[y/N]: ")
                from app.agents.execution import ExecutionAuthorization
                return ExecutionAuthorization(run_id=req.run_id, target_id=req.target_id,
                    target_fingerprint=req.target_fingerprint, plan_fingerprint=req.plan_fingerprint,
                    module_name=req.module_name, module_fingerprint=req.module_fingerprint,
                    verification_policy_id=req.verification_policy_id,
                    session_baseline_ids=req.session_baseline_ids, approved=True) if yes else None
            state = workflow.run(args.cve, authorization_callback=authorize, run_id=run_id)
            if state.get("status") == "execution_unauthorized":
                state["status"] = "cancelled"
                state["failed_stage"] = "authorization"
                state.setdefault("errors", []).append("Execution was declined; no exploit was run.")
    except KeyboardInterrupt:
        state.update(status="cancelled", failed_stage="user_cancelled", errors=[*state.get("errors", []), "User interrupted"])
    except Exception as exc:
        state.update(status="failed", failed_stage=state.get("failed_stage") or "workflow", errors=[*state.get("errors", []), f"{type(exc).__name__}: {exc}"])
        print(f"Workflow failed: {exc}", file=sys.stderr)
    finally:
        if sys.stdin.isatty() and _ask("Stop and clean this run's Vulhub target containers? [y/N]: " if args.lang == "en" else "\u662f\u5426\u505c\u6b62\u5e76\u6e05\u7406\u672c\u6b21 Vulhub \u76ee\u6807\u5bb9\u5668\uff1f[y/N]: ") and workflow:
            try: workflow.target_runtime.cleanup_target(run_id=run_id)
            except Exception as exc: state.setdefault("errors", []).append(f"Cleanup failed: {exc}")
        v = _summary(state.get("verification_result"))
        try:
            execution = _summary(state.get("execution_result"))
            raw_console = execution.get("console_output", "")
            if raw_console:
                with (run_dir / "execution.log").open("a", encoding="utf-8") as log:
                    log.write("\n--- RPC console output (redacted) ---\n")
                    log.write(str(_safe(raw_console)) + "\n")
        except OSError as exc:
            print(f"Could not append execution log: {exc}", file=sys.stderr)
        print(("Final verification: " if args.lang == "en" else "\u6700\u7ec8\u9a8c\u8bc1\u7ed3\u8bba\uff1a") + str(v.get("status", state.get("status", "failed"))))
        result = {"run_id": run_id, "cve_id": args.cve.upper(), "status": state.get("status"), "failed_stage": state.get("failed_stage"), "target": {"environment": str(getattr(target, "environment", "")), **(state.get("runtime_target") or {})}, "research_summary": _summary(state.get("research_result")), "plan_summary": _summary(state.get("reproduction_plan")), "execution_summary": _summary(state.get("execution_result")), "verification_summary": v, "evidence_references": [e.get("evidence_id") for e in _summary(state.get("evidence")).get("evidence", [])], "errors": state.get("errors", [])}
        try:
            (run_dir / "result.json").write_text(json.dumps(_safe(result), ensure_ascii=False, indent=2), encoding="utf-8")
            (run_dir / "report.md").write_text(_report(state, args.cve.upper(), run_time, args.lang), encoding="utf-8")
            evidence = state.get("evidence")
            if evidence is not None:
                evidence_dir = run_dir / "evidence"
                evidence_dir.mkdir(exist_ok=True)
                (evidence_dir / "evidence-bundle.json").write_text(json.dumps(_safe(_json(evidence)), ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as exc: print(f"Could not write run artifacts in {run_dir}: {exc}", file=sys.stderr)
        print(f"Run artifacts: {run_dir}")
    return {"success": 0, "unsupported": 0, "inconclusive": 0, "verification_unsupported": 0, "execution_unauthorized": 0, "cancelled": 0, "plan_blocked": 0, "execution_failed": 4, "failed": 3}.get(state.get("status"), 3)

if __name__ == "__main__": raise SystemExit(main())
