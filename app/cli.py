"""VulnForge command-line entry point."""
from __future__ import annotations
import argparse, json, os, re, sys, uuid
import threading
from contextlib import contextmanager
import time
from datetime import datetime
from pathlib import Path

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
STAGES = {"target_preparation": 1, "document": 2, "research": 3, "planner": 4,
          "execution": 5, "evidence_verification": 6}


def _heading(label):
    if sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.getenv("TERM") != "dumb":
        return f"\033[1;36m{label}\033[0m"
    return label


class StageProgress:
    def __init__(self):
        self.done = threading.Event()
        self.thread = None

    def start(self, label):
        if not sys.stdout.isatty() or os.getenv("TERM") == "dumb":
            return
        self.done.clear()

        def animate():
            started = time.monotonic()
            frame = 0
            line = ""
            while not self.done.wait(0.2):
                position = 8 - abs(frame % 16 - 8)
                bar = " " * position + "===" + " " * (8 - position)
                line = f"  [{bar}] {int(time.monotonic() - started)}s  {label}"
                print("\r" + line, end="", flush=True)
                frame += 1
            if line:
                print("\r" + " " * (len(line) + sum(ord(c) > 127 for c in line)) + "\r", end="", flush=True)

        self.thread = threading.Thread(target=animate, daemon=True)
        self.thread.start()

    def stop(self):
        if self.thread is not None:
            self.done.set()
            self.thread.join()
            self.thread = None


def build_parser():
    parser = argparse.ArgumentParser(prog="vulnforge", description="VulnForge  |  Local Vulhub workflows")
    commands = parser.add_subparsers(dest="command", required=True, title="commands", metavar="COMMAND")
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


def _display_status(value, lang):
    if lang == "en":
        return value
    return {
        "success": "\u6210\u529f", "failed": "\u5931\u8d25",
        "completed": "\u5df2\u5b8c\u6210", "running": "\u8fdb\u884c\u4e2d",
        "inconclusive": "\u8bc1\u636e\u4e0d\u8db3", "unsupported": "\u6682\u4e0d\u652f\u6301",
        "verification_unsupported": "\u6682\u4e0d\u652f\u6301\u81ea\u52a8\u9a8c\u8bc1",
        "cancelled": "\u5df2\u53d6\u6d88", "execution_failed": "\u6267\u884c\u5931\u8d25",
        "execution_unauthorized": "\u672a\u83b7\u5f97\u6267\u884c\u6388\u6743",
        "plan_blocked": "\u590d\u73b0\u8ba1\u5212\u672a\u901a\u8fc7", "rejected": "\u5df2\u62d2\u7edd",
    }.get(value, value)


def _display_vulnerability_type(value, lang):
    if lang == "en":
        return value
    return {"RCE": "\u8fdc\u7a0b\u4ee3\u7801\u6267\u884c\uff08RCE\uff09",
            "SQLi": "SQL \u6ce8\u5165\uff08SQLi\uff09",
            "File Write": "\u6587\u4ef6\u5199\u5165",
            "Unknown": "\u672a\u77e5"}.get(value, value)


def _display_reason(value, lang):
    if lang == "en":
        return value
    return {
        "At least one pre-approved rule matched trusted evidence.": "\u81f3\u5c11\u4e00\u6761\u9884\u5148\u8bbe\u5b9a\u7684\u9a8c\u8bc1\u89c4\u5219\u4e0e\u53ef\u4fe1\u8bc1\u636e\u5339\u914d\u3002",
        "Evidence does not establish the vulnerability; no success conclusion was inferred.": "\u73b0\u6709\u8bc1\u636e\u5c1a\u4e0d\u8db3\u4ee5\u786e\u8ba4\u6f0f\u6d1e\uff0c\u56e0\u6b64\u672a\u5224\u5b9a\u4e3a\u6210\u529f\u3002",
        "A new supported session was observed on the target.": "\u76ee\u6807\u4e0a\u51fa\u73b0\u4e86\u65b0\u5efa\u7684\u53ef\u63a5\u53d7\u4f1a\u8bdd\u3002",
        "No new supported session was observed on the target.": "\u672a\u5728\u76ee\u6807\u4e0a\u89c2\u5bdf\u5230\u7b26\u5408\u6761\u4ef6\u7684\u65b0\u4f1a\u8bdd\u3002",
        "No Metasploit RPC session delta was collected.": "\u6ca1\u6709\u6536\u96c6\u5230 Metasploit RPC \u4f1a\u8bdd\u53d8\u5316\u8bb0\u5f55\u3002",
        "No command output expectation was frozen before execution.": "\u6267\u884c\u524d\u6ca1\u6709\u8bbe\u5b9a\u547d\u4ee4\u8f93\u51fa\u9a8c\u8bc1\u9884\u671f\u3002",
        "No target-bound command output from the Metasploit execution was collected.": "\u6ca1\u6709\u6536\u96c6\u5230\u4e0e\u76ee\u6807\u548c\u672c\u6b21 Metasploit \u6267\u884c\u5173\u8054\u7684\u547d\u4ee4\u8f93\u51fa\u3002",
        "Collected command output did not match the frozen expectation.": "\u6536\u96c6\u5230\u7684\u547d\u4ee4\u8f93\u51fa\u4e0e\u9884\u8bbe\u9a8c\u8bc1\u5185\u5bb9\u4e0d\u5339\u914d\u3002",
    }.get(value, value)


def _event(event, lang, log):
    log.write(json.dumps(_safe(_json(event)), ensure_ascii=False) + "\n"); log.flush()
    kind, stage = event.get("type"), event.get("stage")
    if kind == "stage_started":
        names = {"target_preparation": "\u51c6\u5907\u672c\u5730 Vulhub \u73af\u5883", "document": "\u5206\u6790\u6f0f\u6d1e\u6587\u6863", "research": "\u7814\u7a76\u6f0f\u6d1e\u539f\u7406", "planner": "\u751f\u6210\u590d\u73b0\u8ba1\u5212", "execution": "\u641c\u7d22\u5e76\u6267\u884c Metasploit \u6a21\u5757", "evidence_verification": "\u6536\u96c6\u8bc1\u636e\u5e76\u9a8c\u8bc1\u7ed3\u8bba"}
        en = {"target_preparation": "Prepare local Vulhub", "document": "Analyze vulnerability documents", "research": "Research vulnerability", "planner": "Build reproduction plan", "execution": "Search and run Metasploit", "evidence_verification": "Collect evidence and verify result"}
        step = f"[{STAGES.get(stage, '?')}/{len(STAGES)}]"
        print(f"\n{_heading(step)}  {(en if lang == 'en' else names).get(stage, stage)}")
    elif kind == "stage_completed": print("  completed" if lang == "en" else "  \u5df2\u5b8c\u6210")
    elif kind == "research_summary":
        r = event.get("summary", {})
        unavailable = "Insufficient evidence" if lang == "en" else "\u4fe1\u606f\u4e0d\u8db3"
        details = [_display_vulnerability_type(r.get("vulnerability_type", "Unknown"), lang), r.get("affected_component") or unavailable,
                   r.get("vulnerability_mechanism") or r.get("vulnerability_summary") or unavailable,
                   "; ".join(r.get("trigger_conditions", [])) or unavailable]
        print(("Vulnerability summary: " if lang == "en" else "\u6f0f\u6d1e\u6458\u8981\uff1a") + "\n  " + "\n  ".join(map(str, details)))
    elif kind == "execution_authorization_requested":
        plan, target = event.get("reproduction_plan", {}), event.get("runtime_target", {})
        labels = ("CVE", "Target", "Service", "Module", "Policy") if lang == "en" else ("CVE", "\u76ee\u6807", "\u670d\u52a1", "\u6a21\u5757", "\u9a8c\u8bc1\u7b56\u7565")
        print(f"{labels[0]}: {plan.get('cve_id')} | {labels[1]}: {target.get('host')}:{target.get('port')} | {labels[2]}: {target.get('service')} | {labels[3]}: {event.get('module_name')} | {labels[4]}: {event.get('verification_policy_id')}")
        print(("Goal: " if lang == "en" else "\u590d\u73b0\u76ee\u6807\uff1a") + str(plan.get("reproduction_goal", "")))
        print(("Verification: " if lang == "en" else "\u9884\u671f\u9a8c\u8bc1\uff1a") + str(plan.get("verification_goal", "")))
        print(("Limitations: " if lang == "en" else "\u4e3b\u8981\u9650\u5236\uff1a") + "; ".join(plan.get("limitations", [])))
        configuration = event.get("configuration", {})
        if configuration:
            label = "Module options" if lang == "en" else "\u6a21\u5757\u53c2\u6570"
            print(label + ": " + ", ".join(f"{key}={value}" for key, value in configuration.items()))
    elif kind == "target_selected":
        label = "Vulhub environment" if lang == "en" else "Vulhub \u73af\u5883"
        print(f"{label}: {event.get('environment')}")
    elif kind == "module_path_inference_completed":
        inference = event.get("inference", {})
        if inference.get("status") == "applied":
            print(("Inferred path: " if lang == "en" else "\u63a8\u65ad\u8bf7\u6c42\u8def\u5f84\uff1a")
                  + f"{inference.get('option')}={inference.get('value')} "
                  + (f"({inference.get('source')})" if lang == "en"
                     else f"\uff08\u6765\u6e90\uff1a{inference.get('source')}\uff09"))
        elif inference.get("status") == "module_default":
            print("No unique local request path; using the module default."
                  if lang == "en" else "\u672c\u5730\u8bf7\u6c42\u8def\u5f84\u4e0d\u552f\u4e00\uff0c\u4f7f\u7528\u6a21\u5757\u9ed8\u8ba4\u503c\u3002")
    elif kind == "stage_failed":
        label = "failed" if lang == "en" else "\u5931\u8d25"
        print(f"  {label}: {event.get('error', event.get('errors', 'unknown'))}", file=sys.stderr)
    else:
        phrases = {"module_search_started": ("Searching Metasploit modules", "\u6b63\u5728\u641c\u7d22 Metasploit \u6a21\u5757"), "module_candidates_found": (f"Candidates: {event.get('module_names', [])}", f"\u5019\u9009\u6a21\u5757\uff1a{event.get('module_names', [])}"), "module_selected": (f"Selected: {event.get('module_name')}", f"\u5df2\u9009\u62e9\uff1a{event.get('module_name')}"), "module_configuration_completed": ("Module configured", "\u6a21\u5757\u914d\u7f6e\u5b8c\u6210"), "exploit_started": ("Exploit started", "\u5f00\u59cb\u6267\u884c"), "exploit_completed": (f"Job status: {event.get('job_status', 'finished')}", f"Job \u72b6\u6001\uff1a{_display_status(event.get('job_status', 'finished'), lang)}"), "session_detected": ("Session detected (not proof of success)", "\u68c0\u6d4b\u5230 Session\uff08\u662f\u5426\u6210\u529f\u4ee5\u6700\u7ec8\u9a8c\u8bc1\u7ed3\u679c\u4e3a\u51c6\uff09"), "execution_failed": (f"Execution failed: {event.get('error', 'unknown')}", f"\u6267\u884c\u5931\u8d25\uff1a{event.get('error', 'unknown')}" )}
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
    failed_stage_label = "Failed stage" if en else "\u5931\u8d25\u9636\u6bb5"
    rpc_log_label = "Full RPC log" if en else "RPC \u8be6\u7ec6\u65e5\u5fd7"
    status_label = "Status" if en else "\u72b6\u6001"
    not_reached = "Verification not reached" if en else "\u672a\u8fdb\u5165\u9a8c\u8bc1\u9636\u6bb5"
    report_rules = v.get("rule_results", [])
    if not en:
        report_rules = [
            {**rule, "status": _display_status(rule.get("status"), lang),
             "reason": _display_reason(rule.get("reason"), lang)}
            for rule in report_rules
        ]
    report_reason = _display_reason(v.get("reason", not_reached), lang)
    return _safe(f"""# {title}

## {headings[0]}
- {f['cve']}: {cve}
- {f['time']}: {run_time}
- {f['target']}: {getattr(target, 'environment', 'local Vulhub')} {runtime.get('host', '')}:{runtime.get('port', '')}
- {f['status']}: {_display_status(state.get('status', 'failed'), lang)}
- {failed_stage_label}: {state.get('failed_stage', '')}

## {headings[1]}
- {f['category']}: {_display_vulnerability_type(r.get('vulnerability_type', unknown), lang)}
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
- {f['status']}: {_display_status(x.get('status', 'not started'), lang)}; {f['job']}: {_display_status(x.get('job_status', 'unknown'), lang)}; {f['sessions']}: {x.get('session_after', [])}
- {f['errors']}: {state.get('errors', [])}
- {rpc_log_label}: execution.log

## {headings[4]}
- {status_label}: {_display_status(v.get('status', 'not run'), lang)}
- {f['rules']}: {report_rules}
- {f['evidence']}: {[e.get('evidence_id') for e in _summary(state.get('evidence')).get('evidence', [])]}
- {f['reason']}: {report_reason}

## {headings[5]}
{report_reason if v.get('reason') else _display_status(state.get('status', 'failed'), lang)}
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
    print(f"{_heading('VulnForge')}  |  {args.cve.upper()}")
    run_time = datetime.now().astimezone().isoformat(); workflow = None
    try:
        with (run_dir / "execution.log").open("w", encoding="utf-8") as log:
            progress = StageProgress()
            stage = None
            def sink(e):
                nonlocal stage
                progress.stop()
                _event(e, args.lang, log)
                kind = e.get("type")
                if kind == "stage_started":
                    stage = e.get("stage")
                elif kind in {"stage_completed", "stage_failed"}:
                    stage = None
                if stage and kind != "execution_authorization_requested":
                    label = "Working" if args.lang == "en" else "处理中"
                    if stage == "target_preparation":
                        label = "Preparing Docker environment" if args.lang == "en" else "准备 Docker 环境"
                    progress.start(label)
            workflow = VulnForgeWorkflow.from_environment(event_sink=sink, language=args.lang)
            if sys.stdout.isatty() and sys.stderr.isatty() and os.getenv("TERM") != "dumb":
                @contextmanager
                def compose_progress():
                    progress.stop()
                    try:
                        yield
                    finally:
                        progress.start("Preparing Docker environment" if args.lang == "en" else "准备 Docker 环境")

                workflow.target_runtime.compose_progress = compose_progress
            def authorize(req):
                print("About to run Metasploit against the current local Vulhub target." if args.lang == "en" else "\u5373\u5c06\u5bf9\u5f53\u524d\u672c\u5730 Vulhub \u73af\u5883\u6267\u884c Metasploit \u6f0f\u6d1e\u590d\u73b0\u3002")
                yes = _ask("Continue? [y/N]: " if args.lang == "en" else "\u662f\u5426\u7ee7\u7eed\uff1f[y/N]: ")
                from app.agents.execution import ExecutionAuthorization
                return ExecutionAuthorization(run_id=req.run_id, target_id=req.target_id,
                    target_fingerprint=req.target_fingerprint, plan_fingerprint=req.plan_fingerprint,
                    module_name=req.module_name, module_fingerprint=req.module_fingerprint,
                    configuration_fingerprint=req.configuration_fingerprint,
                    configuration_summary=req.configuration_summary,
                    verification_policy_id=req.verification_policy_id,
                    session_baseline_ids=req.session_baseline_ids, approved=True) if yes else None
            try:
                state = workflow.run(args.cve, authorization_callback=authorize, run_id=run_id)
            finally:
                progress.stop()
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
        print("\n" + _heading("Run summary" if args.lang == "en" else "运行摘要"))
        print(("Final verification: " if args.lang == "en" else "\u6700\u7ec8\u9a8c\u8bc1\u7ed3\u8bba\uff1a") + str(_display_status(v.get("status", state.get("status", "failed")), args.lang)))
        result = {"run_id": run_id, "cve_id": args.cve.upper(), "status": state.get("status"), "failed_stage": state.get("failed_stage"), "target": {"environment": str(getattr(target, "environment", "")), **(state.get("runtime_target") or {})}, "research_summary": _summary(state.get("research_result")), "plan_summary": _summary(state.get("reproduction_plan")), "execution_summary": _summary(state.get("execution_result")), "verification_summary": v, "evidence_references": [e.get("evidence_id") for e in _summary(state.get("evidence")).get("evidence", [])], "errors": state.get("errors", [])}
        try:
            (run_dir / "result.json").write_text(json.dumps(_safe(result), ensure_ascii=False, indent=2), encoding="utf-8")
            report_path = run_dir / "report.md"
            report_path.write_text(_report(state, args.cve.upper(), run_time, args.lang), encoding="utf-8")
            evidence = state.get("evidence")
            if evidence is not None:
                evidence_dir = run_dir / "evidence"
                evidence_dir.mkdir(exist_ok=True)
                (evidence_dir / "evidence-bundle.json").write_text(json.dumps(_safe(_json(evidence)), ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as exc: print(f"Could not write run artifacts in {run_dir}: {exc}", file=sys.stderr)
        print(("Reproduction report: " if args.lang == "en" else "\u590d\u73b0\u62a5\u544a\u8def\u5f84\uff1a") + str((run_dir / "report.md").resolve()))
        print(("Run artifacts: " if args.lang == "en" else "\u672c\u6b21\u8fd0\u884c\u6587\u4ef6\u5939\uff1a") + str(run_dir.resolve()))
    return {"success": 0, "unsupported": 0, "inconclusive": 0, "verification_unsupported": 0, "execution_unauthorized": 0, "cancelled": 0, "plan_blocked": 0, "execution_failed": 4, "failed": 3}.get(state.get("status"), 3)

if __name__ == "__main__": raise SystemExit(main())
