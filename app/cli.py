"""VulnForge command-line entry point."""
from __future__ import annotations
import argparse, json, os, re, sys
import threading
from contextlib import contextmanager
import time
from datetime import datetime

from app.runtime.config import ConfigurationError, RunContext

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
STAGES = {"target_preparation": 1, "document": 2, "research": 3, "planner": 4,
          "execution": 5, "script": 6, "evidence": 7}


class CliArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, lang="zh", **kwargs):
        self.lang = lang
        if lang == "zh":
            kwargs.setdefault("add_help", False)
        super().__init__(*args, **kwargs)
        if lang == "zh":
            self._positionals.title = "位置参数"
            self._optionals.title = "选项"
            self.add_argument("-h", "--help", action="help", help="显示此帮助信息并退出")

    def format_usage(self):
        usage = super().format_usage()
        return usage.replace("usage:", "用法：", 1) if self.lang == "zh" else usage

    def format_help(self):
        help_text = super().format_help()
        return help_text.replace("usage:", "用法：", 1) if self.lang == "zh" else help_text

    def error(self, message):
        if self.lang == "zh":
            message = message.replace("the following arguments are required:", "缺少必需参数：")
            message = message.replace("unrecognized arguments:", "无法识别的参数：")
            message = message.replace("expected one argument", "需要一个参数值")
            message = message.replace("invalid _positive_int value:", "无效整数值：")
            message = message.replace("must be at least 1", "必须至少为 1")
            message = message.replace("not allowed with argument", "不能与参数同时使用")
            message = re.sub(r"invalid choice: (.+?) \(choose from (.+)\)",
                             r"无效选项：\1（请从 \2 中选择）", message)
            message = re.sub(r"argument ([^:]+):", r"参数 \1：", message)
            message = message.replace("： ", "：")
            self.print_usage(sys.stderr)
            self.exit(2, f"{self.prog}：错误：{message}\n")
        super().error(message)


def requested_language(argv):
    for index, argument in enumerate(argv):
        if argument == "--lang" and index + 1 < len(argv):
            return argv[index + 1] if argv[index + 1] in {"zh", "en"} else "zh"
        if argument.startswith("--lang="):
            return argument.split("=", 1)[1] if argument.split("=", 1)[1] in {"zh", "en"} else "zh"
    return "zh"


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


def build_parser(lang="zh"):
    zh = lang == "zh"
    parser = CliArgumentParser(
        prog="vulnforge",
        description="VulnForge  |  本地 Vulhub 工作流" if zh else "VulnForge  |  Local Vulhub workflows",
        lang=lang,
    )
    commands = parser.add_subparsers(
        dest="command", required=True,
        title="命令" if zh else "commands",
        metavar="命令" if zh else "COMMAND",
    )
    run = commands.add_parser(
        "run",
        help="运行本地 Vulhub 漏洞复现工作流。" if zh else "Run local Vulhub reproduction workflow.",
        description="运行本地 Vulhub 漏洞复现工作流。" if zh else "Run local Vulhub reproduction workflow.",
        lang=lang,
    )
    run.add_argument("--cve", required=True, help="要复现的 CVE 编号。" if zh else "CVE identifier to reproduce.")
    run.add_argument("--lang", choices=("zh", "en"), default="zh",
                     help="输出语言，默认中文。" if zh else "Output language (default: Chinese).")
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
        "cancelled": "已取消", "execution_failed": "执行失败",
        "not started": "未开始", "not run": "未运行", "unknown": "未知",
        "execution_unauthorized": "未获得执行授权",
        "plan_blocked": "\u590d\u73b0\u8ba1\u5212\u672a\u901a\u8fc7", "rejected": "\u5df2\u62d2\u7edd", "verification_failed": "\u8bc1\u636e\u9a8c\u8bc1\u5931\u8d25",
    }.get(value, value)


def _display_job_status(job_status, success_basis, lang):
    if success_basis == "session_established" and job_status != "completed":
        return "completed"
    return _display_status(job_status or "unknown", lang)


def _display_vulnerability_type(value, lang):
    if lang == "en":
        return value
    return {"RCE": "远程代码执行（RCE）",
            "SQLi": "SQL \u6ce8\u5165\uff08SQLi\uff09",
            "File Read": "\u6587\u4ef6\u8bfb\u53d6",
            "File Write": "\u6587\u4ef6\u5199\u5165",
            "SSRF": "\u670d\u52a1\u7aef\u8bf7\u6c42\u4f2a\u9020\uff08SSRF\uff09",
            "Auth Bypass": "\u8ba4\u8bc1\u7ed5\u8fc7",
            "Unknown": "\u672a\u77e5"}.get(value, value)


def _display_reason(value, lang):
    if lang == "en":
        return value
    return {
        "At least one required pre-approved rule matched trusted evidence.": "\u81f3\u5c11\u4e00\u6761\u9884\u5148\u8bbe\u5b9a\u7684\u9a8c\u8bc1\u89c4\u5219\u4e0e\u53ef\u4fe1\u8bc1\u636e\u5339\u914d\u3002",
        "At least one pre-approved rule matched trusted evidence.": "\u81f3\u5c11\u4e00\u6762\u9884\u5148\u6279\u51c6\u89c4\u5219\u5339\u914d\u4e86\u53ef\u4fe1\u8bc1\u636e\u3002",
        "All required pre-approved rules matched trusted evidence.": "\u6240\u6709\u5fc5\u9700\u7684\u9884\u5148\u6279\u51c6\u89c4\u5219\u90fd\u5339\u914d\u4e86\u53ef\u4fe1\u8bc1\u636e\u3002",
        "Required evidence rules explicitly failed; no success conclusion was inferred.": "\u5fc5\u9700\u8bc1\u636e\u89c4\u5219\u660e\u786e\u5931\u8d25\uff0c\u56e0\u6b64\u672a\u5224\u5b9a\u4e3a\u6210\u529f\u3002",
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
        names = {"target_preparation": "\u51c6\u5907\u672c\u5730 Vulhub \u73af\u5883", "document": "\u6574\u7406\u6f0f\u6d1e\u8d44\u6599", "research": "\u7814\u7a76\u6f0f\u6d1e\u539f\u7406", "planner": "\u751f\u6210\u590d\u73b0\u8ba1\u5212", "execution": "\u4e00\u952e\u8fd0\u884c Metasploit", "script": "\u751f\u6210\u5e76\u9694\u79bb\u6267\u884c Python PoC", "evidence": "\u72ec\u7acb\u91c7\u96c6\u8bc1\u636e\u5e76\u9a8c\u8bc1"}
        en = {"target_preparation": "Prepare local Vulhub", "document": "Prepare readable vulnerability material", "research": "Research vulnerability", "planner": "Build reproduction plan", "execution": "One-click Metasploit execution", "script": "Generate and run isolated Python PoC", "evidence": "Collect evidence and verify"}
        step = f"[{STAGES.get(stage, '?')}/{len(STAGES)}]"
        print(f"\n{_heading(step)}  {(en if lang == 'en' else names).get(stage, stage)}")
    elif kind == "stage_completed":
        if stage == "evidence":
            print("  " + (f"Verification conclusion: {_display_status(event.get('status'), lang)}"
                          if lang == "en" else
                          f"验证结论：{_display_status(event.get('status'), lang)}"))
        elif stage == "execution":
            execution_status = event.get("execution_status")
            if execution_status == "unsupported":
                message = "No usable Metasploit module; falling back to the independent Python PoC."
                zh_message = "没有可用的 Metasploit 模块，转用独立 Python PoC"
            elif execution_status == "failed":
                errors = "; ".join(event.get("execution_errors", []))
                message = f"Metasploit execution failed; falling back to the independent Python PoC. {errors}".strip()
                zh_message = f"Metasploit 执行失败，转用独立 Python PoC。{errors}".strip()
            else:
                message = "Metasploit execution completed (verification is still pending)."
                zh_message = "Metasploit 执行完成（最终结论仍以证据验证为准）"
            print("  " + (message if lang == "en" else zh_message))
        else:
            print("  completed" if lang == "en" else "  已完成")
    elif kind == "stage_skipped":
        names = {"script": "生成并隔离执行 Python PoC" if lang == "zh" else "Generate and run isolated Python PoC"}
        step = f"[{STAGES.get(stage, '?')}/{len(STAGES)}]"
        reason = ("Metasploit execution completed" if lang == "en" else "第 5 步已执行完成")
        print(f"\n{_heading(step)}  {names.get(stage, stage)} — " +
              (f"skipped ({reason})" if lang == "en" else f"跳过（{reason}）"))
    elif kind in {"evidence_collected", "http_response_collected", "oob_callback_collected"}:
        label = {"evidence_collected": "Evidence collected",
                 "http_response_collected": "HTTP responses collected",
                 "oob_callback_collected": "OOB callbacks collected"}[kind]
        zh_label = {"evidence_collected": "已采集证据",
                    "http_response_collected": "已独立采集 HTTP 响应",
                    "oob_callback_collected": "已独立采集 OOB 回连"}[kind]
        print("  " + (f"{label}: {event.get('evidence_count', 0)}"
                      if lang == "en" else f"{zh_label}：{event.get('evidence_count', 0)} 条"))
    elif kind == "research_summary":
        r = event.get("summary", {})
        unavailable = "Insufficient evidence" if lang == "en" else "\u4fe1\u606f\u4e0d\u8db3"
        details = [_display_vulnerability_type(r.get("vulnerability_type", "Unknown"), lang), r.get("affected_component") or unavailable,
                   r.get("vulnerability_mechanism") or r.get("vulnerability_summary") or unavailable,
                   "; ".join(r.get("trigger_conditions", [])) or unavailable]
        print(("Vulnerability summary: " if lang == "en" else "\u6f0f\u6d1e\u6458\u8981\uff1a") + "\n  " + "\n  ".join(map(str, details)))
    elif kind == "execution_authorization_requested":
        plan, target = event.get("reproduction_plan", {}), event.get("runtime_target", {})
        labels = ("CVE", "Target", "Service", "Module", "Verification") if lang == "en" else ("CVE", "\u76ee\u6807", "\u670d\u52a1", "\u6a21\u5757", "\u9a8c\u8bc1")
        policy_id = event.get("verification_policy_id")
        policy_display = ("disabled" if policy_id == "verification-disabled" else policy_id)
        print(f"{labels[0]}: {plan.get('cve_id')} | {labels[1]}: {target.get('host')}:{target.get('port')} | {labels[2]}: {target.get('service')} | {labels[3]}: {event.get('module_name')} | {labels[4]}: {policy_display}")
        print(("Goal: " if lang == "en" else "\u590d\u73b0\u76ee\u6807\uff1a") + str(plan.get("reproduction_goal", "")))
        contract = event.get("verification_contract") or {}
        if contract:
            print(("Verification: " if lang == "en" else "\u9884\u671f\u9a8c\u8bc1\uff1a") + str(plan.get("verification_goal", "")))
            print(("Evidence contract: " if lang == "en" else "\u8bc1\u636e\u5951\u7ea6\uff1a") + str(contract.get("evidence_requirements", [])))
        else:
            print("Verification: disabled" if lang == "en" else "\u9a8c\u8bc1\u9636\u6bb5\uff1a\u5df2\u7981\u7528")
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
    elif kind == "target_bound":
        print("  " + (f"Target bound before execution: {event.get('host')}:{event.get('port')}"
                      if lang == "en" else
                      f"执行前目标已绑定：{event.get('host')}:{event.get('port')}"))
    elif kind == "target_port_binding_failed":
        print(f"  {event.get('error')}", file=sys.stderr)
    elif kind in {"file_baseline_unavailable", "file_artifact_inspection_failed"}:
        print("  " + (f"File verification unavailable: {event.get('error')}"
                      if lang == "en" else f"\u6587\u4ef6\u9a8c\u8bc1\u4e0d\u53ef\u7528\uff1a{event.get('error')}"))
    elif kind == "stage_failed":
        label = "failed" if lang == "en" else "\u5931\u8d25"
        print(f"  {label}: {event.get('error', event.get('errors', 'unknown'))}", file=sys.stderr)
    elif kind == "module_candidates_found":
        modules = event.get("module_names", [])
        if modules:
            print("  " + (f"Candidates: {modules}" if lang == "en" else f"\u5019\u9009\u6a21\u5757\uff1a{modules}"))
        else:
            print("  " + ("No matching Metasploit module found; falling back to the independent Python PoC."
                          if lang == "en" else
                          "\u672a\u627e\u5230\u5339\u914d\u7684 Metasploit \u6a21\u5757\uff0c\u8f6c\u7528\u72ec\u7acb Python PoC\u3002"))
    else:
        phrases = {"module_search_started": ("Searching Metasploit modules", "\u6b63\u5728\u641c\u7d22 Metasploit \u6a21\u5757"), "module_selected": (f"Selected: {event.get('module_name')}", f"\u5df2\u9009\u62e9\uff1a{event.get('module_name')}"), "module_configuration_completed": ("Module configured", "\u6a21\u5757\u914d\u7f6e\u5b8c\u6210"), "exploit_started": ("Exploit started", "\u5f00\u59cb\u6267\u884c"), "exploit_completed": (f"Job status: {_display_job_status(event.get('job_status'), event.get('success_basis'), lang)}", f"Job \u72b6\u6001\uff1a{_display_job_status(event.get('job_status'), event.get('success_basis'), lang)}"), "session_detected": ("Session detected (not proof of success)", "\u68c0\u6d4b\u5230 Session\uff08\u662f\u5426\u6210\u529f\u4ee5\u6700\u7ec8\u9a8c\u8bc1\u7ed3\u679c\u4e3a\u51c6\uff09"), "verification_completed": (f"Verification: {event.get('status')} | type: {event.get('result_label')} | matched rules: {event.get('matched_rule_names', [])} | matched evidence: {event.get('matched_evidence_ids', [])}", f"\u9a8c\u8bc1\u72b6\u6001\uff1a{_display_status(event.get('status'), lang)} | \u7ed3\u679c\u7c7b\u578b\uff1a{event.get('result_label')} | \u547d\u4e2d\u89c4\u5219\uff1a{event.get('matched_rule_names', [])} | \u547d\u4e2d\u8bc1\u636e\uff1a{event.get('matched_evidence_ids', [])}"), "execution_failed": (f"Execution failed: {event.get('error', 'unknown')}", f"\u6267\u884c\u5931\u8d25\uff1a{event.get('error', 'unknown')}" )}
        if kind in phrases: print("  " + phrases[kind][lang != "en"])


def _report(state, cve, run_time, lang):
    r, p = _summary(state.get("research_result")), _summary(state.get("reproduction_plan"))
    x, v = _summary(state.get("execution_result")), _summary(state.get("verification_result"))
    target = state.get("target"); runtime = state.get("runtime_target") or {}
    en = lang == "en"
    title = "VulnForge run report" if en else "VulnForge \u8fd0\u884c\u62a5\u544a"
    headings = ("Basic information", "Vulnerability analysis", "Reproduction plan", "Execution", "Verification result", "Summary") if en else ("\u57fa\u672c\u4fe1\u606f", "\u6f0f\u6d1e\u5206\u6790", "\u590d\u73b0\u8ba1\u5212", "\u6267\u884c\u8fc7\u7a0b", "\u9a8c\u8bc1\u7ed3\u679c", "\u603b\u7ed3")
    f = {"cve": "CVE" if en else "CVE", "time": "Run time" if en else "\u8fd0\u884c\u65f6\u95f4", "target": "Local target" if en else "\u672c\u5730\u76ee\u6807", "status": "Status" if en else "\u72b6\u6001", "category": "Category" if en else "\u6f0f\u6d1e\u7c7b\u522b", "component": "Affected component" if en else "\u53d7\u5f71\u54cd\u7ec4\u4ef6", "mechanism": "Mechanism" if en else "\u6f0f\u6d1e\u673a\u5236", "trigger": "Trigger conditions" if en else "\u89e6\u53d1\u6761\u4ef6", "sources": "Sources / limitations" if en else "\u6765\u6e90\u4e0e\u5c40\u9650", "goal": "Goal" if en else "\u590d\u73b0\u76ee\u6807", "module": "Module" if en else "Metasploit \u6a21\u5757", "service": "Target service" if en else "\u76ee\u6807\u670d\u52a1", "strategy": "Verification strategy" if en else "\u9a8c\u8bc1\u7b56\u7565", "limits": "Limitations" if en else "\u6267\u884c\u9650\u5236", "job": "Job" if en else "Job \u72b6\u6001", "sessions": "Sessions" if en else "Session \u6458\u8981", "errors": "Errors" if en else "\u9519\u8bef", "rules": "Matched rules" if en else "\u5b9e\u9645\u547d\u4e2d\u7684\u89c4\u5219", "evidence": "Matched evidence IDs" if en else "\u5b9e\u9645\u547d\u4e2d\u7684\u8bc1\u636e ID", "all_evidence": "All evidence references" if en else "\u5168\u90e8\u8bc1\u636e\u5f15\u7528", "reason": "Reason" if en else "\u7ed3\u8bba\u539f\u56e0", "required": "Required evidence" if en else "\u5fc5\u9700\u8bc1\u636e", "optional": "Optional evidence" if en else "\u53ef\u9009\u8bc1\u636e", "acceptance": "Acceptance policy" if en else "\u7ec4\u5408\u7b56\u7565", "result_label": "Result type" if en else "\u7ed3\u679c\u7c7b\u578b", "missing_optional": "Unavailable optional capabilities" if en else "\u672a\u83b7\u5f97\u7684\u53ef\u9009\u80fd\u529b", "unsupported": "Unsupported reason" if en else "\u4e0d\u652f\u6301\u539f\u56e0", "reproduced": "Vulnerability reproduced" if en else "\u6f0f\u6d1e\u590d\u73b0\u6210\u529f", "shell": "Shell acquired" if en else "\u83b7\u5f97 Shell"}
    unknown = "unknown" if en else "\u4fe1\u606f\u4e0d\u8db3"
    mech = r.get("vulnerability_mechanism") or r.get("vulnerability_summary") or ("Insufficient evidence" if en else "\u8bc1\u636e\u4e0d\u8db3")
    failed_stage_label = "Failed stage" if en else "\u5931\u8d25\u9636\u6bb5"
    rpc_log_label = "Full RPC log" if en else "RPC \u8be6\u7ec6\u65e5\u5fd7"
    status_label = "Status" if en else "\u72b6\u6001"
    not_reached = "Verification disabled" if en else "\u9a8c\u8bc1\u9636\u6bb5\u5df2\u7981\u7528"
    report_rules = [rule for rule in v.get("rule_results", [])
                    if rule.get("rule_name") in v.get("matched_rule_names", [])]
    if not en:
        report_rules = [
            {**rule, "status": _display_status(rule.get("status"), lang),
             "reason": _display_reason(rule.get("reason"), lang)}
            for rule in report_rules
        ]
    report_reason = _display_reason(v.get("reason", not_reached), lang)
    contract = p.get("verification_contract") or {}
    requirements = contract.get("evidence_requirements", []) if v else []
    rule_statuses = {rule.get("rule_name"): rule.get("status") for rule in v.get("rule_results", [])}
    required = [item for item in requirements if item.get("required", True)]
    optional = [item for item in requirements if not item.get("required", True)]
    missing_optional = [item for item in optional
                        if rule_statuses.get(item.get("rule_name")) != "success"
                        and item.get("rule_name") not in v.get("matched_rule_names", [])]
    matched_evidence = list(v.get("matched_evidence_ids", []))
    all_evidence = [e.get("evidence_id") for e in _summary(state.get("evidence")).get("evidence", [])]
    result_label = v.get("result_label") or ("not_evaluated" if en else "未评估")
    result_labels = {"remote_command_execution": "\u8fdc\u7a0b\u547d\u4ee4\u6267\u884c", "session_access": "\u4f1a\u8bdd\u8bbf\u95ee",
                     "sql_injection_confirmed": "SQL \u6ce8\u5165\u5df2\u786e\u8ba4", "file_read_confirmed": "\u6587\u4ef6\u8bfb\u53d6\u5df2\u786e\u8ba4",
                     "file_write_confirmed": "\u6587\u4ef6\u5199\u5165\u5df2\u786e\u8ba4", "ssrf_confirmed": "SSRF \u5df2\u786e\u8ba4",
                     "auth_bypass_confirmed": "\u8ba4\u8bc1\u7ed5\u8fc7\u5df2\u786e\u8ba4"}
    display_result_label = result_label if en else result_labels.get(result_label, result_label)
    unsupported_reason = p.get("unsupported_reason") or (v.get("reason") if v.get("status") == "verification_unsupported" else None) or ("none" if en else "无")
    reproduced = ("not evaluated" if en else "\u672a\u8bc4\u4f30") if not v else ("yes" if v.get("status") == "success" and en else ("\u662f" if v.get("status") == "success" else "\u5426"))
    shell_acquired = "yes" if x.get("session_after") and en else ("\u662f" if x.get("session_after") else "\u5426")
    none_text = "none" if en else "无"
    acceptance_labels = {"any": "任一规则通过即可", "all": "所有规则均通过"}
    display_acceptance = contract.get("acceptance_policy", "any") if v else ("disabled" if en else "已禁用")
    if not en and v:
        display_acceptance = acceptance_labels.get(display_acceptance, display_acceptance)
    verification_strategy = p.get("verification_goal", "") if v else ("Disabled" if en else "已禁用")
    verification_status = _display_status(v.get("status"), lang) if v.get("status") else not_reached
    module_name = x.get("module_name") or ("not selected" if en else "未选择")
    local_target = "local Vulhub" if en else "本地 Vulhub"
    format_requirement = lambda item: f"{item.get('kind')}/{item.get('rule_name')}: {item.get('description', '')}"
    return _safe(f"""# {title}

## {headings[0]}
- {f['cve']}: {cve}
- {f['time']}: {run_time}
- {f['target']}: {getattr(target, 'environment', local_target)} {runtime.get('host', '')}:{runtime.get('port', '')}
- {f['status']}: {_display_status(state.get('status', 'failed'), lang)}
- {failed_stage_label}: {state.get('failed_stage', '')}

## {headings[1]}
- {f['category']}: {_display_vulnerability_type(p.get('vulnerability_type', r.get('vulnerability_type', unknown)), lang)}
- {f['component']}: {r.get('affected_component') or unknown}
- {f['mechanism']}: {mech}
- {f['trigger']}: {r.get('trigger_conditions', unknown)}
- {f['sources']}: {r.get('evidence', r.get('limitations', unknown))}

## {headings[2]}
- {f['goal']}: {p.get('reproduction_goal', '')}
- {f['module']}: {module_name}
- {f['service']}: {runtime.get('service', p.get('target_service', ''))}:{runtime.get('port', '')}
- {f['strategy']}: {verification_strategy}
- {f['required']}: {[format_requirement(item) for item in required] or none_text}
- {f['optional']}: {[format_requirement(item) for item in optional] or none_text}
- {f['acceptance']}: {display_acceptance}
- {f['limits']}: {'; '.join(p.get('limitations', []))}

## {headings[3]}
- {f['status']}: {_display_status(x.get('status', 'not started'), lang)}; {f['job']}: {_display_job_status(x.get('job_status'), x.get('success_basis'), lang)}; {f['sessions']}: {x.get('session_after', [])}
- {'Attempts' if en else '尝试次数'}: {len(x.get('attempt_history', [])) or 1}
- {f['errors']}: {state.get('errors', [])}
- {rpc_log_label}: execution.log

## {headings[4]}
- {status_label}: {verification_status}
- {f['result_label']}: {display_result_label}
- {f['reproduced']}: {reproduced}
- {f['shell']}: {shell_acquired}
- {f['rules']}: {report_rules}
- {f['evidence']}: {matched_evidence or none_text}
- {f['all_evidence']}: {all_evidence or none_text}
- {f['missing_optional']}: {[format_requirement(item) for item in missing_optional] or none_text}
- {f['unsupported']}: {unsupported_reason}
- {f['reason']}: {report_reason}

## {headings[5]}
{_display_status(state.get('status', 'failed'), lang)}; {'sessions' if en else '会话数'}: {len(x.get('session_after', []))}
""")

def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = build_parser(requested_language(arguments)).parse_args(arguments)
    if not CVE_RE.fullmatch(args.cve):
        print("Invalid CVE identifier." if args.lang == "en" else "CVE \u7f16\u53f7\u683c\u5f0f\u65e0\u6548\u3002", file=sys.stderr); return 2
    from app.targets.vulhub.config import VulhubSettings
    from app.targets.vulhub.loader import TargetError, load_target
    try:
        settings = VulhubSettings.from_environment(); target = load_target(settings.root, args.cve)
        from app.workflow import VulnForgeWorkflow
        run_context = RunContext.create(args.cve)
        run_id = run_context.run_id
        run_dir = run_context.run_dir
    except (ConfigurationError, TargetError) as exc:
        print(str(exc), file=sys.stderr); return 2
    except Exception as exc:
        print(("Workflow configuration failed: " if args.lang == "en" else "工作流配置失败：") + str(exc), file=sys.stderr); return 2
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
            workflow = VulnForgeWorkflow.from_environment(
                run_context=run_context, event_sink=sink, language=args.lang
            )
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
                print("Authorize this isolated PoC execution against the current local Vulhub target." if args.lang == "en" else "\u5373\u5c06\u6388\u6743\u5728\u5f53\u524d\u9694\u79bb\u7684\u672c\u5730 Vulhub \u76ee\u6807\u4e0a\u6267\u884c PoC\u3002")
                from app.agents.execution import ExecutionAuthorization
                return ExecutionAuthorization(run_id=req.run_id, target_id=req.target_id,
                    target_fingerprint=req.target_fingerprint, plan_fingerprint=req.plan_fingerprint,
                    module_name=req.module_name, module_fingerprint=req.module_fingerprint,
                    configuration_fingerprint=req.configuration_fingerprint,
                    configuration_summary=req.configuration_summary,
                    verification_policy_id=req.verification_policy_id,
                    session_baseline_ids=req.session_baseline_ids, approved=True)
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
        print(("Workflow failed: " if args.lang == "en" else "工作流运行失败：") + str(exc), file=sys.stderr)
    finally:
        v = _summary(state.get("verification_result"))
        try:
            execution = _summary(state.get("execution_result"))
            raw_console = execution.get("console_output", "")
            if raw_console:
                with (run_dir / "execution.log").open("a", encoding="utf-8") as log:
                    log.write("\n--- " + ("RPC console output (redacted)" if args.lang == "en" else "RPC 控制台输出（已脱敏）") + " ---\n")
                    log.write(str(_safe(raw_console)) + "\n")
        except OSError as exc:
            print(("Could not append execution log: " if args.lang == "en" else "无法追加执行日志：") + str(exc), file=sys.stderr)
        print("\n" + _heading("Run summary" if args.lang == "en" else "运行摘要"))
        print(("Final execution: " if args.lang == "en" else "\u6700\u7ec8\u6267\u884c\u7ed3\u679c\uff1a") + str(_display_status(state.get("status", "failed"), args.lang)))
        result = {"run_id": run_id, "cve_id": args.cve.upper(), "status": state.get("status"), "failed_stage": state.get("failed_stage"), "target": {"environment": str(getattr(target, "environment", "")), **(state.get("runtime_target") or {})}, "research_summary": _summary(state.get("research_result")), "plan_summary": _summary(state.get("reproduction_plan")), "execution_summary": _summary(state.get("execution_result")), "script_summary": _summary(state.get("script_result")), "verification_summary": v, "evidence_references": [e.get("evidence_id") for e in _summary(state.get("evidence")).get("evidence", [])], "errors": state.get("errors", [])}
        try:
            (run_dir / "result.json").write_text(json.dumps(_safe(result), ensure_ascii=False, indent=2), encoding="utf-8")
            report_path = run_dir / "report.md"
            report_path.write_text(_report(state, args.cve.upper(), run_time, args.lang), encoding="utf-8")
            evidence = state.get("evidence")
            if evidence is not None:
                evidence_dir = run_context.evidence_dir
                evidence_dir.mkdir(parents=True, exist_ok=True)
                (evidence_dir / "evidence-bundle.json").write_text(json.dumps(_safe(_json(evidence)), ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as exc:
            message = (f"Could not write run artifacts in {run_dir}: {exc}" if args.lang == "en"
                       else f"无法写入运行产物目录 {run_dir}：{exc}")
            print(message, file=sys.stderr)
        print(("Reproduction report: " if args.lang == "en" else "\u590d\u73b0\u62a5\u544a\u8def\u5f84\uff1a") + str((run_dir / "report.md").resolve()))
        print(("Run artifacts: " if args.lang == "en" else "\u672c\u6b21\u8fd0\u884c\u6587\u4ef6\u5939\uff1a") + str(run_dir.resolve()))
    return {"success": 0, "completed": 0, "unsupported": 0, "inconclusive": 0, "verification_unsupported": 0, "execution_unauthorized": 0, "cancelled": 0, "plan_blocked": 0, "execution_failed": 4, "failed": 3, "verification_failed": 4}.get(state.get("status"), 3)

if __name__ == "__main__": raise SystemExit(main())
