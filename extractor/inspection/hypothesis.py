"""Runtime hypothesis verification (assertion evaluation through VerdictEngine / EvidenceLedger) and the incident
report export entry point (delegates to extractor.incident_report).

Moved verbatim from extractor/watch_session.py; functions take the ``WatchSessionManager`` first (``mgr``) and
are bound on it as methods.
"""

import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from ..evidence_adapter import EvidenceAdapter
from ..evidence_ledger import EvidenceLedger
from ..target_adapter import TargetExecutionAdapter
from ..verdict_engine import (
    ASSERTION_ABSTAIN,
    ASSERTION_FAIL,
    ASSERTION_PASS,
    AssertionEvaluation,
    VerdictEngine,
    sanitize_report_output_path,
)


# -------------------------------------------------------------------------
# Phase 50 (Phase 20): Declarative Multi-Assertion Hypothesis Verifier
# (`verify_runtime_hypothesis`) & 1-Call Incident Report Exporter
# (`export_incident_report`)
# -------------------------------------------------------------------------

def _parse_single_assertion(assertion_str: str) -> Dict[str, Any]:
    """Parses a declarative C/C++ assertion string such as:
        - `gpMem.active_buffers >= 2`
        - `buffers[5].seq == 5005`
        - `g_null_pool_ptr == NULL` or `g_null_pool_ptr IS_NULL`
        - `gpMem NOT_NULL`
        - `buffers[5].in_use` (truthy check `!= 0`)
        """
    s = (assertion_str or "").strip()
    if not s:
        raise ValueError("Empty assertion string")

    m_unary = re.match(r"^(.+?)\s+(IS_NULL|NOT_NULL)$", s, flags=re.IGNORECASE)
    if m_unary:
        lhs = m_unary.group(1).strip()
        op = m_unary.group(2).upper()
        return {"raw": s, "lhs": lhs, "operator": op, "rhs_raw": None}

    for op in ("==", "!=", ">=", "<=", ">", "<"):
        if op in s:
            lhs, rhs = s.split(op, 1)
            return {"raw": s, "lhs": lhs.strip(), "operator": op, "rhs_raw": rhs.strip()}

    return {"raw": s, "lhs": s, "operator": "TRUTHY", "rhs_raw": "!= 0"}


def _compare_assertion_values(observed: Any, op: str, rhs_raw: Optional[str]) -> Tuple[bool, Any]:
    """Compares observed DWARF-decoded value against expected operator and RHS literal."""
    def _is_null_like(v: Any) -> bool:
        if v is None or v == 0 or v is False:
            return True
        if isinstance(v, str) and v.strip().lower() in ("0", "0x0", "null", "nullptr", "0x00000000", "0x0000000000000000"):
            return True
        return False

    if op == "IS_NULL":
        return _is_null_like(observed), "NULL (0x0)"
    if op == "NOT_NULL":
        return (not _is_null_like(observed)), "NOT_NULL (!= 0x0)"
    if op == "TRUTHY":
        return (not _is_null_like(observed)), "!= 0"

    rhs_clean = (rhs_raw or "").strip()
    if (rhs_clean.startswith("'") and rhs_clean.endswith("'")) or (rhs_clean.startswith('"') and rhs_clean.endswith('"')):
        rhs_val: Any = rhs_clean[1:-1]
    elif rhs_clean.lower() in ("null", "nullptr", "0x0"):
        rhs_val = 0
    elif rhs_clean.lower() in ("true", "false"):
        rhs_val = 1 if rhs_clean.lower() == "true" else 0
    elif rhs_clean.lower().startswith("0x"):
        try:
            rhs_val = int(rhs_clean, 16)
        except ValueError:
            rhs_val = rhs_clean
    else:
        try:
            rhs_val = int(rhs_clean)
        except ValueError:
            try:
                rhs_val = float(rhs_clean)
            except ValueError:
                rhs_val = rhs_clean

    # Normalize observed value if comparing against numeric
    obs_norm: Any = observed
    if isinstance(rhs_val, (int, float)):
        if isinstance(observed, str):
            obs_s = observed.strip().lower()
            if obs_s in ("null", "nullptr"):
                obs_norm = 0
            elif obs_s.startswith("0x"):
                try:
                    obs_norm = int(obs_s, 16)
                except ValueError:
                    pass
            else:
                # Handle enum format `"STATE_ACTIVE (2)"`
                m_enum = re.search(r"\((-?\d+)\)\s*$", obs_s)
                if m_enum:
                    obs_norm = int(m_enum.group(1))
                else:
                    try:
                        obs_norm = float(obs_s) if "." in obs_s else int(obs_s)
                    except ValueError:
                        pass
        elif isinstance(observed, bool):
            obs_norm = 1 if observed else 0

    try:
        if op == "==":
            if isinstance(rhs_val, str) and not isinstance(obs_norm, str):
                return str(obs_norm) == rhs_val, rhs_val
            return obs_norm == rhs_val, rhs_val
        if op == "!=":
            return obs_norm != rhs_val, rhs_val
        if op == ">=":
            return float(obs_norm) >= float(rhs_val), rhs_val
        if op == "<=":
            return float(obs_norm) <= float(rhs_val), rhs_val
        if op == ">":
            return float(obs_norm) > float(rhs_val), rhs_val
        if op == "<":
            return float(obs_norm) < float(rhs_val), rhs_val
    except Exception:
        return False, rhs_val
    return False, rhs_val


def verify_runtime_hypothesis(
    mgr,
    hypothesis: str,
    assertions: List[str],
    pid: Optional[int] = None,
    companion_elf_path: Optional[str] = None,
    process_name: Optional[str] = None,
    correlate_owners: bool = True,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
    report_html_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Declarative Multi-Assertion Hypothesis Verifier (`runtime_verify_hypothesis`)."""
    t_start_ns = time.monotonic_ns()
    ctx_info = mgr.resolve_target_context(
        pid=pid,
        companion_elf_path=companion_elf_path,
        process_name=process_name,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    eff_pid = ctx_info["pid"]
    eff_elf = ctx_info["companion_elf_path"]

    coerced_assertions = mgr._coerce_str_list(assertions)
    parsed_list = [mgr._parse_single_assertion(a) for a in coerced_assertions if str(a).strip()]
    lhs_exprs = [p["lhs"] for p in parsed_list]

    eval_out = mgr.evaluate_symbol_paths(
        pid=eff_pid,
        companion_elf_path=eff_elf,
        expressions=lhs_exprs,
        remote_host=ctx_info.get("remote_host"),
        ssh_user=ctx_info.get("ssh_user"),
        ssh_port=ctx_info.get("ssh_port", 22),
        ssh_key=ctx_info.get("ssh_key"),
        ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
        adapter=adapter,
    )
    eval_by_expr = {r["expression"]: r for r in eval_out.get("results", [])}

    assertion_results: List[Dict[str, Any]] = []
    ae_list: List[AssertionEvaluation] = []
    passed_count = 0
    failed_count = 0
    abstain_count = 0
    slot_expressions_to_correlate: List[str] = []

    for p_item in parsed_list:
        lhs = p_item["lhs"]
        op = p_item["operator"]
        rhs_raw = p_item["rhs_raw"]
        ev = eval_by_expr.get(lhs, {})
        st = ev.get("status", "UNKNOWN")
        obs_val = ev.get("value")
        res_expr = ev.get("resolved_expression") or lhs

        if st == "OBSERVED":
            passed, expected_val = mgr._compare_assertion_values(obs_val, op, rhs_raw)
            a_verdict = ASSERTION_PASS if passed else ASSERTION_FAIL
        elif st == "NULL_POINTER" and op in ("IS_NULL", "==") and "->" not in lhs and "." not in lhs:
            passed, expected_val = mgr._compare_assertion_values(0, op, rhs_raw)
            a_verdict = ASSERTION_PASS if passed else ASSERTION_FAIL
        else:
            passed = False
            expected_val = rhs_raw
            a_verdict = ASSERTION_ABSTAIN

        if a_verdict == ASSERTION_PASS:
            passed_count += 1
        elif a_verdict == ASSERTION_FAIL:
            failed_count += 1
        else:
            abstain_count += 1

        m_slot = re.match(r"^(.+?\[\s*\d+\s*\])", res_expr)
        if m_slot:
            slot_base = m_slot.group(1)
            if slot_base not in slot_expressions_to_correlate:
                slot_expressions_to_correlate.append(slot_base)

        assertion_results.append({
            "assertion": p_item["raw"],
            "lhs_expression": lhs,
            "resolved_expression": res_expr,
            "was_coerced": ev.get("was_coerced", False),
            "operator": op,
            "expected": expected_val,
            "observed_value": obs_val,
            "evaluation_status": st,
            "verdict": a_verdict,
            "runtime_address": ev.get("runtime_address"),
            "passed": passed,
            "self_repair": ev.get("self_repair"),
        })
        ae_list.append(
            AssertionEvaluation(
                raw_assertion=p_item["raw"],
                lhs_expression=lhs,
                resolved_expression=res_expr,
                operator=op,
                expected=expected_val,
                observed_value=obs_val,
                observation_status=st,
                verdict=a_verdict,
                reason="Condition satisfied" if a_verdict == ASSERTION_PASS else (
                    f"Observation status {st}" if a_verdict == ASSERTION_ABSTAIN else f"Observed {obs_val} != {op} {expected_val}"
                ),
                runtime_address=ev.get("runtime_address"),
                was_coerced=ev.get("was_coerced", False),
            )
        )

    correlated_slot_owners: Dict[str, Any] = {}
    if correlate_owners and slot_expressions_to_correlate:
        for s_expr in slot_expressions_to_correlate[:4]:
            try:
                ow = mgr.find_symbol_owners_and_threads(
                    pid=eff_pid,
                    companion_elf_path=eff_elf,
                    target_expression=s_expr,
                    adapter=adapter,
                )
                correlated_slot_owners[s_expr] = [
                    {"tid": t["tid"], "thread_name": t["thread_name"], "confidence": t["confidence"]}
                    for t in (ow.get("matched_threads") or [])
                ]
            except Exception:
                pass

    total_cnt = len(assertion_results)
    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    ledger = EvidenceLedger()
    ev_adapter = EvidenceAdapter()
    sym_recs = ev_adapter.adapt_symbol_evaluation(
        eval_result=eval_out,
        target_identity={"pid": eff_pid, "companion_elf": eff_elf},
        session_id=ledger.session_id,
    )
    ev_adapter.record_into_ledger(sym_recs, ledger)
    # IMP-017: the assertion-outcome rollup and its report live in verdict_engine (this class only collects)
    hv = VerdictEngine.summarize_hypothesis_verification(
        hypothesis=hypothesis, evaluations=ae_list, total=total_cnt, passed=passed_count, failed=failed_count,
        abstained=abstain_count, target_identity={"pid": eff_pid, "companion_elf": eff_elf},
        latency_us=latency_us, bytes_read=len(lhs_exprs) * 64,
    )
    verdict, pass_ratio = hv["outcome"], hv["pass_ratio"]
    report_html, report_json = hv["report_html"], hv["report_json"]

    saved_html_path = None
    save_html_error = None
    if report_html_path and str(report_html_path).strip():
        san_html, html_err = sanitize_report_output_path(report_html_path, file_type="HTML report")
        if html_err or not san_html:
            save_html_error = html_err or f"Invalid HTML report path: {report_html_path}"
            print(f"WARNING: {save_html_error}", file=sys.stderr)
        else:
            try:
                os.makedirs(os.path.dirname(san_html), exist_ok=True)
                with open(san_html, "w", encoding="utf-8") as hf:
                    hf.write(report_html)
                saved_html_path = san_html
            except OSError as os_err:
                save_html_error = f"Failed to write HTML report to {san_html}: {os_err}"

    # Persist golden corpus snapshot if corpus_dir is configured
    if mgr.corpus_dir:
        try:
            os.makedirs(mgr.corpus_dir, exist_ok=True)
            snap_file = os.path.join(mgr.corpus_dir, f"000_verify_snapshot_{eff_pid}.json")
            with open(snap_file, "w", encoding="utf-8") as cf:
                json.dump(
                    {
                        "goal": "Verify worker integrity",
                        "hypothesis": hypothesis,
                        "verdict": verdict,
                        "pid": eff_pid,
                        "confidence": round(pass_ratio, 3),
                    },
                    cf,
                    indent=2,
                )
        except Exception:
            pass

    return {
        "pid": eff_pid,
        "companion_elf": eff_elf,
        "stop_duration_ms": 0.0,
        "target_stop_duration_ms": 0.0,
        "verification_latency_us": latency_us,
        "observation_latency_us": latency_us,
        "hypothesis": hypothesis,
        "verdict": verdict,
        "confidence": round(pass_ratio, 3),
        "confidence_score": round(pass_ratio, 3),
        "total_assertions": total_cnt,
        "passed_assertions": passed_count,
        "failed_assertions": failed_count,
        "abstain_assertions": abstain_count,
        "assertion_results": assertion_results,
        "correlated_slot_owners": correlated_slot_owners,
        "evidence_ledger": ledger.to_dict(),
        "report_html": report_html,
        "report_json": report_json,
        "saved_html_path": saved_html_path,
        "save_html_error": save_html_error,
        "llm_next_step_hint": (
            f"Hypothesis '{hypothesis}' is {verdict} ({passed_count}/{total_cnt} assertions passed, "
            f"confidence {round(pass_ratio * 100, 1)}%) in zero-stop mode."
        ),
    }


def export_incident_report(
    mgr,
    title: str = "dynamicState Zero-Stop Runtime Incident Report",
    hypothesis: Optional[str] = None,
    assertions: Optional[List[str]] = None,
    output_path: Optional[str] = None,
    report_html_path: Optional[str] = None,
    template_path: Optional[str] = None,
    pid: Optional[int] = None,
    companion_elf_path: Optional[str] = None,
    process_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
    language: str = "en",
) -> Dict[str, Any]:
    """1-Call Incident Report exporter (`runtime_export_incident_report`, CLI `export-report`, web).

        IMP-017: delegates to :func:`extractor.incident_report.export_incident_report`, which runs ``diagnose()``
        once; this class no longer decides a verdict or builds the report.  Only the target context (bound PID /
        ELF / SSH settings) is resolved here.
        """
    from ..incident_report import export_incident_report as _export
    pre: List[str] = []
    build_id = None
    if pid is not None and (isinstance(pid, bool) or pid <= 0):
        return _export(title=title, pid=pid, language=language)
    try:
        ctx_info = mgr.resolve_target_context(
            pid=pid, companion_elf_path=companion_elf_path, process_name=process_name,
            remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump, adapter=adapter,
        )
    except Exception as ctx_exc:  # noqa: BLE001
        ctx_info = {"pid": pid, "companion_elf_path": companion_elf_path, "process_name": process_name,
                    "remote_host": remote_host, "ssh_user": ssh_user, "ssh_port": ssh_port, "ssh_key": ssh_key,
                    "ssh_proxy_jump": ssh_proxy_jump}
        pre.append(f"resolve_target_context failed: {type(ctx_exc).__name__}: {ctx_exc}")
    build_id = ctx_info.get("build_id")
    return _export(
        title=title, hypothesis=hypothesis, assertions=assertions, output_path=output_path,
        report_html_path=report_html_path, template_path=template_path,
        pid=ctx_info.get("pid") or pid, companion_elf_path=ctx_info.get("companion_elf_path") or companion_elf_path,
        process_name=ctx_info.get("process_name"), build_id=build_id,
        remote_host=ctx_info.get("remote_host"), ssh_user=ctx_info.get("ssh_user"),
        ssh_port=ctx_info.get("ssh_port") or 22, ssh_key=ctx_info.get("ssh_key"),
        ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"), adapter=adapter, corpus_dir=mgr.corpus_dir,
        hypothesis_verifier=mgr.verify_runtime_hypothesis, pre_limitations=pre, language=language,
    )
