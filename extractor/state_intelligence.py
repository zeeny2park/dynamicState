"""State intelligence, redesigned coverage taxonomy, and LLM-agent action planner.

Expands ``diagnose`` beyond binary fault detection by providing:
1. ``extract_notable_observations``: Watchlist items worth noticing even when no
   recipe FAILED (e.g., elevated FD utilization, transient lock contention,
   sub-threshold RSS growth, high involuntary preemption, long waits, C++
   container over-allocation).
2. ``classify_coverage``: Preserves conservative verdict semantics while clearly
   separating coverage into 4 buckets (``passed``, ``policy_skipped``,
   ``mode_or_target_unsupported``, ``blocking_gap``) plus ``inherent_limits``
   kept strictly in ``coverage_detail``, and computes ``verdict_qualifier``
   (e.g., ``LIMITED_OBSERVATION``, ``NO_FAULT_LIMITED_OBSERVATION``).
3. ``build_suggested_actions``: Returns concrete, executable MCP tool calls and
   CLI commands with pre-filled parameters to close blind spots or follow up on
   watchlist items / findings.
4. ``build_agent_summary``: Clean, disclaimer-free summary for LLM agents so
   downstream reasoning is not polluted by defensive boilerplate.
"""

from __future__ import annotations

import ast
import functools
import os
import shlex
from typing import Any, Dict, List, Optional, Set, Tuple

from .healthy_verdict import BLOCKING_KINDS, SCOPE_KINDS

# Policy-skipped kinds: intentionally omitted due to plan/cost/budget policy, not an error.
POLICY_SKIPPED_KINDS = frozenset({
    "recipes_not_planned",
    "integrity_not_checked",
    "uaf_not_checked",
    "double_free_not_checked",
    "no_mutex_to_inspect",
})

# Mode or target capability limits: cannot execute in zero-stop / remote / target ABI.
MODE_UNSUPPORTED_KINDS = frozenset({
    "unsupported_in_mode",
    "unsupported_on_target",
    "remote_limitation",
    "collector_not_deployed",
})

# Inherent observation limits: never a verdict blocker, kept out of top-level summaries.
INHERENT_LIMIT_KINDS = frozenset({
    "outside_baseline",
    "long_wait_not_judged",
    "leak_owner_limited",
    "integrity_limited",
    "report_not_saved",
})


def _num(x: Any) -> Optional[float]:
    if isinstance(x, bool) or x is None:
        return None
    if isinstance(x, (int, float)):
        return float(x)
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _all_observations(report: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(report, dict):
        return []
    out: List[Dict[str, Any]] = []
    sec_d = report.get("section_d_detailed_inspection_results")
    checks = (sec_d.get("checks") if isinstance(sec_d, dict) else None) or report.get("section_d_executed_checks") or []
    for c in checks:
        if isinstance(c, dict) and isinstance(c.get("actual_observations"), dict):
            out.append(c["actual_observations"])
    return out


# ------------------------------------------------------------------ 1. Notable Observations (Watchlist)
def extract_notable_observations(
    result: Dict[str, Any],
    report: Optional[Dict[str, Any]] = None,
    profile: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Extract non-FAIL noteworthy state observations (watchlist items)."""
    res = result if isinstance(result, dict) else {}
    prof = profile if isinstance(profile, dict) else (res.get("process_profile") or {})
    findings = [f for f in (res.get("findings") or []) if isinstance(f, dict)]
    finding_cats = {str(f.get("category") or "").upper() for f in findings}
    obs_list = _all_observations(report)
    items: List[Dict[str, Any]] = []
    seen_ids = set()

    def _add(item: Dict[str, Any]) -> None:
        iid = str(item.get("id") or "")
        if iid and iid not in seen_ids:
            seen_ids.add(iid)
            items.append(item)

    # 1) FD utilization watch (50%~79% of soft limit, or mild positive growth below leak threshold)
    resources = prof.get("resources") if isinstance(prof.get("resources"), dict) else {}
    fds_v = _num((resources.get("fds") or {}).get("v") if isinstance(resources.get("fds"), dict) else resources.get("fds"))
    fds_obj = resources.get("fds") if isinstance(resources.get("fds"), dict) else {}
    fd_lim = _num(fds_obj.get("limit")) or _num((resources.get("fd_limit") or {}).get("v") if isinstance(resources.get("fd_limit"), dict) else resources.get("fd_limit"))
    if fds_v is not None and fd_lim and fd_lim > 0 and "FD_LEAK" not in finding_cats:
        pct = fds_v / fd_lim * 100.0
        if 50.0 <= pct < 80.0:
            _add({
                "id": "watch_fd_utilization",
                "category": "resources",
                "severity": "watch",
                "subject": "file_descriptors",
                "title_en": f"Elevated FD usage ({int(fds_v)}/{int(fd_lim)}, {pct:.0f}%)",
                "title_ko": f"파일 디스크립터 사용률 주의 ({int(fds_v)}/{int(fd_lim)}, {pct:.0f}%)",
                "detail_en": "Below the 80% fault threshold, but worth tracking against baseline or under peak load.",
                "detail_ko": "결함 임계치(80%) 미만이지만 기준선 대비 추이나 피크 부하 시 모니터링이 필요합니다.",
                "metrics": {"fds": int(fds_v), "fd_limit": int(fd_lim), "usage_pct": round(pct, 1)},
            })

    # 2) Transient lock contention (queued waiters observed without deadlock/contention FAIL)
    locks = prof.get("locks") if isinstance(prof.get("locks"), dict) else {}
    if "LOCK_CONTENTION" not in finding_cats and "DEADLOCK_INDICATORS" not in finding_cats:
        lk_candidates = list(locks.get("items") or [])
        for ob in obs_list:
            lc = ob.get("lock_contention")
            if isinstance(lc, dict):
                lk_candidates.extend(lc.get("mutexes") or [])
        for lk in lk_candidates:
            if not isinstance(lk, dict):
                continue
            queued = int(_num(lk.get("samples_queued") or lk.get("queued_samples") or lk.get("wait_samples")) or 0)
            if queued > 0:
                lname = str(lk.get("name") or lk.get("address") or "mutex")
                _add({
                    "id": f"watch_lock_contention:{lname}",
                    "category": "locks",
                    "severity": "watch",
                    "subject": lname,
                    "title_en": f"Transient contention on lock `{lname}` ({queued} queued sample(s))",
                    "title_ko": f"락 `{lname}`에서 일시적 경합 관측 (대기 샘플 {queued}회)",
                    "detail_en": "Not a deadlock, but waiters queued during sampling; monitor under higher concurrency.",
                    "detail_ko": "교착 상태는 아니나 샘플링 중 대기 스레드가 관측되어 동시성 증가 시 병목 가능성을 지켜볼 필요가 있습니다.",
                    "metrics": {"lock": lname, "samples_queued": queued},
                })

    # 3) Sub-threshold RSS growth over observation window
    mem = prof.get("memory") if isinstance(prof.get("memory"), dict) else {}
    rss_ser = (mem.get("rss_series") or {}).get("v") if isinstance(mem.get("rss_series"), dict) else None
    if isinstance(rss_ser, list) and len(rss_ser) >= 2 and "MEMORY_GROWTH" not in finding_cats and "MEMORY_LEAK" not in finding_cats:
        r0, r1 = _num(rss_ser[0]), _num(rss_ser[-1])
        if r0 and r1 and r1 > r0:
            diff_kb = r1 - r0
            pct = diff_kb / r0 * 100.0
            if diff_kb >= 1024 and pct >= 2.0:
                _add({
                    "id": "watch_rss_subthreshold_growth",
                    "category": "memory",
                    "severity": "watch",
                    "subject": "rss",
                    "title_en": f"Sub-threshold RSS increase (+{diff_kb / 1024.0:.1f} MiB, +{pct:.1f}%)",
                    "title_ko": f"임계치 미만 RSS 증가 (+{diff_kb / 1024.0:.1f} MiB, +{pct:.1f}%)",
                    "detail_en": "Did not trigger a memory-leak fault in this window, but comparing against a baseline is recommended.",
                    "detail_ko": "이번 관측 구간에서는 누수 결함으로 판정되지 않았으나 기준선 비교로 지속 증가 여부를 확인하는 것이 좋습니다.",
                    "metrics": {"rss_start_kb": int(r0), "rss_end_kb": int(r1), "delta_kb": int(diff_kb), "delta_pct": round(pct, 1)},
                })

    # 4) Heap above baseline walk cap (large heap awareness)
    for nc in (res.get("healthy_scope") or {}).get("not_checked") or []:
        if isinstance(nc, dict) and nc.get("kind") == "integrity_not_checked":
            _add({
                "id": "watch_large_heap_uncapped",
                "category": "memory",
                "severity": "info",
                "subject": "heap",
                "title_en": "Large heap skipped in default walk cap",
                "title_ko": "대형 힙으로 인해 기본 힙 순회 상한 초과",
                "detail_en": str(nc.get("label") or nc.get("reason") or ""),
                "detail_ko": str(nc.get("label_ko") or nc.get("label") or ""),
                "metrics": {},
            })

    # 5) C++ container over-allocation or growth below fault threshold
    for cont in (mem.get("containers") or []):
        if not isinstance(cont, dict):
            continue
        var = str(cont.get("variable") or "")
        size = _num(cont.get("size"))
        cap = _num(cont.get("capacity"))
        if var and size is not None and cap is not None and cap >= 256 and cap >= max(size * 2.5, size + 256):
            _add({
                "id": f"watch_container_capacity:{var}",
                "category": "memory",
                "severity": "info",
                "subject": var,
                "title_en": f"Container `{var}` over-allocated (size {int(size)} / capacity {int(cap)})",
                "title_ko": f"컨테이너 `{var}` 용량 과다 할당 (원소 {int(size)} / 용량 {int(cap)})",
                "detail_en": "Capacity is significantly larger than current size; may retain peak memory without shrinking.",
                "detail_ko": "현재 원소 수 대비 예약 용량이 커서 피크 이후 메모리를 유지하고 있을 수 있습니다.",
                "metrics": {"variable": var, "size": int(size), "capacity": int(cap)},
            })

    # 6) High involuntary preemption (CPU contention / scheduling pressure)
    liveness = prof.get("liveness") if isinstance(prof.get("liveness"), dict) else {}
    vol_d = _num(liveness.get("voluntary_switches_delta"))
    invol_d = _num(liveness.get("involuntary_switches_delta"))
    if invol_d is not None and invol_d >= 20 and (vol_d is None or invol_d > vol_d):
        _add({
            "id": "watch_cpu_preemption",
            "category": "threads",
            "severity": "watch",
            "subject": "scheduler",
            "title_en": f"High involuntary context switches (Δinvol={int(invol_d)}, Δvol={int(vol_d or 0)})",
            "title_ko": f"비자발적 컨텍스트 스위치 비중 높음 (Δ비자발={int(invol_d)}, Δ자발={int(vol_d or 0)})",
            "detail_en": "Threads are being preempted by the scheduler frequently, suggesting CPU contention on the host.",
            "detail_ko": "스레드가 스케줄러에 의해 빈번히 선점되고 있어 호스트 CPU 경합 가능성이 있습니다.",
            "metrics": {"involuntary_switches_delta": int(invol_d), "voluntary_switches_delta": int(vol_d or 0)},
        })

    # 7) Thread count fluctuation
    threads = prof.get("threads") if isinstance(prof.get("threads"), dict) else {}
    t_ser = (threads.get("series") or {}).get("v") if isinstance(threads.get("series"), dict) else None
    if isinstance(t_ser, list) and len(t_ser) >= 2 and "THREAD_LEAK" not in finding_cats:
        t0, t1 = int(t_ser[0]), int(t_ser[-1])
        if t1 - t0 >= 2:
            _add({
                "id": "watch_thread_count_increase",
                "category": "threads",
                "severity": "watch",
                "subject": "threads",
                "title_en": f"Thread count rose during observation ({t0} -> {t1}, +{t1 - t0})",
                "title_ko": f"관측 중 스레드 수 증가 ({t0} -> {t1}, +{t1 - t0})",
                "detail_en": "Below thread-leak fault criteria, but verify whether worker pool expansion is expected.",
                "detail_ko": "스레드 누수 결함 기준 미만이지만 워커 풀 확장이 의도된 동작인지 확인해 보세요.",
                "metrics": {"threads_start": t0, "threads_end": t1, "delta": t1 - t0},
            })

    # 8) Long waits that could not be judged from outside (grouped into one clean watchlist item)
    long_wait_rows = [
        n for n in (res.get("not_covered") or [])
        if isinstance(n, dict) and n.get("kind") == "long_wait_not_judged"
    ]
    if long_wait_rows:
        names = [str(n.get("item") or n.get("thread") or "?") for n in long_wait_rows]
        shown = ", ".join(names[:4]) + (f" (+{len(names) - 4})" if len(names) > 4 else "")
        _add({
            "id": "watch_long_wait_threads",
            "category": "threads",
            "severity": "info",
            "subject": shown,
            "title_en": f"{len(long_wait_rows)} thread(s) waited across the entire window ({shown})",
            "title_ko": f"스레드 {len(long_wait_rows)}개가 관측 구간 내내 대기 상태 유지 ({shown})",
            "detail_en": "Idle event-loop waits and external I/O stalls look identical from outside; confirm if expected.",
            "detail_ko": "유휴 이벤트 대기인지 외부 I/O 지연인지는 외부 관측만으로 구분할 수 없으므로 정상 대기 여부를 확인하세요.",
            "metrics": {"count": len(long_wait_rows), "threads": names[:8]},
        })

    # 9) Non-zero memory mapping growth below leak threshold
    for ob in obs_list:
        mg = ob.get("mapping_growth")
        if isinstance(mg, dict) and "MAPPING_GROWTH" not in finding_cats:
            delta_kb = _num(mg.get("vsz_delta_kb") or mg.get("delta_kb"))
            if delta_kb is not None and delta_kb >= 4096:
                _add({
                    "id": "watch_mapping_growth",
                    "category": "memory",
                    "severity": "info",
                    "subject": "mappings",
                    "title_en": f"Virtual mapping growth observed (+{delta_kb / 1024.0:.1f} MiB)",
                    "title_ko": f"가상 메모리 매핑 증가 관측 (+{delta_kb / 1024.0:.1f} MiB)",
                    "detail_en": "Below fault threshold; track if mmap/arena mappings keep growing across runs.",
                    "detail_ko": "결함 임계치 미만이나 반복 진단 시 mmap/arena 증가가 이어지는지 추적이 필요합니다.",
                    "metrics": {"delta_kb": int(delta_kb)},
                })

    return items


# ------------------------------------------------------------------ 2. Coverage Taxonomy Redesign
def classify_coverage(
    result: Dict[str, Any],
    report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Classify checks and coverage gaps into clean, actionable buckets.

    Keeps the conservative ``verdict`` intact while separating:
    - ``passed``: checks that completed and found no fault
    - ``failed``: checks that detected a fault
    - ``policy_skipped``: skipped by plan, default-check time budget, or heap walk cap
    - ``mode_or_target_unsupported``: requires stop/tracing mode or unsupported on target/remote ABI
    - ``blocking_gap``: genuine blocker preventing a full verdict
    - ``inherent_limits``: always-true caveats (outside_baseline, long_wait_not_judged) kept in detail only
    """
    res = result if isinstance(result, dict) else {}
    verdict = str(res.get("verdict") or "INCONCLUSIVE")
    checks_run = [c for c in (res.get("checks_run") or []) if isinstance(c, dict)]
    not_covered = [n for n in (res.get("not_covered") or []) if isinstance(n, dict)]
    hs = res.get("healthy_scope") if isinstance(res.get("healthy_scope"), dict) else {}
    blocking = [b for b in (hs.get("blocking") or []) if isinstance(b, dict)]
    not_checked = [x for x in (hs.get("not_checked") or []) if isinstance(x, dict)]

    passed = [c for c in checks_run if str(c.get("status") or "").upper() == "PASS"]
    failed = [c for c in checks_run if str(c.get("status") or "").upper() == "FAIL"]
    undecided = [c for c in checks_run if str(c.get("status") or "").upper() not in ("PASS", "FAIL")]

    policy_skipped: List[Dict[str, Any]] = []
    mode_unsupported: List[Dict[str, Any]] = []
    blocking_gaps: List[Dict[str, Any]] = []
    inherent_limits: List[Dict[str, Any]] = []

    seen = set()

    def _push(bucket: List[Dict[str, Any]], kind: str, item: str, reason: str,
              extra: Optional[Dict[str, Any]] = None) -> None:
        key = (id(bucket), kind, item)
        if key in seen:
            return
        seen.add(key)
        row = {"kind": kind, "item": item, "reason": reason}
        if extra:
            row.update(extra)
        bucket.append(row)

    for n in not_covered:
        kind = str(n.get("kind") or "")
        item = str(n.get("item") or "")
        reason = str(n.get("reason") or kind)
        if kind == "baseline_check_not_run" and n.get("not_run_reason") == "default_check_time_budget":
            _push(policy_skipped, kind, item, reason, {"not_run_reason": "default_check_time_budget"})
        elif kind in POLICY_SKIPPED_KINDS:
            _push(policy_skipped, kind, item, reason)
        elif kind in MODE_UNSUPPORTED_KINDS:
            extra = {"capability": n.get("capability")} if n.get("capability") else None
            _push(mode_unsupported, kind, item, reason, extra)
        elif kind in INHERENT_LIMIT_KINDS:
            _push(inherent_limits, kind, item, reason)
        elif kind in BLOCKING_KINDS or kind.startswith("check_") or kind not in SCOPE_KINDS:
            _push(blocking_gaps, kind, item, reason)

    for x in not_checked:
        kind = str(x.get("kind") or "")
        item = str(x.get("item") or "")
        reason = str(x.get("reason") or x.get("label") or kind)
        if kind in POLICY_SKIPPED_KINDS:
            _push(policy_skipped, kind, item, reason, {"label": x.get("label"), "label_ko": x.get("label_ko")})
        elif kind in MODE_UNSUPPORTED_KINDS:
            _push(mode_unsupported, kind, item, reason, {
                "label": x.get("label"), "label_ko": x.get("label_ko"), "capability": x.get("capability"),
            })
        elif kind in INHERENT_LIMIT_KINDS:
            _push(inherent_limits, kind, item, reason, {"label": x.get("label"), "label_ko": x.get("label_ko")})

    for b in blocking:
        kind = str(b.get("kind") or "")
        item = str(b.get("item") or "")
        reason = str(b.get("reason") or kind)
        if kind == "baseline_check_missing" and b.get("not_run_reason") == "default_check_time_budget":
            _push(policy_skipped, kind, item, reason, {"not_run_reason": "default_check_time_budget"})
        elif kind not in ("verdict", "finding", "check_fail"):
            _push(blocking_gaps, kind, item, reason)

    # Determine verdict_qualifier with strict conservative semantics:
    # Partial PASS must NEVER mask execution failures, blocking gaps, or failed checks.
    access_block_kinds = {"target_unreadable", "target_unreachable", "invalid_target", "missing_debug_image"}
    exec_failure_kinds = {
        "stage_failed", "unexpected_error", "abi_detection_failed", "budget_exhausted",
        "not_executed", "limitation", "unattributed_finding", "symptom_question_unanswered",
    }
    has_access_block = any(g["kind"] in access_block_kinds for g in blocking_gaps)
    has_check_error = any(
        str(c.get("status") or "").upper() in ("ERROR", "FAILED_TO_RUN", "ABORTED")
        for c in checks_run
    )
    non_budget_blocking = [
        g for g in blocking_gaps
        if not (g["kind"] in ("baseline_check_missing", "baseline_check_not_run")
                and g.get("not_run_reason") == "default_check_time_budget")
    ]
    has_execution_failure = has_check_error or any(
        g["kind"] in exec_failure_kinds
        or g["kind"].startswith("check_error")
        or g["kind"].startswith("baseline_check_error")
        or g["kind"] in ("baseline_check_inconclusive", "baseline_check_missing")
        for g in non_budget_blocking
    )
    meaningful_policy = [p for p in policy_skipped if p["kind"] != "recipes_not_planned"]
    has_limits = bool(meaningful_policy or mode_unsupported)

    if verdict == "HEALTHY":
        # Guard: incomplete/failed coverage must never masquerade as full HEALTHY
        if failed or non_budget_blocking or has_execution_failure:
            qualifier = "INCONSISTENT_HEALTHY_CLAIM"
        elif has_limits:
            qualifier = "LIMITED_OBSERVATION"
        else:
            qualifier = "FULL_BASELINE"
    elif verdict == "INCONCLUSIVE":
        if has_access_block:
            qualifier = "BLOCKED_TARGET_ACCESS"
        elif failed or has_execution_failure or non_budget_blocking:
            qualifier = "BLOCKED_EXECUTION"
        elif passed and not failed and not undecided and not non_budget_blocking:
            qualifier = "NO_FAULT_LIMITED_OBSERVATION"
        elif passed and not failed and not has_execution_failure and not non_budget_blocking:
            qualifier = "NO_FAULT_LIMITED_OBSERVATION"
        else:
            qualifier = "BLOCKED_EXECUTION"
    elif verdict == "DEGRADED":
        qualifier = "DEGRADED_OBSERVED"
    elif verdict == "ABORTED":
        qualifier = "ABORTED"
    else:
        qualifier = "FAULT_IDENTIFIED"

    counts = {
        "executed": len(checks_run),
        "passed": len(passed),
        "failed": len(failed),
        "undecided": len(undecided),
        "policy_skipped": len(policy_skipped),
        "mode_or_target_unsupported": len(mode_unsupported),
        "blocking_gaps": len(blocking_gaps),
        "inherent_limits": len(inherent_limits),
    }

    # Build compact 1-line summaries (EN & KO)
    parts_en = [f"{counts['passed']}/{counts['executed']} passed"]
    parts_ko = [f"검사 {counts['passed']}/{counts['executed']} 통과"]
    if counts["failed"]:
        parts_en.append(f"{counts['failed']} fault(s)")
        parts_ko.append(f"결함 {counts['failed']}건")
    if counts["policy_skipped"]:
        parts_en.append(f"{counts['policy_skipped']} policy-skipped")
        parts_ko.append(f"정책 생략 {counts['policy_skipped']}건")
    if counts["mode_or_target_unsupported"]:
        parts_en.append(f"{counts['mode_or_target_unsupported']} mode/target-unsupported")
        parts_ko.append(f"모드·대상 미지원 {counts['mode_or_target_unsupported']}건")
    if counts["blocking_gaps"]:
        parts_en.append(f"{counts['blocking_gaps']} blocking gap(s)")
        parts_ko.append(f"수집·판단 제약 {counts['blocking_gaps']}건")

    qual_label_en = {
        "FULL_BASELINE": "Healthy (full baseline coverage)",
        "INCONSISTENT_HEALTHY_CLAIM": "Incomplete coverage (cannot confirm full healthy)",
        "LIMITED_OBSERVATION": "No fault found (limited observation)",
        "NO_FAULT_LIMITED_OBSERVATION": "No fault in executed checks (limited observation)",
        "BLOCKED_TARGET_ACCESS": "Inconclusive (target access or debug info missing)",
        "BLOCKED_EXECUTION": "Inconclusive (insufficient evidence)",
        "DEGRADED_OBSERVED": "Degraded",
        "FAULT_IDENTIFIED": "Fault identified",
        "ABORTED": "Aborted",
    }.get(qualifier, verdict)

    qual_label_ko = {
        "FULL_BASELINE": "정상 (기본 검사 전체 통과)",
        "INCONSISTENT_HEALTHY_CLAIM": "불완전 관측 (전체 정상 확정 불가)",
        "LIMITED_OBSERVATION": "정상 (제한적 관측)",
        "NO_FAULT_LIMITED_OBSERVATION": "실행 검사 통과 (제한적 관측)",
        "BLOCKED_TARGET_ACCESS": "판단 불가 (대상 접근 또는 디버그 정보 누락)",
        "BLOCKED_EXECUTION": "판단 불가 (근거 부족)",
        "DEGRADED_OBSERVED": "성능 저하 관측",
        "FAULT_IDENTIFIED": "결함 확인",
        "ABORTED": "진단 중단",
    }.get(qualifier, verdict)

    return {
        "verdict": verdict,
        "verdict_qualifier": qualifier,
        "qualifier_label_en": qual_label_en,
        "qualifier_label_ko": qual_label_ko,
        "counts": counts,
        "one_liner_en": " · ".join(parts_en),
        "one_liner_ko": " · ".join(parts_ko),
        "detail": {
            "policy_skipped": policy_skipped,
            "mode_or_target_unsupported": mode_unsupported,
            "blocking_gaps": blocking_gaps,
            "inherent_limits": inherent_limits,
        },
    }


# ------------------------------------------------------------------ 3. Executable Follow-up Actions
def _remote_cli_flags(target: Dict[str, Any], *, style: str = "diagnose") -> List[str]:
    host = target.get("host") or target.get("remote_host")
    if not host:
        return []
    user = target.get("ssh_user") or target.get("user")
    port = target.get("ssh_port") or target.get("port")
    key = target.get("ssh_key") or target.get("identity")
    if style == "remote_long":
        flags = ["--remote-host", str(host)]
        if user:
            flags += ["--ssh-user", str(user)]
        if port and int(port) != 22:
            flags += ["--ssh-port", str(port)]
        if key:
            flags += ["--ssh-key", str(key)]
        return flags
    flags = ["--host", str(host)]
    if user:
        flags += ["--user", str(user)]
    if port and int(port) != 22:
        flags += ["--port", str(port)]
    if key:
        flags += ["--identity", str(key)]
    return flags


def _remote_mcp_args(target: Dict[str, Any]) -> Dict[str, Any]:
    host = target.get("host") or target.get("remote_host")
    if not host:
        return {}
    out: Dict[str, Any] = {"remote_host": str(host)}
    if target.get("ssh_user") or target.get("user"):
        out["ssh_user"] = str(target.get("ssh_user") or target.get("user"))
    if target.get("ssh_port") or target.get("port"):
        out["ssh_port"] = int(target.get("ssh_port") or target.get("port"))
    if target.get("ssh_key") or target.get("identity"):
        out["ssh_key"] = str(target.get("ssh_key") or target.get("identity"))
    return out


def _fmt_cmd(parts: List[str]) -> str:
    return " ".join(shlex.quote(str(p)) for p in parts)


@functools.lru_cache(maxsize=1)
def get_mcp_tool_registry() -> Dict[str, Dict[str, Any]]:
    """Introspect registered ``@server.tool()`` functions in ``scripts/mcp_server.py`` via AST.

    Returns ``{tool_name: {"required": [...], "params": {param_name: annotation_str}}}``.
    Zero runtime side effects; cached per process.
    """
    mcp_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "mcp_server.py")
    if not os.path.isfile(mcp_path):
        return {}
    try:
        with open(mcp_path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=mcp_path)
    except (OSError, SyntaxError):
        return {}

    registry: Dict[str, Dict[str, Any]] = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        is_tool = False
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr == "tool":
                is_tool = True
                break
        if not is_tool:
            continue
        all_args = [a.arg for a in node.args.args]
        n_def = len(node.args.defaults)
        required = all_args[: len(all_args) - n_def]
        params: Dict[str, str] = {}
        for a in node.args.args:
            ann = ast.unparse(a.annotation) if a.annotation is not None else "Any"
            params[a.arg] = ann
        registry[node.name] = {"required": required, "params": params}
    return registry


def _check_arg_type(value: Any, annotation: str) -> bool:
    ann = annotation.replace(" ", "")
    if value is None:
        return "Optional[" in ann or "None" in ann or ann == "Any"
    if "Any" in ann:
        return True
    if "bool" in ann and isinstance(value, bool):
        return True
    if "int" in ann and isinstance(value, int) and not isinstance(value, bool):
        return True
    if "float" in ann and isinstance(value, (int, float)) and not isinstance(value, bool):
        return True
    if "str" in ann and isinstance(value, str):
        return True
    if "List[" in ann or "list[" in ann:
        return isinstance(value, list)
    return True


def validate_suggested_action(
    action: Dict[str, Any],
    target: Optional[Dict[str, Any]] = None,
    registry: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Validate a suggested action against the MCP tool registry, types, and target preconditions."""
    reg = registry if registry is not None else get_mcp_tool_registry()
    tgt = target if isinstance(target, dict) else {}
    tool = str(action.get("mcp_tool") or "")
    args = action.get("mcp_args") if isinstance(action.get("mcp_args"), dict) else {}
    issues: List[str] = []
    missing_inputs: List[str] = []
    blocked_reasons: List[str] = []

    if not tool:
        issues.append("missing_mcp_tool")
        blocked_reasons.append("no MCP tool specified")
    elif reg and tool not in reg:
        issues.append(f"unknown_mcp_tool:{tool}")
        blocked_reasons.append(f"MCP tool '{tool}' is not registered")
    elif reg and tool in reg:
        spec = reg[tool]
        params = spec["params"]
        for req in spec["required"]:
            if req not in args or args[req] is None:
                issues.append(f"missing_required_arg:{req}")
                missing_inputs.append(req)
        for k, v in args.items():
            if k not in params:
                issues.append(f"unknown_arg:{k}")
                blocked_reasons.append(f"parameter '{k}' is not accepted by {tool}")
            elif not _check_arg_type(v, params[k]):
                issues.append(f"type_mismatch:{k}")
                blocked_reasons.append(f"parameter '{k}' has incompatible type for {params[k]}")
            if isinstance(v, str) and v.startswith("<") and v.endswith(">"):
                missing_inputs.append(k)
                blocked_reasons.append(f"user must provide '{k}' ({v})")

    # Remote / local & capability precondition checks
    is_remote = bool(tgt.get("host") or tgt.get("remote_host") or args.get("remote_host"))
    if is_remote:
        has_elf = bool(args.get("debug_image") or args.get("companion_elf") or tgt.get("debug_image"))
        elf_val = str(args.get("debug_image") or args.get("companion_elf") or "")
        if not has_elf or (elf_val.startswith("<") and elf_val.endswith(">")):
            if "debug_image" not in missing_inputs and "companion_elf" not in missing_inputs:
                missing_inputs.append("debug_image")
            blocked_reasons.append("remote target requires an unstripped ELF debug image on this host")
        if args.get("enable_tracing") is True:
            issues.append("remote_tracing_unsupported")
            blocked_reasons.append("eBPF/uprobe selective tracing is only supported for local targets")

    valid_schema = not any(
        i.startswith(("unknown_mcp_tool", "unknown_arg", "type_mismatch", "missing_required_arg"))
        for i in issues
    )
    executable = valid_schema and not missing_inputs and not blocked_reasons

    enriched = dict(action)
    enriched.setdefault("estimated_cost", "low")
    enriched.setdefault("expected_evidence", enriched.get("expected_value_en") or "")
    enriched.setdefault("risk_level", "read_only_zero_stop")
    enriched.setdefault("requires_user_approval", bool(missing_inputs or enriched.get("risk_level") != "read_only_zero_stop"))
    enriched["executable"] = executable
    if blocked_reasons:
        enriched["blocked_reason"] = "; ".join(dict.fromkeys(blocked_reasons))
    if missing_inputs:
        enriched["missing_inputs"] = list(dict.fromkeys(missing_inputs))
    enriched["validation"] = {
        "valid": valid_schema,
        "issues": issues,
    }
    return enriched


def build_suggested_actions(
    result: Dict[str, Any],
    report: Optional[Dict[str, Any]] = None,
    profile: Optional[Dict[str, Any]] = None,
    coverage: Optional[Dict[str, Any]] = None,
    notable_observations: Optional[List[Dict[str, Any]]] = None,
    baseline_diff: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Generate concrete, parameter-filled follow-up actions for LLM agents & humans."""
    res = result if isinstance(result, dict) else {}
    target = res.get("target") if isinstance(res.get("target"), dict) else {}
    pid = target.get("pid")
    debug_image = target.get("debug_image")
    cov = coverage if isinstance(coverage, dict) else classify_coverage(res, report)
    detail = cov.get("detail") or {}
    notable = notable_observations if isinstance(notable_observations, list) else []
    findings = [f for f in (res.get("findings") or []) if isinstance(f, dict)]

    actions: List[Dict[str, Any]] = []
    seen = set()

    def _add(action: Dict[str, Any]) -> None:
        aid = str(action.get("id") or "")
        if aid and aid not in seen:
            seen.add(aid)
            actions.append(validate_suggested_action(action, target))

    if not pid:
        return actions

    rm_mcp = _remote_mcp_args(target)
    base_diagnose_args: Dict[str, Any] = {"pid": int(pid), **rm_mcp}
    if debug_image:
        base_diagnose_args["debug_image"] = str(debug_image)
    base_narrow_args: Dict[str, Any] = {"pid": int(pid), **rm_mcp}
    if debug_image:
        base_narrow_args["companion_elf"] = str(debug_image)

    # A) Missing debug image -> provide unstripped ELF
    if any(g.get("kind") == "missing_debug_image" for g in detail.get("blocking_gaps") or []):
        cmd = ["dynamic-state", "diagnose", "-p", str(pid), "-d", "<path/to/unstripped.elf>"] + _remote_cli_flags(target)
        _add({
            "id": "provide_debug_image",
            "priority": "high",
            "category": "coverage_gap",
            "title_en": "Re-run with unstripped ELF debug image",
            "title_ko": "심볼 포함 ELF 디버그 이미지를 지정해 재진단",
            "reason_en": "Symbols and DWARF types could not be resolved without the matching debug image.",
            "reason_ko": "일치하는 디버그 이미지가 없어 심볼·변수·소스 라인을 해석하지 못했습니다.",
            "mcp_tool": "runtime_diagnose_process",
            "mcp_args": {**base_diagnose_args, "debug_image": "<path/to/unstripped.elf>"},
            "estimated_cost": "medium",
            "expected_evidence": "Full DWARF symbol, lock, variable, and source-line resolution",
            "risk_level": "read_only_zero_stop",
            "requires_user_approval": True,
            "cli_command": _fmt_cmd(cmd),
            "expected_value_en": "Unlocks full DWARF variable, lock, and call-stack resolution.",
            "expected_value_ko": "변수·락·콜스택의 DWARF 심볼 및 소스 위치 해석이 활성화됩니다.",
        })

    # B) Heap above baseline walk cap -> run targeted heap-leaks or memory-corruption symptom
    if any(p.get("kind") in ("integrity_not_checked", "uaf_not_checked", "double_free_not_checked")
           for p in detail.get("policy_skipped") or []):
        hl_cmd = ["dynamic-state", "heap-leaks", "-p", str(pid)]
        if debug_image:
            hl_cmd += ["-d", str(debug_image)]
        hl_cmd += _remote_cli_flags(target)
        _add({
            "id": "full_heap_walk",
            "priority": "medium",
            "category": "coverage_gap",
            "title_en": "Run targeted heap integrity / leak analysis",
            "title_ko": "힙 상한을 초과한 영역에 대해 힙 누수·무결성 정밀 검사 실행",
            "reason_en": "Heap exceeded the baseline walk cap, so heap integrity/UAF/double-free checks were skipped.",
            "reason_ko": "힙 크기가 기본 검사 상한을 초과해 힙 무결성·UAF·이중 해제 순회가 정책상 생략되었습니다.",
            "mcp_tool": "runtime_heap_leak_candidates",
            "mcp_args": dict(base_narrow_args),
            "estimated_cost": "medium",
            "expected_evidence": "Unreachable heap chunks and owning global/container symbol paths",
            "risk_level": "read_only_zero_stop",
            "requires_user_approval": False,
            "cli_command": _fmt_cmd(hl_cmd),
            "expected_value_en": "Identifies unreachable heap blocks and owning global/container paths.",
            "expected_value_ko": "미참조 힙 블록 및 소유 변수·컨테이너 경로를 직접 추적합니다.",
        })

    # C) Default check time budget skipped checks -> re-run without default budget cap
    if any(p.get("not_run_reason") == "default_check_time_budget" for p in detail.get("policy_skipped") or []):
        cmd = ["dynamic-state", "diagnose", "-p", str(pid), "--default-check-budget", "0"]
        if debug_image:
            cmd += ["-d", str(debug_image)]
        cmd += _remote_cli_flags(target)
        _add({
            "id": "lift_default_check_budget",
            "priority": "medium",
            "category": "coverage_gap",
            "title_en": "Run skipped baseline checks without default time budget",
            "title_ko": "기본 검사 시간 예산 제한을 해제해 생략된 검사 완료",
            "reason_en": "Some baseline checks were skipped to stay within the configured default-check time budget.",
            "reason_ko": "설정된 기본 검사 시간 예산으로 인해 일부 기본 검사가 생략되었습니다.",
            "mcp_tool": "runtime_diagnose_process",
            "mcp_args": {**base_diagnose_args, "default_check_budget_s": 0},
            "estimated_cost": "medium",
            "expected_evidence": "Completion of all baseline checks skipped by time budget",
            "risk_level": "read_only_zero_stop",
            "requires_user_approval": False,
            "cli_command": _fmt_cmd(cmd),
            "expected_value_en": "Completes all remaining baseline checks for full coverage.",
            "expected_value_ko": "생략된 기본 검사를 모두 완료해 전체 커버리지를 확보합니다.",
        })

    # D) Mode unsupported due to tracing capability -> suggest enable_tracing=True
    if any(m.get("kind") == "unsupported_in_mode" and "trac" in str(m.get("capability") or m.get("reason") or "").lower()
           for m in detail.get("mode_or_target_unsupported") or []):
        cmd = ["dynamic-state", "diagnose", "-p", str(pid), "--enable-tracing"]
        if debug_image:
            cmd += ["-d", str(debug_image)]
        cmd += _remote_cli_flags(target)
        _add({
            "id": "enable_selective_tracing",
            "priority": "low",
            "category": "mode_expansion",
            "title_en": "Enable selective eBPF tracing for call-site checks",
            "title_ko": "선택적 트레이싱 모드로 함수 호출 지점 검사 확장",
            "reason_en": "Checks requiring runtime function tracing were excluded in default zero-stop memory-only mode.",
            "reason_ko": "기본 메모리 읽기 전용 모드에서는 함수 트레이싱이 필요한 검사가 제외되었습니다.",
            "mcp_tool": "runtime_diagnose_process",
            "mcp_args": {**base_diagnose_args, "enable_tracing": True},
            "estimated_cost": "high",
            "expected_evidence": "Live eBPF/uprobe function entry/return call sites",
            "risk_level": "tracing_overhead",
            "requires_user_approval": True,
            "cli_command": _fmt_cmd(cmd),
            "expected_value_en": "Captures live call-site paths for allocation/lock transitions.",
            "expected_value_ko": "할당·락 전이의 실제 런타임 호출 지점을 추가로 확보합니다.",
        })

    # E) Lock contention or deadlock / long-wait watchlist -> callstacks & locks
    has_lock_signal = (
        any("DEADLOCK" in str(f.get("category") or "").upper() or "LOCK" in str(f.get("category") or "").upper() for f in findings)
        or any(n.get("category") == "locks" or n.get("id") == "watch_long_wait_threads" for n in notable)
    )
    if has_lock_signal:
        cs_cmd = ["dynamic-state", "callstacks", "-p", str(pid)]
        if debug_image:
            cs_cmd += ["-d", str(debug_image)]
        cs_cmd += _remote_cli_flags(target, style="remote_long")
        _add({
            "id": "inspect_callstacks_and_locks",
            "priority": "high" if findings else "medium",
            "category": "follow_up",
            "title_en": "Inspect thread call stacks and mutex wait graph",
            "title_ko": "스레드 콜스택 및 뮤텍스 대기 관계 상세 조회",
            "reason_en": "Lock contention or long-waiting threads were observed.",
            "reason_ko": "락 경합 또는 장기 대기 스레드가 관측되어 전체 콜스택 확인이 유용합니다.",
            "mcp_tool": "runtime_inspect_thread_callstack_and_locks",
            "mcp_args": dict(base_narrow_args),
            "estimated_cost": "low",
            "expected_evidence": "Per-thread unwound call stacks and mutex owner/waiter edges",
            "risk_level": "read_only_zero_stop",
            "requires_user_approval": False,
            "cli_command": _fmt_cmd(cs_cmd),
            "expected_value_en": "Shows full stack frames and lock ownership chains per thread.",
            "expected_value_ko": "스레드별 전체 스택 프레임과 락 소유 체인을 확인합니다.",
        })

    # F) Memory / container watchlist -> eval container or heap-leaks
    for n in notable:
        if str(n.get("id") or "").startswith("watch_container_capacity:") and n.get("subject"):
            var = str(n["subject"])
            ev_cmd = ["dynamic-state", "eval", "--pid", str(pid), "--expr", var]
            if debug_image:
                ev_cmd += ["--debug-image", str(debug_image)]
            ev_cmd += _remote_cli_flags(target, style="remote_long")
            _add({
                "id": f"eval_container:{var}",
                "priority": "low",
                "category": "watchlist",
                "title_en": f"Inspect live contents of `{var}`",
                "title_ko": f"컨테이너 `{var}`의 실시간 내부 상태 조회",
                "reason_en": n.get("title_en") or "Over-allocated container detected.",
                "reason_ko": n.get("title_ko") or "용량 과다 할당 컨테이너가 관측되었습니다.",
                "mcp_tool": "runtime_eval_memory_path",
                "mcp_args": {**base_narrow_args, "expressions": [var]},
                "estimated_cost": "low",
                "expected_evidence": f"Live DWARF-decoded size, capacity, and fields of {var}",
                "risk_level": "read_only_zero_stop",
                "requires_user_approval": False,
                "cli_command": _fmt_cmd(ev_cmd),
                "expected_value_en": "Reads current size, capacity, and sample entries with 0ms stop.",
                "expected_value_ko": "프로세스 중단 없이 현재 크기·용량·원소 상태를 확인합니다.",
            })
            break

    # G) Baseline comparison not yet performed -> suggest comparing with latest baseline
    if not (isinstance(baseline_diff, dict) and baseline_diff.get("available")):
        cmd = ["dynamic-state", "diagnose", "-p", str(pid), "--compare-baseline", "latest"]
        if debug_image:
            cmd += ["-d", str(debug_image)]
        cmd += _remote_cli_flags(target)
        _add({
            "id": "compare_with_baseline",
            "priority": "low",
            "category": "baseline",
            "title_en": "Compare against previous baseline snapshot",
            "title_ko": "이전 기준선 스냅샷과 회귀 비교 실행",
            "reason_en": "A single-point snapshot shows current health only; baseline diff detects gradual drift.",
            "reason_ko": "단일 시점 진단은 현재 상태만 보여주므로 이전 스냅샷과 비교해 점진적 드리프트·회귀를 검증할 수 있습니다.",
            "mcp_tool": "runtime_diagnose_process",
            "mcp_args": {**base_diagnose_args, "compare_baseline": "latest"},
            "estimated_cost": "low",
            "expected_evidence": "Regression diff against last compatible baseline snapshot",
            "risk_level": "read_only_zero_stop",
            "requires_user_approval": False,
            "cli_command": _fmt_cmd(cmd),
            "expected_value_en": "Reports RSS, heap, thread, FD, and watchlist deltas against the last saved baseline.",
            "expected_value_ko": "이전 저장 기준선 대비 RSS·힙·스레드·FD·주의 항목 증감을 비교합니다.",
        })

    return actions


# ------------------------------------------------------------------ 4. LLM-Agent Friendly Summary
def build_agent_summary(
    result: Dict[str, Any],
    profile: Optional[Dict[str, Any]] = None,
    coverage: Optional[Dict[str, Any]] = None,
    notable_observations: Optional[List[Dict[str, Any]]] = None,
    baseline_diff: Optional[Dict[str, Any]] = None,
    suggested_actions: Optional[List[Dict[str, Any]]] = None,
    lang: str = "en",
) -> Dict[str, Any]:
    """Build a concise, disclaimer-free summary payload tailored for LLM agents."""
    res = result if isinstance(result, dict) else {}
    prof = profile if isinstance(profile, dict) else (res.get("process_profile") or {})
    cov = coverage if isinstance(coverage, dict) else classify_coverage(res)
    notable = notable_observations if isinstance(notable_observations, list) else []
    actions = suggested_actions if isinstance(suggested_actions, list) else []
    findings = [f for f in (res.get("findings") or []) if isinstance(f, dict)]
    ko = lang == "ko"

    target = res.get("target") if isinstance(res.get("target"), dict) else {}
    who = f"{target.get('process_name') or 'pid'} (pid {target.get('pid')})"
    qual_label = cov["qualifier_label_ko" if ko else "qualifier_label_en"]
    cov_line = cov["one_liner_ko" if ko else "one_liner_en"]

    if findings:
        cats = ", ".join(dict.fromkeys(str(f.get("category")) for f in findings if f.get("category")))
        headline = (
            f"{who}: {qual_label} — {cats} ({cov_line})"
            if ko else f"{who}: {qual_label} — {cats} ({cov_line})"
        )
    else:
        headline = f"{who}: {qual_label} ({cov_line})"

    # Liveness brief
    liv = prof.get("liveness") if isinstance(prof.get("liveness"), dict) else {}
    liveness_brief: Optional[str] = None
    if liv.get("window_s") is not None:
        w = liv["window_s"]
        parts = []
        if liv.get("cpu_time_ms_delta") is not None:
            parts.append(f"CPU +{liv['cpu_time_ms_delta']:.1f}ms")
        if liv.get("total_switches_delta") is not None:
            parts.append(f"ctx_sw +{liv['total_switches_delta']}")
        if liv.get("io_syscalls_delta") is not None:
            parts.append(f"io +{liv['io_syscalls_delta']}")
        if parts:
            liveness_brief = (
                f"{w:.1f}s 관측 구간 활동성({liv.get('status', 'UNKNOWN')}): " + ", ".join(parts)
                if ko else f"{w:.1f}s window activity ({liv.get('status', 'UNKNOWN')}): " + ", ".join(parts)
            )

    state_snapshot = dict(prof.get("summary") or {})
    if liv.get("status"):
        state_snapshot["liveness_status"] = liv["status"]

    notable_highlights = [
        str(n.get("title_ko" if ko else "title_en") or n.get("id"))
        for n in notable[:4]
    ]

    baseline_status = None
    if isinstance(baseline_diff, dict) and baseline_diff.get("available"):
        baseline_status = baseline_diff.get("summary_ko" if ko else "summary_en")

    return {
        "verdict": cov["verdict"],
        "verdict_qualifier": cov["verdict_qualifier"],
        "confidence": res.get("confidence", 0.0),
        "headline": headline,
        "coverage_one_liner": cov_line,
        "state_snapshot": state_snapshot,
        "liveness_brief": liveness_brief,
        "notable_count": len(notable),
        "notable_highlights": notable_highlights,
        "baseline_status": baseline_status,
        "next_actions_count": len(actions),
        "top_action": actions[0] if actions else None,
    }
