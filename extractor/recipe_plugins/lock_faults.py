"""Orphan lock and self-deadlock recipes - registered entirely from this file.

Observation kind ``lock_wait_state``: two zero-stop lock inspections (the same ``inspect_thread_callstacks_and_locks``
the deadlock recipe uses) ``SAMPLE_GAP_S`` apart, reduced to what these two diagnoses need: the glibc
``pthread_mutex_t`` words (state word, owner tid), the live thread ids of the process, and which thread is blocked in
a futex wait on which mutex.  Read-only, no ptrace.

ORPHAN LOCK (RECIPE_ORPHAN_LOCK, category ORPHAN_LOCK).  A ``pthread_mutex_t`` that is locked (state word 1 or 2)
and whose owner tid is not a thread of the process in *both* samples, and whose tid does not exist on the host
either (``/proc/<tid>``): the owner exited while holding it.  A tid that exists outside this process is a
process-shared mutex held by another process, not an orphan.  A robust mutex whose owner died (FUTEX_OWNER_DIED set)
is recoverable by design and is not reported.  Threads waiting for it make it an outage; with no waiter it is a
latent defect (lower confidence).

SELF-DEADLOCK (RECIPE_SELF_DEADLOCK, category SELF_DEADLOCK).  A thread blocked in a futex wait on a
``pthread_mutex_t`` whose owner tid is that same thread, in both samples.  A default (non-recursive) mutex can never
be granted to its own owner, so the thread waits forever.  (The wait-for graph of the deadlock recipe drops
waiter == owner edges on purpose, so a cycle of length one is not reported there; this recipe covers that case.)

Both recipes decide only from these observations: not enough samples, an undecodable owner layout or an owner whose
liveness could not be checked is INSUFFICIENT_EVIDENCE; a complete look that found nothing is CONTRADICTED.
Mutexes the inspector cannot see (no debug info for the variable) are outside the check; this is a declared limit.

Lock contention (waiters present in most samples while the owner keeps running) is a degradation, not a fault: it
is the separate check in ``lock_contention.py`` (severity INFO, verdict DEGRADED).  Both recipes here still
report faults only; a mutex whose owner makes progress is never reported as orphaned or deadlocked.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Tuple

from ..diagnostic_recipes import (
    DOMAIN_CONCURRENCY,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipe,
    RecipeEvaluationResult,
    register_recipe,
)
from ..runtime_evidence_provider import register_observation_collector

RECIPE_ORPHAN_LOCK = "RECIPE_ORPHAN_LOCK"
RECIPE_SELF_DEADLOCK = "RECIPE_SELF_DEADLOCK"
CATEGORY_ORPHAN_LOCK = "ORPHAN_LOCK"
CATEGORY_SELF_DEADLOCK = "SELF_DEADLOCK"
OBS_LOCK_WAIT_STATE = "lock_wait_state"

SAMPLES = 2
SAMPLE_GAP_S = 0.15
CACHE_TTL_S = 3.0               # the two recipes share one observation when they run back to back
LOCKED_WORDS = (1, 2)           # glibc normal mutex: 1 locked, 2 locked with waiters
MUTEX_TYPE = "pthread_mutex_t"


# ---------------------------------------------------------------------------------------------- collection
def _is_mutex(lock: Dict[str, Any]) -> bool:
    """Only a glibc pthread_mutex_t has the word layout these rules read (sem_t, rwlock, custom structs do not).
    Decided by the layout the inspector derived from DWARF (``glibc_mutex_layout``: pthread_mutex_t, or std::mutex
    & co. wrapping one at offset 0), not by the type name; the name is a fallback for records without the field."""
    layout = lock.get("glibc_mutex_layout")
    if layout is not None:
        return layout is True
    return MUTEX_TYPE in str(lock.get("type_name") or lock.get("type") or "")


def _user_frames(thread: Dict[str, Any], limit: int = 4) -> List[Dict[str, str]]:
    out = []
    for f in thread.get("callstack") or []:
        if isinstance(f, dict) and f.get("resolution_source") == "DWARF_SUBPROGRAM" and f.get("function_name"):
            out.append({"function_name": str(f["function_name"]), "source_location": str(f.get("source_location") or "")})
        if len(out) >= limit:
            break
    return out


def _switches(adapter: Any, pid: int) -> Dict[str, int]:
    """Voluntary + involuntary context switches per thread (one /proc scan); {} when the adapter cannot provide them."""
    try:
        recs = adapter.read_thread_samples(pid, {}) if adapter is not None else None
        return {str(r["tid"]): int(r.get("voluntary_ctxt_switches") or 0) + int(r.get("nonvoluntary_ctxt_switches") or 0)
                for r in recs or [] if isinstance(r, dict) and r.get("tid") is not None}
    except Exception:  # noqa: BLE001
        return {}


def _digest(info: Dict[str, Any], t_s: float, switches: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """One inspection reduced to the fields the rules read.  Key names avoid the subject keys of the engine on
    purpose: the findings' subjects are taken from ``orphan_locks`` / ``self_waits`` only."""
    threads = [t for t in info.get("threads") or [] if isinstance(t, dict) and t.get("tid") is not None]
    locks = []
    for l in info.get("locks") or []:
        if not isinstance(l, dict):
            continue
        locks.append({"lock_label": l.get("name"), "address": l.get("runtime_address"), "type": l.get("type_name"),
                      "glibc_mutex_layout": l.get("glibc_mutex_layout"),
                      "state_word": l.get("lock_state_word"), "recursion_count": l.get("recursion_count"),
                      "owner_id": l.get("owner_tid"), "waiter_ids": [w for w in l.get("waiting_tids") or []]})
    waits, frames = [], {}
    for t in threads:
        w = t.get("waiting_on_lock")
        if isinstance(w, dict) and t.get("syscall") == "futex":
            waits.append({"thread_id": t["tid"], "thread_label": t.get("name"), "lock_label": w.get("lock_name"),
                          "address": w.get("lock_address"), "owner_id": w.get("held_by_tid")})
            frames[t["tid"]] = _user_frames(t)
    return {"t_s": round(t_s, 3), "thread_ids": [t["tid"] for t in threads], "thread_labels": {str(t["tid"]): t.get("name") for t in threads},
            "locks": locks, "waits": waits, "wait_frames": {str(k): v for k, v in frames.items()},
            "switches": {str(w["thread_id"]): (switches or {}).get(str(w["thread_id"])) for w in waits
                         if (switches or {}).get(str(w["thread_id"])) is not None},
            "status": info.get("status"), "lock_owner_status": info.get("lock_owner_status"),
            "limitations": [str(x) for x in (info.get("limitations") or [])][:3]}


def _tid_exists(adapter: Any, pid: int, tid: int) -> Optional[bool]:
    """Does thread/process ``tid`` exist on the host?  None when that could not be checked."""
    try:
        if adapter is None or not getattr(adapter, "is_remote", lambda: False)():
            return os.path.isdir(f"/proc/{int(tid)}")
        run = getattr(adapter, "run_ssh", None)
        if not callable(run):
            return None
        rc, _, _ = run(f"[ -d /proc/{int(tid)} ]")
        return True if rc == 0 else (False if rc == 1 else None)
    except Exception:  # noqa: BLE001
        return None


def analyse(samples: List[Dict[str, Any]], exists: Any) -> Dict[str, Any]:
    """Orphan locks and self waits that hold in EVERY sample.  ``exists(tid) -> bool | None`` (host-wide)."""
    out: Dict[str, Any] = {"orphan_locks": [], "self_waits": [], "unverified_owner_tids": [], "owner_outside_process": []}
    if len(samples) < SAMPLES:
        return out
    last = samples[-1]
    # --- orphan: same lock, same owner, owner not a thread of the process in any sample
    for l in last["locks"]:
        owner = l.get("owner_id")
        if not (_is_mutex(l) and isinstance(owner, int) and owner > 0 and l.get("state_word") in LOCKED_WORDS):
            continue
        same = all(any(x.get("address") == l.get("address") and x.get("owner_id") == owner and x.get("state_word") in LOCKED_WORDS
                       for x in s["locks"]) and owner not in s["thread_ids"] for s in samples)
        if not same:
            continue
        alive = exists(owner)
        if alive is None:
            out["unverified_owner_tids"].append(owner)
            continue
        if alive:
            out["owner_outside_process"].append({"lock_name": l.get("lock_label"), "owner_tid": owner})
            continue
        waiters = []
        for w in last["waits"]:
            if w.get("address") == l.get("address") and w.get("owner_id") == owner:
                frames = last["wait_frames"].get(str(w["thread_id"])) or []
                waiters.append({"waiter_tid": w["thread_id"], "waiter_name": w.get("thread_label"),
                                **({"source_location": frames[0]["source_location"]} if frames and frames[0]["source_location"] else {})})
        out["orphan_locks"].append({"lock_name": l.get("lock_label"), "lock_address": l.get("address"), "owner_tid": owner,
                                    "owner_alive": False, "lock_state_word": l.get("state_word"), "waiters": waiters,
                                    "samples_seen": len(samples)})
    # --- self wait: a thread blocked in futex on a mutex it owns, in every sample
    for w in last["waits"]:
        tid = w["thread_id"]
        lock = next((l for l in last["locks"] if l.get("address") == w.get("address")), None)
        if lock is None or not _is_mutex(lock) or w.get("owner_id") != tid:
            continue
        if not all(any(x["thread_id"] == tid and x.get("address") == w.get("address") and x.get("owner_id") == tid
                       for x in s["waits"]) for s in samples):
            continue
        # A thread that is really stuck on its own lock never gets scheduled: no context switch between the samples.
        # A thread that keeps being woken (a busy lock handed on between threads) shows up as its own owner in a
        # sample only because the owner word was read a moment after its futex wait ended: it is not stuck.
        sw = [(s.get("switches") or {}).get(str(tid)) for s in samples]
        if all(v is not None for v in sw) and len(set(sw)) > 1:
            continue
        frames = last["wait_frames"].get(str(tid)) or []
        item: Dict[str, Any] = {"lock_name": lock.get("lock_label"), "lock_address": lock.get("address"), "waiter_tid": tid,
                                "waiter_name": w.get("thread_label"), "samples_seen": len(samples),
                                "call_path": [{"function_name": f["function_name"], "source_location": f["source_location"]}
                                              for f in frames if f["source_location"]]}
        if frames and frames[0]["source_location"]:
            item["source_location"] = frames[0]["source_location"]
        out["self_waits"].append(item)
    return out


def collect_lock_wait_state(provider: Any, ctx: Dict[str, Any]) -> None:
    pid = ctx["pid"]
    cached = getattr(provider, "_lock_wait_state_cache", None)
    if cached and cached[0] == pid and time.monotonic() - cached[1] < CACHE_TTL_S:
        ctx["observation_data"][OBS_LOCK_WAIT_STATE] = cached[2]
        return None
    adapter = getattr(provider, "adapter", None)
    samples: List[Dict[str, Any]] = []
    t0 = time.monotonic()
    err: Optional[str] = None
    for i in range(SAMPLES):
        try:
            info = provider._inspect_locks(pid, ctx.get("companion_elf"))
            if not isinstance(info, dict) or info.get("error") or info.get("success") is False:
                err = str((info or {}).get("error") if isinstance(info, dict) else "unexpected result")
                break
            samples.append(_digest(info, time.monotonic() - t0, _switches(adapter, pid)))
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
            break
        if i + 1 < SAMPLES:
            time.sleep(SAMPLE_GAP_S)
    obs: Dict[str, Any] = {"samples": samples}
    if err:
        obs["unavailable"] = f"lock inspection failed: {err}"
    elif samples:
        statuses = {s.get("lock_owner_status") for s in samples}
        obs["lock_owner_status"] = "SUPPORTED" if statuses == {"SUPPORTED"} else sorted(str(x) for x in statuses)[0]
        obs.update(analyse(samples, lambda tid: _tid_exists(adapter, pid, tid)))
    try:
        provider._lock_wait_state_cache = (pid, time.monotonic(), obs)
    except Exception:  # noqa: BLE001
        pass
    ctx["observation_data"][OBS_LOCK_WAIT_STATE] = obs
    return None


# ---------------------------------------------------------------------------------------------- rules
def _incomplete(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """INSUFFICIENT_EVIDENCE when the two inspections cannot support a decision either way."""
    lw = data.get(OBS_LOCK_WAIT_STATE) or {}
    samples = lw.get("samples") or []
    why = None
    if lw.get("unavailable"):
        why = lw["unavailable"]
    elif len(samples) < SAMPLES:
        why = f"fewer than {SAMPLES} lock inspections"
    elif lw.get("lock_owner_status") != "SUPPORTED":
        why = f"mutex owners cannot be decoded on this target ({lw.get('lock_owner_status')})"
    elif not any(s.get("thread_ids") for s in samples):
        why = "the thread list of the process could not be read"
    if why:
        return RecipeEvaluationResult(
            recipe_id=recipe.recipe_id, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.0,
            confidence_basis=f"lock state not observed: {why}", missing_evidence=["lock_wait_state"],
            limitations=list(recipe.limitations), details={"reason": why})
    return None


def _n_locks(lw: Dict[str, Any]) -> int:
    return max((sum(1 for l in s.get("locks") or [] if _is_mutex(l)) for s in lw.get("samples") or []), default=0)


def _nothing_inspected(recipe: DiagnosticRecipe, lw: Dict[str, Any]) -> RecipeEvaluationResult:
    """No mutex with the glibc layout was found (debug info, struct members, futex waits): the question was not
    checked.  That is "nothing inspected", not "every mutex is fine" (HEALTHY lists it as a scope limit)."""
    txt = (f"no pthread mutex found to inspect in {len(lw.get('samples') or [])} samples (globals, struct members, "
           "futex waits): nothing inspected")
    return RecipeEvaluationResult(
        recipe_id=recipe.recipe_id, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.3, confidence_basis=txt,
        missing_evidence=["a pthread mutex to inspect"], limitations=list(recipe.limitations) + [txt],
        details={"mutexes_inspected": 0, "nothing_inspected": True})


def no_mutex_to_inspect(observation: Dict[str, Any]) -> bool:
    """The lock-wait observation is complete and holds no mutex with the glibc layout (used by the HEALTHY rule)."""
    lw = observation.get(OBS_LOCK_WAIT_STATE) if isinstance(observation, dict) else None
    if not isinstance(lw, dict) or lw.get("unavailable") or len(lw.get("samples") or []) < SAMPLES:
        return False
    if lw.get("lock_owner_status") != "SUPPORTED" or not any(s.get("thread_ids") for s in lw["samples"]):
        return False
    return _n_locks(lw) == 0 and not any(s.get("waits") for s in lw["samples"])


def orphan_lock_rule(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    bad = _incomplete(recipe, data)
    if bad:
        return bad
    lw = data[OBS_LOCK_WAIT_STATE]
    orphans = [o for o in lw.get("orphan_locks") or [] if isinstance(o, dict)]
    rid = recipe.recipe_id
    if orphans:
        facts, waiting = [], 0
        for o in orphans:
            w = [x for x in o.get("waiters") or [] if isinstance(x, dict)]
            waiting += len(w)
            facts.append(f"mutex '{o.get('lock_name')}' is locked by tid {o.get('owner_tid')}, which is not a thread of the process "
                         f"(no /proc/{o.get('owner_tid')}), in {o.get('samples_seen')} samples"
                         + (f"; {len(w)} thread(s) wait for it: " + ", ".join(f"'{x.get('waiter_name')}' ({x.get('waiter_tid')})" for x in w[:6]) if w
                            else "; no thread waits for it"))
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.9 if waiting else 0.7,
            confidence_basis="A mutex is held by a thread that no longer exists: " + "; ".join(facts[:3]),
            supporting_facts=facts,
            recommended_action="Find the thread that exits while holding the mutex (return/pthread_exit/cancellation inside the "
                               "critical section without unlock); use RAII/cleanup handlers or a robust mutex.",
            details={"orphan_locks": orphans, "waiting_threads": waiting, "finding_category": CATEGORY_ORPHAN_LOCK})
    if lw.get("unverified_owner_tids"):
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.2,
            confidence_basis="a locked mutex has an owner outside the process thread list and its existence on the host could not be checked: "
                             + ", ".join(map(str, lw["unverified_owner_tids"][:5])),
            missing_evidence=["owner_tid_liveness"], limitations=list(recipe.limitations), details={"lock_wait_state": lw})
    n = _n_locks(lw)
    if n == 0:
        return _nothing_inspected(recipe, lw)
    out_of = lw.get("owner_outside_process") or []
    txt = (f"{n} mutex(es) inspected in {len(lw['samples'])} samples: every locked one is owned by a live thread"
           + (f"; {len(out_of)} is owned by a thread outside this process (process-shared mutex, not an orphan)" if out_of else ""))
    return RecipeEvaluationResult(
        recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.8, confidence_basis=txt, contradicting_facts=[txt],
        recommended_action="No orphaned mutex in the observed window.", details={"mutexes_inspected": n})


def self_deadlock_rule(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    bad = _incomplete(recipe, data)
    if bad:
        return bad
    lw = data[OBS_LOCK_WAIT_STATE]
    selfw = [o for o in lw.get("self_waits") or [] if isinstance(o, dict)]
    rid = recipe.recipe_id
    if selfw:
        facts = [f"thread '{o.get('waiter_name')}' (tid {o.get('waiter_tid')}) waits for mutex '{o.get('lock_name')}', which it holds itself "
                 f"(same wait in {o.get('samples_seen')} samples)" + (f" at {o['source_location']}" if o.get("source_location") else "")
                 for o in selfw]
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.92,
            confidence_basis="A thread is blocked on a non-recursive mutex it already owns: " + "; ".join(facts[:3]),
            supporting_facts=facts,
            recommended_action="The thread locks the same mutex twice (look at the call path of the second lock): restructure so the "
                               "inner function does not lock again, or use a recursive mutex deliberately.",
            details={"self_waits": selfw, "finding_category": CATEGORY_SELF_DEADLOCK})
    n = _n_locks(lw)
    if n == 0:
        return _nothing_inspected(recipe, lw)
    txt = f"{n} mutex(es) inspected in {len(lw['samples'])} samples: no thread waits for a mutex it owns itself"
    return RecipeEvaluationResult(
        recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.8, confidence_basis=txt, contradicting_facts=[txt],
        recommended_action="No self-deadlock in the observed window.", details={"mutexes_inspected": n})


def _recipe(rid: str, name: str, category: str, rule: Any, analysis: str, support: str, contra: str) -> None:
    register_recipe(DiagnosticRecipe(
        recipe_id=rid, version="1.0.0", name=name, domain=DOMAIN_CONCURRENCY,
        applicable_problem_categories=[category], required_prerequisites=[],
        evidence_sources=["pthread_mutex_t words", "/proc/<pid>/task", "/proc/<tid>/syscall"],
        collection_steps=[{"step": 1, "action": "inspect_mutex_owners_and_waiters",
                           "purpose": f"{SAMPLES} lock inspections, {SAMPLE_GAP_S} s apart"}],
        analysis_rules=[analysis], thresholds_and_conditions={"samples": SAMPLES, "sample_gap_s": SAMPLE_GAP_S},
        supporting_evidence_criteria=[support], contradicting_evidence_criteria=[contra],
        verification_procedure="Re-inspect the mutex words later: the owner stays the same tid and the waits do not end.",
        stop_conditions=["mutex owner layout not decodable"],
        limitations=["only pthread_mutex_t variables the inspector discovers (debug info or futex address) are examined",
                     "glibc pthread_mutex_t layout (x86-64, ARM64)"],
        output_structure={"orphan_locks": "list", "self_waits": "list"},
        observations=(OBS_LOCK_WAIT_STATE,), rule=rule, requires_lock_owner=True,
    ), baseline=True, category=category)


register_observation_collector(OBS_LOCK_WAIT_STATE, collect_lock_wait_state)
_recipe(RECIPE_ORPHAN_LOCK, "Orphan Lock (owner thread exited)", CATEGORY_ORPHAN_LOCK, orphan_lock_rule,
        "A locked pthread_mutex_t whose owner tid is not a thread of the process (and not a process on the host) in both samples is orphaned.",
        "locked mutex, owner tid gone, waiters blocked on it", "every locked mutex is owned by a live thread")
_recipe(RECIPE_SELF_DEADLOCK, "Self-Deadlock (thread waits for its own mutex)", CATEGORY_SELF_DEADLOCK, self_deadlock_rule,
        "A thread blocked in futex wait on a pthread_mutex_t whose owner is that thread, in both samples, is a self-deadlock.",
        "waiter tid == owner tid on a non-recursive mutex", "no thread waits for a mutex it owns")


# ---------------------------------------------------------------------------------------------- presentation
_TXT = {
    "orphan": ("Mutex {lock} is locked by tid {owner}, but no thread of the process has that id and /proc/{owner} does not exist: "
               "the thread that took the lock exited without releasing it.",
               "뮤텍스 {lock}은(는) tid {owner}이(가) 잡고 있지만, 프로세스에 그 번호의 스레드가 없고 /proc/{owner}도 없습니다. "
               "락을 잡은 스레드가 해제하지 않고 종료했습니다."),
    "orphan_w": ("{n} thread(s) wait for it and can never continue: {who}.",
                 "{n}개 스레드가 이 락을 기다리며 영원히 진행하지 못합니다: {who}."),
    "orphan_n": ("No thread waits for it yet; the next thread that asks for it will block forever.",
                 "아직 기다리는 스레드는 없지만, 다음에 이 락을 요청하는 스레드는 영원히 대기합니다."),
    "orphan_c": ("Which code path let the thread exit while holding the lock was not observed; look for a return, pthread_exit or "
                 "cancellation inside the critical section of {lock}.",
                 "어느 코드 경로가 락을 잡은 채 스레드를 끝냈는지는 관측되지 않았습니다. {lock}의 임계 구역 안의 return, "
                 "pthread_exit, 취소를 찾으세요."),
    "self": ("Thread {thr} waits for mutex {lock}, which it holds itself (the same wait in {n} samples)",
             "스레드 {thr}이(가) 자신이 이미 잡고 있는 뮤텍스 {lock}을(를) 기다립니다 (같은 대기가 {n}번의 샘플에서 확인됨)"),
    "self_at": (" at {loc}.", " 위치: {loc}."),
    "self_c": ("A normal mutex cannot be granted to its own owner, so this thread never continues. Check the second lock call "
               "on the path shown; a recursive mutex or a lock-free inner helper avoids it.",
               "일반 뮤텍스는 소유자 자신에게 다시 줄 수 없으므로 이 스레드는 영원히 진행하지 못합니다. 보이는 경로의 두 번째 "
               "lock 호출을 확인하세요. 재귀 뮤텍스나 락을 잡지 않는 내부 함수로 피할 수 있습니다."),
    "o_title": ("How the lock became orphaned", "락이 주인 없이 남게 된 순서"),
    "s_title": ("How the thread blocked itself", "스레드가 스스로 멈추게 된 순서"),
    "thread": ("thread", "스레드"), "lock": ("lock", "락"), "gone": ("exited", "종료됨"),
    "taken": ("lock ✔ taken", "lock ✔ 획득"), "again": ("lock ✖ asks again", "lock ✖ 다시 요청"),
    "waits": ("lock ✖ waits", "lock ✖ 대기"), "exit": ("thread exits", "스레드 종료"),
    "held": ("held by {t}", "{t} 소유"), "blocked": ("BLOCKED", "대기 중"),
    "o_s1": ("{t} takes lock {l}", "{t}: 락 {l} 획득"),
    "o_s1n": ("Seen as the recorded owner of this lock. When and where it took the lock was not observed.",
              "이 락의 소유자로 기록되어 있음. 언제 어디서 잡았는지는 관측되지 않았습니다."),
    "o_s2": ("{t} is gone: tid {tid} is not a thread of the process and /proc/{tid} does not exist; the lock is still marked as held",
             "{t} 종료: tid {tid}은(는) 프로세스의 스레드가 아니고 /proc/{tid}도 없음. 락은 여전히 잡힌 상태"),
    "o_s3": ("{t} asks for lock {l}, which nobody can release, and blocks", "{t}: 아무도 해제할 수 없는 락 {l}을(를) 요청하고 대기"),
    "o_end": ("ORPHANED LOCK", "주인 없는 락"),
    "o_note": ("The order of the first two steps follows from the evidence: a thread that does not exist now cannot have exited "
               "before it took the lock. The moment of exit was not observed.",
               "처음 두 단계의 순서는 증거에서 추론한 것입니다. 지금 없는 스레드가 락을 잡은 뒤 종료했다는 점만 알 수 있고, "
               "종료 시점은 관측되지 않았습니다."),
    "s_s1": ("{t} takes lock {l}", "{t}: 락 {l} 획득"),
    "s_s2": ("{t} asks for lock {l} again while holding it, and blocks", "{t}: 이미 잡고 있는 락 {l}을(를) 다시 요청하고 대기"),
    "s_at": ("Stopped at {loc}", "{loc} 에서 멈춤"),
    "s_end": ("SELF-DEADLOCK", "자기 교착"),
    "s_note": ("The first lock call was not observed; it follows from the lock being owned by this thread now.",
               "첫 번째 lock 호출은 관측되지 않았습니다. 지금 이 스레드가 락을 소유하고 있다는 사실에서 추론한 것입니다."),
    "obs_win": ("Same state in {n} samples, {win} s apart.", "{n}번의 샘플에서 같은 상태 ({win}초 간격)."),
}


def _lw(report: Optional[Dict[str, Any]], rid: str) -> Dict[str, Any]:
    checks = ((report or {}).get("section_d_detailed_inspection_results") or {}).get("checks") or []
    for c in checks:
        if isinstance(c, dict) and c.get("recipe_id") == rid:
            lw = (c.get("actual_observations") or {}).get(OBS_LOCK_WAIT_STATE)
            if isinstance(lw, dict):
                return lw
    return {}


def _orphan_facts(i: int, lw: Dict[str, Any], wrap: Any) -> List[str]:
    out: List[str] = []
    for o in [x for x in lw.get("orphan_locks") or [] if isinstance(x, dict)]:
        out.append(_TXT["orphan"][i].format(lock=wrap(o.get("lock_name")), owner=o.get("owner_tid")))
        w = [x for x in o.get("waiters") or [] if isinstance(x, dict)]
        if w:
            out.append(_TXT["orphan_w"][i].format(n=len(w), who=", ".join(f"{wrap(x.get('waiter_name'))} (tid {x.get('waiter_tid')})" for x in w[:6])))
        else:
            out.append(_TXT["orphan_n"][i])
        out.append(_TXT["orphan_c"][i].format(lock=wrap(o.get("lock_name"))))
    return out


def _self_facts(i: int, lw: Dict[str, Any], wrap: Any) -> List[str]:
    out: List[str] = []
    for o in [x for x in lw.get("self_waits") or [] if isinstance(x, dict)]:
        s = _TXT["self"][i].format(thr=wrap(o.get("waiter_name") or o.get("waiter_tid")), lock=wrap(o.get("lock_name")), n=o.get("samples_seen"))
        s = s.rstrip(".") + (_TXT["self_at"][i].format(loc=wrap(o["source_location"])) if o.get("source_location") else ".")
        out += [s, _TXT["self_c"][i]]
    return out


def _wrap_md(x: Any) -> str:
    return "`" + str(x).replace("`", "'") + "`"


def orphan_finding_text(ctx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {"lines": _orphan_facts(ctx.i, _lw(report, RECIPE_ORPHAN_LOCK), _wrap_md)}


def self_finding_text(ctx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {"lines": _self_facts(ctx.i, _lw(report, RECIPE_SELF_DEADLOCK), _wrap_md)}


def _facts_html(lines_fn: Any, i: int, lw: Dict[str, Any]) -> str:
    """Sentences carry target-controlled names: escape the sentence, then mark the names as code."""
    from ..report_visuals import code, esc, facts_list
    marks: List[str] = []

    def wrap(x: Any) -> str:
        marks.append(str(x))
        return f"\x00{len(marks) - 1}\x00"

    items = []
    for line in lines_fn(i, lw, wrap):
        h = esc(line)
        for k, m in enumerate(marks):
            h = h.replace(f"\x00{k}\x00", code(m))
        items.append(h)
    return facts_list(items)


def _sequence(lx: Any, uid: str, title: str, cols: List[Tuple[str, str, str]], steps: List[Dict[str, Any]], banner: str,
              note: str, sub_obs: str) -> str:
    """Sequence diagram in the style of the deadlock picture.  ``cols``: (kind thread|lock, label, sub label);
    ``steps``: {kind acq|wait|exit, src, dst, label, text_html, chip, sub_html, ...}; text values are escaped here."""
    from ..report_visuals import _THREAD_COLORS, _legend, _sa, _stepper_controls, chip, esc
    i = lx.i
    col_w, left, top, row_h = 150, 85, 64, 58
    x = [left + k * col_w for k in range(len(cols))]
    n_steps = len(steps) + 1
    width = left * 2 + (len(cols) - 1) * col_w
    y_of = lambda k: top + 34 + (k - 1) * row_h  # noqa: E731
    bottom = y_of(n_steps) + 44
    tcolor: Dict[int, str] = {}
    for k, (kind, _, _) in enumerate(cols):
        if kind == "thread":
            tcolor[k] = _THREAD_COLORS[len(tcolor) % len(_THREAD_COLORS)]
    s: List[str] = [f'<svg viewBox="0 0 {width} {bottom + 8}" width="{width}" role="img" aria-label="{esc(title)}">',
                    '<defs><marker id="dsv-ah" markerWidth="9" markerHeight="8" refX="8" refY="4" orient="auto">'
                    '<path d="M0,0 L9,4 L0,8 z" fill="context-stroke"/></marker></defs>']
    for k, (kind, label, sub) in enumerate(cols):
        cx = x[k]
        s.append(f'<line class="dsv-life" x1="{cx}" y1="{top}" x2="{cx}" y2="{bottom - 36}"/>')
        if kind == "thread":
            s.append(f'<rect x="{cx - 64}" y="14" width="128" height="{top - 22}" rx="8" fill="{tcolor[k]}"/>'
                     f'<text class="dsv-t-on" x="{cx}" y="32" text-anchor="middle" font-size="13">{esc(label[:17])}</text>'
                     f'<text class="dsv-t-on" x="{cx}" y="48" text-anchor="middle" font-size="10" font-weight="400">{esc(sub[:22])}</text>')
        else:
            s.append(f'<rect class="dsv-lockbox" x="{cx - 56}" y="18" width="112" height="{top - 30}" rx="3"/>'
                     f'<text x="{cx}" y="34" text-anchor="middle" font-size="13" font-weight="700">{esc(label[:15])}</text>'
                     f'<text class="dsv-t-mute" x="{cx}" y="47" text-anchor="middle" font-size="10">{esc(sub)}</text>')
    li: List[str] = []
    for k, st in enumerate(steps, 1):
        y, x1, x2 = y_of(k), x[st["src"]], x[st.get("dst", st["src"])]
        d = 1 if x2 > x1 else -1
        if st["kind"] == "acq":
            c = tcolor[st["src"]]
            s.append(f'<g{_sa(k)}><line class="dsv-arrow" x1="{x1}" y1="{y}" x2="{x2 - d * 7}" y2="{y}" stroke="{c}" style="stroke:{c}" '
                     f'marker-end="url(#dsv-ah)"/><text x="{(x1 + x2) / 2}" y="{y - 8}" text-anchor="middle" font-size="11">{esc(_TXT["taken"][i])}</text>'
                     f'<rect x="{x2 - 6}" y="{y}" width="12" height="{bottom - 36 - y}" fill="{c}" opacity="0.85"/>'
                     f'<text class="dsv-t-mute" x="{x2 + 10}" y="{y + 16}" font-size="10">{esc(_TXT["held"][i].format(t=st["who"])[:22])}</text></g>')
        elif st["kind"] == "wait":
            s.append(f'<g{_sa(k)}><line class="dsv-arrow-bad" x1="{x1}" y1="{y}" x2="{x2 - d * 14}" y2="{y}" marker-end="url(#dsv-ah)"/>'
                     f'<text class="dsv-t-bad" x="{(x1 + x2) / 2}" y="{y - 8}" text-anchor="middle" font-size="11">{esc(st["arrow"])}</text>'
                     f'<line class="dsv-blocked" x1="{x1}" y1="{y}" x2="{x1}" y2="{bottom - 36}"/>'
                     f'<text class="dsv-t-bad" x="{x1 - d * 8}" y="{y + 18}" text-anchor="{"end" if d > 0 else "start"}" font-size="10">'
                     f'{esc(_TXT["blocked"][i])}</text></g>')
        else:  # exit: the lifeline of the thread ends here
            s.append(f'<g{_sa(k)}><line class="dsv-arrow-bad" x1="{x1 - 14}" y1="{y - 10}" x2="{x1 + 14}" y2="{y + 10}"/>'
                     f'<line class="dsv-arrow-bad" x1="{x1 + 14}" y1="{y - 10}" x2="{x1 - 14}" y2="{y + 10}"/>'
                     f'<text class="dsv-t-bad" x="{x1}" y="{y + 28}" text-anchor="middle" font-size="11">{esc(_TXT["gone"][i])}</text></g>')
        li.append(f'<li{_sa(k)}>{st["text_html"]} {chip(lx, st["chip"])}' + (f'<span class="dsv-sub">{st["sub_html"]}</span>' if st.get("sub_html") else "") + "</li>")
    k = n_steps
    yb = bottom - 30
    s.append(f'<g{_sa(k)}><rect class="dsv-banner" x="12" y="{yb}" width="{width - 24}" height="28" rx="6"/>'
             f'<text class="dsv-t-bad" x="{width / 2}" y="{yb + 19}" text-anchor="middle" font-size="13">{esc(banner[:90])}</text></g></svg>')
    li.append(f'<li{_sa(k)}>{esc(banner)} {chip(lx, "obs")}' + (f'<span class="dsv-sub">{esc(sub_obs)}</span>' if sub_obs else "") + "</li>")
    return (f'<h4>{esc(title)}</h4><div class="dsv-stepper" data-steps="{n_steps}">{_stepper_controls(lx, uid, n_steps)}'
            f'<div class="dsv-seq"><div class="dsv-svgbox">{"".join(s)}</div><ol class="dsv-steps">{"".join(li)}</ol></div></div>'
            f'<p class="dsv-note">{esc(note)}</p>{_legend(lx, "obs", "rec")}')


def _window(lw: Dict[str, Any], i: int) -> str:
    ss = [s for s in lw.get("samples") or [] if isinstance(s, dict) and isinstance(s.get("t_s"), (int, float))]
    if len(ss) < 2:
        return ""
    return _TXT["obs_win"][i].format(n=len(ss), win=f'{ss[-1]["t_s"] - ss[0]["t_s"]:.2f}')


def orphan_finding_viz(lx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]], uid: str = "0") -> str:
    from ..report_visuals import code, esc, thread_strip
    lw = _lw(report, RECIPE_ORPHAN_LOCK)
    orphans = [o for o in lw.get("orphan_locks") or [] if isinstance(o, dict) and o.get("lock_name") is not None]
    if not orphans:
        return ""
    i, o = lx.i, orphans[0]
    waiters = [w for w in o.get("waiters") or [] if isinstance(w, dict)][:4]
    own = f"tid {o.get('owner_tid')}"
    cols = [("thread", own, _TXT["gone"][i]), ("lock", str(o["lock_name"]), _TXT["lock"][i])]
    cols += [("thread", str(w.get("waiter_name") or f"tid {w.get('waiter_tid')}"), f"{_TXT['thread'][i]} · tid {w.get('waiter_tid')}") for w in waiters]
    steps: List[Dict[str, Any]] = [
        {"kind": "acq", "src": 0, "dst": 1, "who": own, "chip": "rec",
         "text_html": esc(_TXT["o_s1"][i].replace("{t}", "\x00").replace("{l}", "\x01")).replace("\x00", code(own)).replace("\x01", code(o["lock_name"])),
         "sub_html": esc(_TXT["o_s1n"][i])},
        {"kind": "exit", "src": 0, "chip": "obs",
         "text_html": esc(_TXT["o_s2"][i].replace("{t}", "\x00").replace("{tid}", str(o.get("owner_tid")))).replace("\x00", code(own))}]
    for k, w in enumerate(waiters):
        name = str(w.get("waiter_name") or f"tid {w.get('waiter_tid')}")
        sub = (esc(_TXT["s_at"][i].replace("{loc}", "\x00")).replace("\x00", code(w["source_location"]))
               if w.get("source_location") else "")
        steps.append({"kind": "wait", "src": 2 + k, "dst": 1, "arrow": _TXT["waits"][i], "chip": "obs", "sub_html": sub,
                      "text_html": esc(_TXT["o_s3"][i].replace("{t}", "\x00").replace("{l}", "\x01")).replace("\x00", code(name)).replace("\x01", code(o["lock_name"]))})
    html = _sequence(lx, uid, _TXT["o_title"][i], cols, steps, _TXT["o_end"][i], _TXT["o_note"][i], _window(lw, i))
    html += _facts_html(_orphan_facts, i, lw)
    rows = _rows(report, RECIPE_ORPHAN_LOCK)
    return html + thread_strip(lx, finding, report, [w.get("waiter_tid") for w in waiters]) if rows else html


def self_finding_viz(lx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]], uid: str = "0") -> str:
    from ..report_visuals import code, esc
    lw = _lw(report, RECIPE_SELF_DEADLOCK)
    selfw = [o for o in lw.get("self_waits") or [] if isinstance(o, dict) and o.get("lock_name") is not None]
    if not selfw:
        return ""
    i, o = lx.i, selfw[0]
    name = str(o.get("waiter_name") or f"tid {o.get('waiter_tid')}")
    cols = [("thread", name, f"{_TXT['thread'][i]} · tid {o.get('waiter_tid')}"), ("lock", str(o["lock_name"]), _TXT["lock"][i])]
    sub = ""
    if o.get("source_location"):
        sub = esc(_TXT["s_at"][i].replace("{loc}", "\x00")).replace("\x00", code(o["source_location"]))
    path = [p for p in o.get("call_path") or [] if isinstance(p, dict) and p.get("function_name")]
    if len(path) > 1:
        sub += " " + " ← ".join(code(p["function_name"]) for p in path)
    steps = [
        {"kind": "acq", "src": 0, "dst": 1, "who": name, "chip": "rec",
         "text_html": esc(_TXT["s_s1"][i].replace("{t}", "\x00").replace("{l}", "\x01")).replace("\x00", code(name)).replace("\x01", code(o["lock_name"])),
         "sub_html": esc(_TXT["o_s1n"][i])},
        {"kind": "wait", "src": 0, "dst": 1, "arrow": _TXT["again"][i], "chip": "obs", "sub_html": sub,
         "text_html": esc(_TXT["s_s2"][i].replace("{t}", "\x00").replace("{l}", "\x01")).replace("\x00", code(name)).replace("\x01", code(o["lock_name"]))}]
    html = _sequence(lx, uid, _TXT["s_title"][i], cols, steps, _TXT["s_end"][i], _TXT["s_note"][i], _window(lw, i))
    return html + _facts_html(_self_facts, i, lw)


def _rows(report: Optional[Dict[str, Any]], rid: str) -> bool:
    """Is there a per-sample thread table in the evidence of this finding (the thread-sampling recipes carry it)?"""
    from ..report_visuals import _thread_rows
    try:
        return bool(_thread_rows(report, [rid]))
    except Exception:  # noqa: BLE001
        return False


def _register_presentation() -> None:
    from ..report_registry import register_category, register_finding_text, register_finding_viz, register_recipe_label
    register_category(CATEGORY_ORPHAN_LOCK, "orphaned lock (owner thread exited)", "주인 없는 락 (소유 스레드 종료)")
    register_category(CATEGORY_SELF_DEADLOCK, "self-deadlock (thread waits for its own lock)", "자기 교착 (스레드가 자기 락을 기다림)")
    register_recipe_label(RECIPE_ORPHAN_LOCK, "CONCURRENCY", "Orphaned lock", "주인 없는 락",
                          "a mutex still held by a thread that has exited", "이미 종료한 스레드가 잡은 채로 남은 뮤텍스")
    register_recipe_label(RECIPE_SELF_DEADLOCK, "CONCURRENCY", "Self-deadlock", "자기 교착",
                          "a thread blocked on a mutex it holds itself", "자신이 이미 잡고 있는 뮤텍스를 기다리며 멈춘 스레드")
    register_finding_text(CATEGORY_ORPHAN_LOCK, orphan_finding_text)
    register_finding_text(CATEGORY_SELF_DEADLOCK, self_finding_text)
    register_finding_viz(CATEGORY_ORPHAN_LOCK, orphan_finding_viz)
    register_finding_viz(CATEGORY_SELF_DEADLOCK, self_finding_viz)


_register_presentation()
