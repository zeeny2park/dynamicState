"""Non-blocking diagnosis jobs for the web UI: a worker thread runs the same ``diagnose_with_summary`` as the
synchronous ``POST /api/diagnose`` while a read-only listener on the engine's timeline turns what the session
exposes into numbered events (see docs/ui-redesign/API_CONTRACT.md).

The listener only reads the session; it never changes what the diagnosis does.  Everything it does is wrapped so
that a failure in event building loses an event, not a diagnosis.
"""

import os
import secrets
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

MAX_FINISHED_JOBS = 20
MAX_RUNNING_JOBS = 4
SESSION_WAIT_S = 3.0
VERIFICATION_RESULTS_CAP = 10
JOB_ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
JOB_ID_LEN = 22


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_valid_job_id(value: Any) -> bool:
    return isinstance(value, str) and len(value) == JOB_ID_LEN and all(c in JOB_ID_CHARS for c in value)


def _process_name(pid: int) -> Optional[str]:
    try:
        with open(f"/proc/{int(pid)}/comm", "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


class DiagnoseJob:
    def __init__(self, params: Dict[str, Any]):
        self.job_id = secrets.token_urlsafe(16)[:JOB_ID_LEN]
        self.pid: int = params["pid"]
        self.remote_host: Optional[str] = (params.get("remote_target") or {}).get("remote_host")
        self.target_name: Optional[str] = None if self.remote_host else _process_name(self.pid)
        self.language: str = params.get("language") or "en"
        self.params = params
        self.investigation_id: Optional[str] = None
        self.state = "running"          # running | done | error
        self.verdict: Optional[str] = None
        self.started_at = _now()
        self.finished_at: Optional[str] = None
        self.events: List[Dict[str, Any]] = []
        self.cond = threading.Condition()
        self.session_ready = threading.Event()
        self.session: Any = None
        self.reports: Dict[str, Dict[str, Any]] = {}
        self.report_lock = threading.Lock()

    # -- events
    def emit(self, etype: str, data: Dict[str, Any]) -> None:
        with self.cond:
            self.events.append({"seq": len(self.events) + 1, "ts": _now(), "type": etype, "data": data})
            self.cond.notify_all()

    def events_after(self, after: int) -> List[Dict[str, Any]]:
        with self.cond:
            return list(self.events[max(0, after):])

    def wait_for_events(self, after: int, timeout: float) -> Tuple[List[Dict[str, Any]], bool]:
        """Block until there are events after ``after`` or the job is finished; returns (events, finished)."""
        with self.cond:
            if len(self.events) <= after and self.state == "running":
                self.cond.wait(timeout)
            return list(self.events[max(0, after):]), self.state != "running"

    def finish(self, state: str, verdict: Optional[str]) -> None:
        with self.cond:
            self.state = state
            self.verdict = verdict
            self.finished_at = _now()
            self.cond.notify_all()

    def summary(self) -> Dict[str, Any]:
        with self.cond:
            return {
                "job_id": self.job_id, "investigation_id": self.investigation_id, "pid": self.pid,
                "target_name": self.target_name, "remote_host": self.remote_host, "state": self.state,
                "verdict": self.verdict, "started_at": self.started_at, "finished_at": self.finished_at,
                "last_seq": len(self.events),
            }


def _dump_hypothesis(h: Any, serialize: Callable[[Any], Any]) -> Dict[str, Any]:
    results = list(getattr(h, "verification_execution_results", None) or [])[:VERIFICATION_RESULTS_CAP]
    return {
        "hypothesis_id": getattr(h, "hypothesis_id", None), "category": getattr(h, "category", None),
        "domain": getattr(h, "domain", None), "status": getattr(h, "status", None),
        "confidence": getattr(h, "confidence", None), "problem_statement": getattr(h, "problem_statement", ""),
        "confidence_basis": getattr(h, "confidence_basis", ""),
        "recommended_next_action": getattr(h, "recommended_next_action", ""),
        "verification_execution_results": serialize(results),
    }


class _TimelineTranslator:
    """Turns timeline entries (plus the session's plan / checks / hypotheses) into UI events.  Read-only."""

    def __init__(self, job: DiagnoseJob, serialize: Callable[[Any], Any]):
        self.job = job
        self.serialize = serialize
        self.started_steps: set = set()
        self.provisional_keys: set = set()

    def __call__(self, session: Any, entry: Dict[str, Any]) -> None:
        try:
            handler = getattr(self, "_on_" + str(entry.get("event_type")), None)
            if handler is not None:
                handler(session, entry.get("details") or {})
        except Exception:  # noqa: BLE001 - losing one event must never touch the diagnosis
            pass

    # -- helpers
    @staticmethod
    def _steps(session: Any) -> List[Any]:
        plan = getattr(session, "plan", None)
        return list(getattr(plan, "steps", None) or [])

    def _step_row(self, step: Any, index: Optional[int]) -> Dict[str, Any]:
        return {"step_id": step.step_id, "recipe_id": step.recipe_id, "name": step.recipe_name,
                "index": index, "total": None}

    def _announce_next(self, session: Any, index: int) -> None:
        steps = self._steps(session)
        if 0 <= index < len(steps) and steps[index].step_id not in self.started_steps:
            st = steps[index]
            self.started_steps.add(st.step_id)
            self.job.emit("check_start", {"step_id": st.step_id, "recipe_id": st.recipe_id, "name": st.recipe_name,
                                          "index": index, "total": len(steps)})

    # -- timeline handlers
    def _on_PROBLEM_CLASSIFIED(self, session: Any, d: Dict[str, Any]) -> None:
        cr = getattr(session, "classification_result", None)
        data = dict(d)
        data["candidate_categories"] = self.serialize(list(getattr(cr, "candidate_categories", None) or []))
        data["problem_statement"] = getattr(session, "raw_problem_statement", "")
        self.job.emit("classified", self.serialize(data))

    def _on_TARGET_ASSESSED(self, session: Any, d: Dict[str, Any]) -> None:
        ta = getattr(session, "target_assessment", None)
        data: Dict[str, Any] = self.serialize(ta.to_dict()) if ta is not None and hasattr(ta, "to_dict") else dict(d)
        data.setdefault("pid", session.pid)
        data["process_name"] = self.job.target_name
        data["transport"] = "ssh" if self.job.remote_host else "local"
        data["investigation_id"] = session.investigation_id
        self.job.emit("target", data)

    def _on_PLAN_GENERATED(self, session: Any, d: Dict[str, Any]) -> None:
        plan = session.get_plan()
        steps = [{"step_id": s["step_id"], "recipe_id": s["recipe_id"], "name": s.get("recipe_name"),
                  "category": s.get("category"), "domain": s.get("domain"), "priority": s.get("priority"),
                  "status": s.get("status", "PENDING")} for s in plan.get("steps", [])]
        self.job.emit("plan", {"total_steps": plan.get("total_steps", len(steps)),
                               "rationale": plan.get("plan_rationale", d.get("rationale", "")),
                               "estimated_overhead_ms": plan.get("estimated_overhead_ms"), "steps": steps})
        self._announce_next(session, int(plan.get("current_step_index", 0) or 0))

    def _on_STEP_EXECUTED(self, session: Any, d: Dict[str, Any]) -> None:
        steps = self._steps(session)
        step_id, recipe_id = d.get("step_id"), d.get("recipe_id")
        index = next((i for i, s in enumerate(steps) if s.step_id == step_id), None)
        check = next((c for c in reversed(list(getattr(session, "checks", []))) if c.recipe_id == recipe_id), None)
        name = (check.name if check is not None and check.name else None) or (steps[index].recipe_name if index is not None else recipe_id)
        if step_id not in self.started_steps:
            self.started_steps.add(step_id)
            self.job.emit("check_start", {"step_id": step_id, "recipe_id": recipe_id, "name": name,
                                          "index": index, "total": len(steps)})
        status = check.status if check is not None else None
        self.job.emit("check_done", self.serialize({
            "step_id": step_id, "recipe_id": recipe_id, "check_id": getattr(check, "check_id", None), "name": name,
            "status": status, "duration_ms": getattr(check, "duration_ms", None),
            "summary": getattr(check, "technical_interpretation", ""), "eval_status": d.get("eval_status"),
            "confidence": d.get("confidence"),
            "supporting_evidence_ids": list(getattr(check, "supporting_evidence_ids", []) or []),
            "contradicting_evidence_ids": list(getattr(check, "contradicting_evidence_ids", []) or []),
            "limitations": list(getattr(check, "limitations", []) or []),
            "missing_evidence": list(getattr(check, "missing_evidence", []) or []),
            "index": index, "total": len(steps)}))
        if status == "FAIL" and index is not None:
            st = steps[index]
            key = f"{st.category}/{st.domain}"
            if key not in self.provisional_keys:
                self.provisional_keys.add(key)
                self.job.emit("finding_provisional", self.serialize({
                    "key": key, "recipe_id": recipe_id, "check_id": getattr(check, "check_id", None), "name": name,
                    "category": st.category, "domain": st.domain,
                    "summary": getattr(check, "technical_interpretation", ""), "status": "provisional"}))
        plan = getattr(session, "plan", None)
        if plan is not None:
            nxt = (index + 1) if index is not None else int(getattr(plan, "current_step_index", 0)) + 1
            self._announce_next(session, nxt)

    def _on_HYPOTHESES_VERIFIED(self, session: Any, d: Dict[str, Any]) -> None:
        act = list(getattr(session, "active_hypotheses", []) or [])
        rej = list(getattr(session, "rejected_hypotheses", []) or [])
        self.job.emit("verified", {
            "active_count": len(act), "rejected_count": len(rej),
            "hypotheses": [_dump_hypothesis(h, self.serialize) for h in act],
            "rejected": [_dump_hypothesis(h, self.serialize) for h in rej]})


class DiagnoseJobManager:
    def __init__(self, engine_getter: Callable[[], Any], serialize: Callable[[Any], Any],
                 diagnose_fn: Optional[Callable[..., Tuple[Dict[str, Any], str]]] = None):
        self._engine_getter = engine_getter
        self._serialize = serialize
        self._diagnose_fn = diagnose_fn
        self._lock = threading.Lock()
        self._jobs: "OrderedDict[str, DiagnoseJob]" = OrderedDict()
        self._running_by_target: Dict[Tuple[str, int], str] = {}
        self._by_thread: Dict[int, DiagnoseJob] = {}
        self._hooked_engine: Any = None

    # -- engine hook
    def _install_hook(self, engine: Any) -> None:
        if self._hooked_engine is engine:
            return
        previous = getattr(engine, "session_listener_factory", None)

        def factory(session: Any) -> Any:
            job = self._by_thread.get(threading.get_ident())
            if job is None:
                return previous(session) if previous is not None else None
            job.investigation_id = getattr(session, "investigation_id", None)
            job.session = session
            job.session_ready.set()
            return _TimelineTranslator(job, self._serialize)

        engine.session_listener_factory = factory
        self._hooked_engine = engine

    # -- API
    def start(self, params: Dict[str, Any]) -> Dict[str, Any]:
        key = (str((params.get("remote_target") or {}).get("remote_host") or ""), int(params["pid"]))
        with self._lock:
            running_id = self._running_by_target.get(key)
            if running_id is not None and running_id in self._jobs and self._jobs[running_id].state == "running":
                job = self._jobs[running_id]
                return self._started(job, already=True)
            if len(self._running_by_target) >= MAX_RUNNING_JOBS:
                return {"success": False, "error": {"code": "TOO_MANY_JOBS",
                                                    "message": f"at most {MAX_RUNNING_JOBS} diagnoses run at the same time"}}
            job = DiagnoseJob(params)
            self._jobs[job.job_id] = job
            self._running_by_target[key] = job.job_id
            engine = self._engine_getter()
            self._install_hook(engine)
        t = threading.Thread(target=self._run, args=(job, key, engine), name=f"diagnose-{job.job_id[:6]}", daemon=True)
        t.start()
        job.session_ready.wait(SESSION_WAIT_S)
        return self._started(job, already=False)

    def _started(self, job: DiagnoseJob, already: bool) -> Dict[str, Any]:
        s = job.summary()
        return {"success": True, "job_id": job.job_id, "investigation_id": s["investigation_id"],
                "already_running": already, "state": s["state"]}

    def _run(self, job: DiagnoseJob, key: Tuple[str, int], engine: Any) -> None:
        self._by_thread[threading.get_ident()] = job
        state, verdict = "error", None
        try:
            fn = self._diagnose_fn
            if fn is None:
                from extractor.human_report import diagnose_with_summary as fn  # same function as POST /api/diagnose
            p = job.params
            result, summary = fn(
                p["pid"], debug_image=p.get("debug_image"), symptom=p.get("symptom"), time_limit_s=p.get("time_limit_s"),
                engine=engine, lang=job.language, target=p.get("remote_target"), symptom_fields=p.get("symptom_fields"),
            )
            full = self._serialize({**result, "human_summary": summary})
            verdict = full.get("verdict")
            if not job.investigation_id:
                job.investigation_id = full.get("investigation_id")
            base = f"api/diagnose/{job.job_id}/report"
            job.emit("verdict", {
                "result": full, "human_summary": summary, "report_path": full.get("report_path"),
                "report_urls": {f: f"{base}?format={f}" for f in ("html", "md", "json")}, "language": job.language,
            })
            state = "done"
        except Exception as exc:  # noqa: BLE001
            job.emit("error", {"code": "DIAGNOSE_ERROR", "message": f"{type(exc).__name__}: {exc}", "stage": "diagnose"})
        finally:
            self._by_thread.pop(threading.get_ident(), None)
            job.finish(state, verdict)
            with self._lock:
                if self._running_by_target.get(key) == job.job_id:
                    del self._running_by_target[key]
                self._evict()

    def _evict(self) -> None:
        finished = [jid for jid, j in self._jobs.items() if j.state != "running"]
        for jid in finished[:max(0, len(finished) - MAX_FINISHED_JOBS)]:
            del self._jobs[jid]

    def get(self, job_id: str) -> Optional[DiagnoseJob]:
        if not is_valid_job_id(job_id):
            return None
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            jobs = list(self._jobs.values())
        return [j.summary() for j in reversed(jobs)]

    def status(self, job: DiagnoseJob, after: int = 0) -> Dict[str, Any]:
        info = job.summary()
        info["engine_state"] = None
        info["progress_percentage"] = None
        if info["state"] == "running" and job.session is not None:
            try:
                st = job.session.get_status()
                info["engine_state"] = st.get("state")
                info["progress_percentage"] = st.get("progress_percentage")
            except Exception:  # noqa: BLE001
                pass
        return {"success": True, "job": info, "events": job.events_after(after)}

    def report(self, job: DiagnoseJob, lang: Optional[str]) -> Dict[str, Any]:
        """The incident report of a finished job, by the one report path (``incident_report.export_incident_report``)."""
        lang = lang or job.language
        with job.report_lock:
            if lang in job.reports:
                return job.reports[lang]
            engine = self._engine_getter()
            session = job.session or (getattr(engine, "sessions", {}) or {}).get(job.investigation_id or "")
            if session is None:
                return {"success": False, "error": {"code": "SESSION_GONE", "message": "the investigation is no longer in memory"}}
            from extractor import incident_report
            res = incident_report.export_incident_report(
                session=session, language=lang, pid=job.pid, process_name=job.target_name, engine=engine)
            if not res.get("success"):
                return {"success": False, "error": {"code": "REPORT_ERROR", "message": str(res.get("error") or "report failed")}}
            out = {"success": True, "html": res.get("report_html") or "", "md": res.get("report_markdown") or "",
                   "json": res.get("report_json") or "{}"}
            job.reports[lang] = out
            return out
