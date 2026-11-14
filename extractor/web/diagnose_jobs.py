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
WATCH_INTERVAL_S = 0.05
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


def _start_ticks(pid: int) -> Optional[int]:
    try:
        with open(f"/proc/{int(pid)}/stat", "r", encoding="utf-8", errors="replace") as fh:
            return int(fh.read().rsplit(")", 1)[1].split()[19])
    except (OSError, IndexError, ValueError):
        return None


def _reason_code(reason: str) -> str:
    """The engine's own words for an unusable local target (``_preflight_target``) as an error code."""
    r = reason or ""
    if "not readable by this user" in r or "Permission denied" in r or "Operation not permitted" in r:
        return "PERMISSION_DENIED"
    if "does not exist" in r or "No such process" in r or "has exited" in r or "No such file" in r:
        return "TARGET_NOT_FOUND"
    return "TARGET_UNREADABLE"


def preflight_error(pid: int) -> Optional[Dict[str, str]]:
    """The engine's pre-flight check of a local target (``expert_diagnostic_engine._preflight_target``), before a
    job exists: ``{"code", "message"}`` when the diagnosis could only end INCONCLUSIVE for that reason, else None."""
    try:
        from extractor.expert_diagnostic_engine import _preflight_target
        from extractor.target_adapter import LocalTargetAdapter
        _name, reason = _preflight_target(pid, LocalTargetAdapter())
    except Exception:  # noqa: BLE001 - the diagnosis itself will say what is wrong
        return None
    return {"code": _reason_code(reason), "message": reason} if reason else None


def outcome_notice(result: Dict[str, Any], job: "DiagnoseJob") -> Optional[Dict[str, str]]:
    """What the UI should say next to a verdict that the target itself prevented: it exited during the diagnosis,
    or it could not be read.  From the result's ``target_unreadable`` entry, or a local process that is gone now."""
    for n in result.get("not_covered") or []:
        if isinstance(n, dict) and n.get("kind") == "target_unreadable":
            code = _reason_code(str(n.get("reason") or ""))
            return {"code": "TARGET_EXITED" if code == "TARGET_NOT_FOUND" and job.target_name else code,
                    "message": str(n.get("reason") or "")}
    if not job.remote_host and job.target_name and not _alive(int(job.pid)):
        return {"code": "TARGET_EXITED", "message": f"process {job.pid} exited during the diagnosis"}
    return None


def _alive(pid: int) -> bool:
    """A local process that still runs: present in /proc and not a zombie (an exited child its parent has not reaped
    yet still has a /proc entry)."""
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace") as fh:
            state = fh.read().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return False
    return state not in ("Z", "X")


class DiagnoseJob:
    def __init__(self, params: Dict[str, Any]):
        self.job_id = secrets.token_urlsafe(16)[:JOB_ID_LEN]
        self.pid: int = params["pid"]
        self.remote_host: Optional[str] = (params.get("remote_target") or {}).get("remote_host")
        self.target_name: Optional[str] = None if self.remote_host else _process_name(self.pid)
        # the process's start time: exploration refuses to read a pid that now belongs to another process
        self.start_ticks: Optional[int] = None if self.remote_host else _start_ticks(self.pid)
        self.observation: Optional[Dict[str, Any]] = None     # "Add to report": the user's observation, in the report only
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
        self.result: Optional[Dict[str, Any]] = None      # the finished DiagnoseResult with its inline report
        self.verdict_word: Optional[Dict[str, str]] = None
        self.headline: Optional[Dict[str, str]] = None

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
                "verdict": self.verdict, "verdict_word": self.verdict_word, "headline": self.headline,
                "started_at": self.started_at, "finished_at": self.finished_at, "last_seq": len(self.events),
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
        self._lock = threading.Lock()      # keeps check_start before check_done for a step

    def watch_running_steps(self, session: Any) -> None:
        """The engine marks a step RUNNING but records no timeline entry for it, so a small read-only thread
        watches the plan and announces each step when it is seen running (latency <= WATCH_INTERVAL_S)."""

        def loop() -> None:
            while self.job.state == "running":
                try:
                    steps = self._steps(session)
                    for index, st in enumerate(steps):
                        if st.status == "RUNNING":
                            self._announce(st.step_id, st.recipe_id, st.recipe_name, index, len(steps))
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(WATCH_INTERVAL_S)

        threading.Thread(target=loop, name=f"watch-{self.job.job_id[:6]}", daemon=True).start()

    def _announce(self, step_id: str, recipe_id: str, name: Optional[str], index: Optional[int], total: int) -> None:
        with self._lock:
            if step_id in self.started_steps:
                return
            self.started_steps.add(step_id)
            self.job.emit("check_start", {"step_id": step_id, "recipe_id": recipe_id, "name": name,
                                          "index": index, "total": total})

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
        abi = data.get("target_abi") if isinstance(data.get("target_abi"), dict) else {}
        for key in ("architecture", "libc", "libc_version"):
            if abi.get(key):
                data[key] = abi[key]
        self.job.emit("target", data)

    def _on_PLAN_GENERATED(self, session: Any, d: Dict[str, Any]) -> None:
        plan = session.get_plan()
        steps = [{"step_id": s["step_id"], "recipe_id": s["recipe_id"], "name": s.get("recipe_name"),
                  "category": s.get("category"), "domain": s.get("domain"), "priority": s.get("priority"),
                  "status": s.get("status", "PENDING")} for s in plan.get("steps", [])]
        data: Dict[str, Any] = {"total_steps": plan.get("total_steps", len(steps)),
                                "rationale": plan.get("plan_rationale", d.get("rationale", "")),
                                "estimated_overhead_ms": plan.get("estimated_overhead_ms"), "steps": steps}
        try:
            from extractor.web.ui import view
            labels = view.plan_labels([st["recipe_id"] for st in steps])
            for st in steps:
                st["label"] = labels[st["recipe_id"]]["name"]
                st["domain_label"] = labels[st["recipe_id"]]["domain_label"]
            registry = getattr(session, "recipe_registry", None)
            if registry is not None:
                data.update(view.plan_exclusions(registry, [st["recipe_id"] for st in steps]))
        except Exception:  # noqa: BLE001 - labels are a convenience; the plan event goes out without them
            pass
        self.job.emit("plan", data)

    def _on_STEP_EXECUTED(self, session: Any, d: Dict[str, Any]) -> None:
        steps = self._steps(session)
        step_id, recipe_id = d.get("step_id"), d.get("recipe_id")
        if not step_id or not recipe_id:
            return
        index = next((i for i, s in enumerate(steps) if s.step_id == step_id), None)
        check = next((c for c in reversed(list(getattr(session, "checks", []))) if c.recipe_id == recipe_id), None)
        name = (check.name if check is not None and check.name else None) or (steps[index].recipe_name if index is not None else recipe_id)
        self._announce(step_id, recipe_id, name, index, len(steps))
        status = check.status if check is not None else None
        with self._lock:
            self._emit_check_done(session, d, steps, step_id, recipe_id, check, name, index, status)

    def _emit_check_done(self, session: Any, d: Dict[str, Any], steps: List[Any], step_id: str, recipe_id: str,
                         check: Any, name: Optional[str], index: Optional[int], status: Optional[str]) -> None:
        self.job.emit("check_done", self.serialize({
            "step_id": step_id, "recipe_id": recipe_id, "check_id": getattr(check, "check_id", None), "name": name,
            "status": status, "duration_ms": getattr(check, "duration_ms", None),
            "summary": getattr(check, "technical_interpretation", ""), "eval_status": d.get("eval_status"),
            "confidence": d.get("confidence"),
            "supporting_evidence_ids": list(getattr(check, "supporting_evidence_ids", []) or []),
            "contradicting_evidence_ids": list(getattr(check, "contradicting_evidence_ids", []) or []),
            "limitations": list(getattr(check, "limitations", []) or []),
            "missing_evidence": list(getattr(check, "missing_evidence", []) or []),
            "index": index, "total": len(steps), **self._extras(session, check)}))
        if status == "FAIL" and index is not None:
            st = steps[index]
            key = f"{st.category}/{st.domain}"
            if key not in self.provisional_keys:
                self.provisional_keys.add(key)
                data = {"key": key, "recipe_id": recipe_id, "check_id": getattr(check, "check_id", None), "name": name,
                        "category": st.category, "domain": st.domain,
                        "summary": getattr(check, "technical_interpretation", ""), "status": "provisional"}
                try:
                    from extractor.web.ui import view
                    data["category_label"] = view.category_labels(str(st.category))
                except Exception:  # noqa: BLE001
                    pass
                self.job.emit("finding_provisional", self.serialize(data))

    @staticmethod
    def _extras(session: Any, check: Any) -> Dict[str, Any]:
        """``line`` (the report's one-line result, ko / en) and ``bytes_read`` (cumulative), when they exist."""
        out: Dict[str, Any] = {}
        try:
            from extractor.web.ui import view
            if check is not None:
                out["line"] = view.check_line({
                    "recipe_id": check.recipe_id, "status": str(check.status), "name": check.name,
                    "technical_interpretation": getattr(check, "technical_interpretation", ""),
                    "limitations": list(getattr(check, "limitations", []) or []),
                    "missing_evidence": list(getattr(check, "missing_evidence", []) or []),
                    "actual_observations": getattr(check, "actual_observations", None) or {},
                    "error_details": getattr(check, "error_details", None)})
        except Exception:  # noqa: BLE001
            pass
        metrics = getattr(getattr(session, "budget_tracker", None), "metrics", None)
        if isinstance(getattr(metrics, "bytes_read", None), (int, float)):
            out["bytes_read"] = int(metrics.bytes_read)
        return out

    def _on_HYPOTHESES_VERIFIED(self, session: Any, d: Dict[str, Any]) -> None:
        act = list(getattr(session, "active_hypotheses", []) or [])
        rej = list(getattr(session, "rejected_hypotheses", []) or [])
        self.job.emit("verified", {
            "active_count": len(act), "rejected_count": len(rej),
            "hypotheses": [_dump_hypothesis(h, self.serialize) for h in act],
            "rejected": [_dump_hypothesis(h, self.serialize) for h in rej]})


class DiagnoseJobManager:
    def __init__(self, engine_getter: Callable[[], Any], serialize: Callable[[Any], Any],
                 diagnose_fn: Optional[Callable[..., Tuple[Dict[str, Any], str]]] = None, corpus_dir: Optional[str] = None):
        self._engine_getter = engine_getter
        self._serialize = serialize
        self._diagnose_fn = diagnose_fn
        self._corpus_dir = corpus_dir
        self._explore: Any = None
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
            translator = _TimelineTranslator(job, self._serialize)
            translator.watch_running_steps(session)
            return translator

        engine.session_listener_factory = factory
        self._hooked_engine = engine

    # -- API
    def start(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if self._diagnose_fn is None and not params.get("remote_target"):
            refused = preflight_error(int(params["pid"]))
            if refused is not None:
                return {"success": False, "error": refused}
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
            extra: Dict[str, Any] = {}
            if fn is None:
                from extractor.human_report import diagnose_with_summary as fn  # same function as POST /api/diagnose
                extra["keep_report"] = True     # the view and the report are made from this very result
            p = job.params
            for k in ("default_check_budget_s", "default_check_max_s", "enable_tracing"):   # options
                if p.get(k) is not None:
                    extra[k] = p[k]
            result, summary = fn(
                p["pid"], debug_image=p.get("debug_image"), symptom=p.get("symptom"), time_limit_s=p.get("time_limit_s"),
                engine=engine, lang=job.language, target=p.get("remote_target"), symptom_fields=p.get("symptom_fields"),
                **extra,
            )
            report = result.get("report") if isinstance(result.get("report"), dict) else None
            if report is not None:
                job.result = self._serialize(result)
            result = {k: v for k, v in result.items() if k != "report"}
            full = self._serialize({**result, "report": None, "human_summary": summary})
            verdict = full.get("verdict")
            if not job.investigation_id:
                job.investigation_id = full.get("investigation_id")
            base = f"api/diagnose/{job.job_id}/report"
            data: Dict[str, Any] = {
                "result": full, "human_summary": summary, "report_path": full.get("report_path"),
                "report_urls": {f: f"{base}?format={f}" for f in ("html", "md", "json")}, "language": job.language,
            }
            try:
                from extractor.web.ui import view
                job.verdict_word, job.headline = view.verdict_words(verdict), view.headline(full)
                data["view"] = view.build_views(job.result or full, report)
            except Exception:  # noqa: BLE001 - the UI renders the result without the view
                pass
            notice = outcome_notice(full, job)
            if notice:
                data["notice"] = notice
            job.emit("verdict", data)
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
        if self._explore is not None:
            self._explore.prune(list(self._jobs))

    # -- exploration (extractor/web/explore.py): read-only, bound to a job's target
    @property
    def explore(self) -> Any:
        with self._lock:
            if self._explore is None:
                import tempfile
                from extractor.web.explore import ExploreHub
                corpus = self._corpus_dir or os.path.join(tempfile.gettempdir(), "dynamicstate-explore")
                self._explore = ExploreHub(corpus)
            return self._explore

    def set_observation(self, job: DiagnoseJob, observation: Optional[Dict[str, Any]]) -> None:
        """"Add to report": the next report of this job carries the observation as its own section (or none)."""
        with job.report_lock:
            job.observation = observation

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
                return self._with_observation(job, job.reports[lang], lang)
            engine = self._engine_getter()
            from extractor import incident_report
            if job.result is not None:      # the result the UI showed, so the report says exactly the same
                res = incident_report.export_incident_report(result=job.result, language=lang, pid=job.pid,
                                                             process_name=job.target_name)
            else:
                session = job.session or (getattr(engine, "sessions", {}) or {}).get(job.investigation_id or "")
                if session is None:
                    return {"success": False, "error": {"code": "SESSION_GONE", "message": "the investigation is no longer in memory"}}
                res = incident_report.export_incident_report(
                    session=session, language=lang, pid=job.pid, process_name=job.target_name, engine=engine)
            if not res.get("success"):
                return {"success": False, "error": {"code": "REPORT_ERROR", "message": str(res.get("error") or "report failed")}}
            out = {"success": True, "html": res.get("report_html") or "", "md": res.get("report_markdown") or "",
                   "json": res.get("report_json") or "{}"}
            job.reports[lang] = out
            return self._with_observation(job, out, lang)

    @staticmethod
    def _with_observation(job: DiagnoseJob, base: Dict[str, Any], lang: str) -> Dict[str, Any]:
        """"Add to report": the same report (the cached one, byte for byte) plus the user's observation section."""
        if not job.observation:
            return base
        from extractor.web.observation_report import add_to_report
        return add_to_report(base, job.observation, lang)
