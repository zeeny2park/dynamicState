"""Collection impact measurement (IMP-020): what did this diagnosis cost the target?

A ``CollectionImpactMeter`` brackets a collection: at start and end it reads, through the target adapter (so it
works for remote targets via the collector daemon or one batched shell command), the TARGET's
``/proc/PID/stat`` (utime, stime, state), context switches and ``schedstat`` (run time, run-queue wait) summed
over its threads, plus the system's ``/proc/loadavg`` and the aggregate CPU line of ``/proc/stat``.  For remote
targets the same exchange carries the collector process's own ``getrusage`` (CPU time, peak RSS).

What the numbers mean (do not overclaim):

* Everything under ``target`` is a DELTA over the window of the target's OWN activity.  The diagnosis never stops
  the target in zero-stop mode, so its utime/stime is not caused by us.  Read it as "what the target was doing
  while we looked", not as our cost.  Time the target spent stopped (``measured_stop_ms``) is time it did NOT run.
* What is attributable to the diagnosis is ``attributable_cpu_ms``: on remote targets the collector process's own
  CPU time (exact, from its getrusage, cumulative-since-start delta); locally the CPU consumed by the diagnosing
  process during the window (an upper bound of the read cost: it includes analysis, not only reads).  The
  collector's runtime cost is therefore real and measured; the indirect effect on the target (cache/lock
  contention, page-cache pressure) is NOT measured here - the throughput benchmark estimates that.
* Resolution: utime/stime come in clock ticks (usually 10 ms) so windows shorter than a few ticks read as 0.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional

IMPACT_SCHEMA_VERSION = "1"
DEFAULT_CLK_TCK = 100


def parse_stat_line(raw: str) -> Optional[Dict[str, Any]]:
    """Fields of /proc/PID/stat: state, utime, stime (ticks), starttime.  comm may contain spaces/parentheses."""
    if not raw:
        return None
    rp = raw.rfind(")")
    if rp < 0:
        return None
    rest = raw[rp + 1:].split()
    if len(rest) < 20:
        return None
    try:
        return {"state": rest[0], "utime": int(rest[11]), "stime": int(rest[12]), "starttime": rest[19]}
    except ValueError:
        return None


def parse_cpu_line(line: Optional[str]) -> Optional[Dict[str, int]]:
    """Aggregate "cpu" line of /proc/stat -> {"total", "idle"} jiffies (idle includes iowait)."""
    if not line:
        return None
    f = line.split()
    if not f or f[0] != "cpu" or len(f) < 5:
        return None
    try:
        vals = [int(x) for x in f[1:]]
    except ValueError:
        return None
    # user nice system idle iowait irq softirq steal [guest guest_nice are already inside user/nice]
    counted = vals[:8]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    return {"total": sum(counted), "idle": idle}


def parse_loadavg(text: Optional[str]) -> Optional[Dict[str, float]]:
    if not text:
        return None
    f = text.split()
    try:
        return {"load1": float(f[0]), "load5": float(f[1]), "load15": float(f[2])}
    except (ValueError, IndexError):
        return None


@dataclass
class CollectionImpact:
    """JSON-serialisable record of one bracketed collection window."""
    schema_version: str = IMPACT_SCHEMA_VERSION
    pid: Optional[int] = None
    remote: bool = False
    transport: Optional[str] = None
    measured: bool = False
    wall_ms: float = 0.0
    bytes_read: Optional[int] = None
    measured_stop_ms: Optional[float] = None
    #: the target's own activity during the window (delta; NOT caused by the diagnosis)
    target: Dict[str, Any] = field(default_factory=dict)
    #: system-wide figures during the window
    system: Dict[str, Any] = field(default_factory=dict)
    #: cost of the diagnosis itself
    diagnosis_attributable: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    #: remote targets: what the window cost in ssh invocations / daemon exchanges, by purpose and call site
    remote_commands: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _ms_from_ticks(ticks: int, clk_tck: int) -> float:
    return round(ticks * 1000.0 / max(1, clk_tck), 3)


class CollectionImpactMeter:
    """Brackets a collection: ``start()`` ... diagnosis ... ``finish()``.  Never raises."""

    def __init__(
        self,
        adapter: Any,
        pid: int,
        host_cpu_fn: Callable[[], float] = time.process_time,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.adapter = adapter
        self.pid = int(pid)
        self._host_cpu_fn = host_cpu_fn
        self._clock = clock
        self._start_snap: Optional[Dict[str, Any]] = None
        self._start_t: Optional[float] = None
        self._start_host_cpu: Optional[float] = None
        self._start_collector: Optional[Dict[str, Any]] = None
        self._last_collector: Optional[Dict[str, Any]] = None
        self._notes: List[str] = []
        self.remote = bool(getattr(adapter, "is_remote", lambda: False)()) if adapter is not None else False

    # ---- snapshots ---------------------------------------------------------------------------
    def _snapshot(self) -> Optional[Dict[str, Any]]:
        try:
            snap = self.adapter.read_load_snapshot(self.pid) if self.adapter is not None else None
        except Exception as exc:  # noqa: BLE001
            self._notes.append(f"load snapshot failed: {type(exc).__name__}: {exc}")
            return None
        if snap is not None and isinstance(snap.get("collector"), dict):
            self._last_collector = snap["collector"]
        return snap

    def start(self) -> "CollectionImpactMeter":
        self._start_t = self._clock()
        self._start_host_cpu = self._host_cpu_fn()
        self._start_snap = self._snapshot()
        if self._start_snap is None:
            self._notes.append("no load snapshot at window start: target deltas unavailable")
        else:
            self._start_collector = self._start_snap.get("collector") if isinstance(self._start_snap.get("collector"), dict) else None
        return self

    # ---- attributable cost, usable while the collection is still running ---------------------
    @staticmethod
    def _collector_cpu_ms(c: Optional[Dict[str, Any]]) -> Optional[float]:
        if not isinstance(c, dict):
            return None
        try:
            return (int(c.get("cpu_user_us", 0)) + int(c.get("cpu_sys_us", 0))) / 1000.0
        except (TypeError, ValueError):
            return None

    def attributable_cpu_ms(self) -> Optional[float]:
        """Cumulative target-side CPU (ms) the observation has consumed since ``start()``.

        Remote: the collector's own CPU delta (one cheap STATS exchange).  Local: the diagnosing process's CPU
        delta.  None when it cannot be measured (e.g. remote target without collector support)."""
        if self._start_t is None:
            return None
        if not self.remote:
            return max(0.0, (self._host_cpu_fn() - (self._start_host_cpu or 0.0)) * 1000.0)
        base = self._collector_cpu_ms(self._start_collector)
        if base is None:
            return None
        try:
            cur = self.adapter.read_collector_stats()
        except Exception:  # noqa: BLE001
            cur = None
        if isinstance(cur, dict):
            self._last_collector = cur
        now = self._collector_cpu_ms(self._last_collector)
        return None if now is None else max(0.0, now - base)

    # ---- result --------------------------------------------------------------------------------
    def finish(self, bytes_read: Optional[int] = None, measured_stop_ms: Optional[float] = None) -> CollectionImpact:
        rec = CollectionImpact(pid=self.pid, remote=self.remote, bytes_read=bytes_read, measured_stop_ms=measured_stop_ms)
        notes = rec.notes
        if self._start_t is None:
            notes.append("meter was never started")
            return rec
        rec.wall_ms = round((self._clock() - self._start_t) * 1000.0, 3)
        end_host_cpu = self._host_cpu_fn()
        end_snap = self._snapshot()
        notes.extend(self._notes)
        a, b = self._start_snap, end_snap
        if end_snap is not None:
            rec.transport = end_snap.get("transport")
        if a is None or b is None:
            if b is None and a is not None:
                notes.append("no load snapshot at window end (target gone or unreadable): target deltas unavailable")
        else:
            rec.measured = True
            self._fill_deltas(rec, a, b)
        self._fill_attributable(rec, a, b, end_host_cpu)
        summarize = getattr(self.adapter, "remote_command_summary", None)
        if self.remote and callable(summarize):
            try:   # whole adapter session (preflight, deploy and identity included), not only this window
                rec.remote_commands = summarize()
            except Exception as exc:  # noqa: BLE001
                notes.append(f"remote command summary failed: {type(exc).__name__}: {exc}")
        notes.append(
            "target.* is the target's own activity during the window (delta); it is not caused by the diagnosis, "
            "which never stops the target in zero-stop mode. Cost of the diagnosis is under diagnosis_attributable."
        )
        if measured_stop_ms:
            notes.append(f"the target was stopped for {measured_stop_ms:.2f} ms of the window; target.cpu_ms excludes that time")
        return rec

    @staticmethod
    def _fill_deltas(rec: CollectionImpact, a: Dict[str, Any], b: Dict[str, Any]) -> None:
        notes = rec.notes
        clk = int(b.get("clk_tck") or a.get("clk_tck") or DEFAULT_CLK_TCK)
        if not (b.get("clk_tck") or a.get("clk_tck")):
            notes.append(f"clock tick rate unknown on the target, assumed {DEFAULT_CLK_TCK} Hz")
        sa, sb = parse_stat_line(a.get("stat", "")), parse_stat_line(b.get("stat", ""))
        tgt: Dict[str, Any] = {
            "cpu_resolution_ms": round(1000.0 / max(1, clk), 3),
            "state_start": sa["state"] if sa else None,
            "state_end": sb["state"] if sb else None,
        }
        if sa and sb and sa["starttime"] != sb["starttime"]:
            notes.append("target identity changed during the window (start time differs): target deltas discarded")
            sa = sb = None
        if sa and sb:
            du, ds = sb["utime"] - sa["utime"], sb["stime"] - sa["stime"]
            if du < 0 or ds < 0:
                notes.append("target CPU counters went backwards (exited threads leave the sum): clamped to 0")
            du, ds = max(0, du), max(0, ds)
            tgt.update(utime_ms=_ms_from_ticks(du, clk), stime_ms=_ms_from_ticks(ds, clk), cpu_ms=_ms_from_ticks(du + ds, clk))
        else:
            tgt.update(utime_ms=None, stime_ms=None, cpu_ms=None)
        for key in ("vol", "invol"):
            x, y = a.get(key), b.get(key)
            tgt[f"ctx_switches_{'voluntary' if key == 'vol' else 'involuntary'}"] = (
                max(0, int(y) - int(x)) if x is not None and y is not None and sa and sb else None
            )
        v, i = tgt["ctx_switches_voluntary"], tgt["ctx_switches_involuntary"]
        tgt["ctx_switches"] = (v + i) if v is not None and i is not None else None
        scha, schb = a.get("sched"), b.get("sched")
        if scha and schb and sa and sb:
            tgt["run_ms"] = round(max(0, schb["run_ns"] - scha["run_ns"]) / 1e6, 3)
            tgt["runqueue_wait_ms"] = round(max(0, schb["wait_ns"] - scha["wait_ns"]) / 1e6, 3)
        else:
            tgt["run_ms"] = None
            tgt["runqueue_wait_ms"] = None
            notes.append("schedstat unavailable on the target (no CONFIG_SCHED_INFO): run-queue wait not measured")
        rec.target = tgt

        ca, cb = parse_cpu_line(a.get("cpu_line")), parse_cpu_line(b.get("cpu_line"))
        la, lb = parse_loadavg(a.get("loadavg")), parse_loadavg(b.get("loadavg"))
        sysd: Dict[str, Any] = {"cpu_busy_fraction": None, "loadavg1_start": la and la["load1"], "loadavg1_end": lb and lb["load1"]}
        if ca and cb:
            dt = cb["total"] - ca["total"]
            if dt > 0:
                sysd["cpu_busy_fraction"] = round(min(1.0, max(0.0, 1.0 - (cb["idle"] - ca["idle"]) / dt)), 4)
            else:
                notes.append("system CPU counters did not advance during the window: busy fraction not measured")
        rec.system = sysd

    def _fill_attributable(self, rec: CollectionImpact, a: Optional[Dict[str, Any]], b: Optional[Dict[str, Any]], end_host_cpu: float) -> None:
        attr: Dict[str, Any] = {
            "attributable_cpu_ms": None, "basis": None,
            "collector_cpu_ms": None, "collector_cpu_total_ms": None, "collector_max_rss_kb": None,
            "host_process_cpu_ms": round(max(0.0, (end_host_cpu - (self._start_host_cpu or 0.0)) * 1000.0), 3),
        }
        if not self.remote:
            attr["attributable_cpu_ms"] = attr["host_process_cpu_ms"]
            attr["basis"] = "diagnosing_process_cpu"
            rec.notes.append("local target: attributable_cpu_ms is the diagnosing process's CPU in the window "
                             "(upper bound of the read cost, includes analysis)")
        else:
            c_end = (b or {}).get("collector") if b else None
            c_end = c_end if isinstance(c_end, dict) else self._last_collector
            c_start = self._start_collector
            total = self._collector_cpu_ms(c_end)
            base = self._collector_cpu_ms(c_start)
            if total is None:
                rec.notes.append("collector self-cost unavailable (old collector without IMPACT/STATS or shell fallback): "
                                 "diagnosis-attributable target CPU not measured")
            else:
                attr["collector_cpu_total_ms"] = round(total, 3)
                if base is not None:
                    attr["collector_cpu_ms"] = round(max(0.0, total - base), 3)
                    attr["attributable_cpu_ms"] = attr["collector_cpu_ms"]
                    attr["basis"] = "collector_process_rusage"
                try:
                    attr["collector_max_rss_kb"] = int(c_end.get("max_rss_kb"))
                except (TypeError, ValueError, AttributeError):
                    pass
        rec.diagnosis_attributable = attr


def impact_summary_for_report(
    impact: Optional[Any],
    capture_mode: Optional[str] = None,
    measured_stop_ms: Optional[float] = None,
    bytes_read: Optional[int] = None,
    budget_exhausted: Optional[bool] = None,
    exhaustion_reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Flat, JSON-safe fields for a report's "collection impact" block (merge into ``collection_impact``).

    ``impact`` is a ``CollectionImpact`` or its dict (None when no measurement exists).  Unmeasured values stay
    None - never 0 - so a report cannot present "not measured" as "no load"."""
    d = impact.to_dict() if hasattr(impact, "to_dict") else (impact if isinstance(impact, dict) else None)
    out: Dict[str, Any] = {"impact_measured": bool(d and d.get("measured"))}
    if capture_mode is not None:
        out["capture_mode"] = capture_mode
    if budget_exhausted is not None:
        out["budget_exhausted"] = bool(budget_exhausted)
    if exhaustion_reason:
        out["budget_exhaustion_reason"] = exhaustion_reason
    if not d:
        out["impact_notes"] = ["collection impact was not measured"]
        if measured_stop_ms is not None:
            out["measured_stop_ms"] = measured_stop_ms
        if bytes_read is not None:
            out["bytes_read"] = bytes_read
        return out
    tgt, sysd, attr = d.get("target") or {}, d.get("system") or {}, d.get("diagnosis_attributable") or {}
    stop = measured_stop_ms if measured_stop_ms is not None else d.get("measured_stop_ms")
    nbytes = bytes_read if bytes_read is not None else d.get("bytes_read")
    out.update({
        "measured_stop_ms": stop,
        "bytes_read": nbytes,
        "impact_window_ms": d.get("wall_ms"),
        "impact_transport": d.get("transport"),
        "target_cpu_ms_during_window": tgt.get("cpu_ms"),
        "target_ctx_switches_during_window": tgt.get("ctx_switches"),
        "target_runqueue_wait_ms_during_window": tgt.get("runqueue_wait_ms"),
        "system_cpu_busy_fraction": sysd.get("cpu_busy_fraction"),
        "attributable_cpu_ms": attr.get("attributable_cpu_ms"),
        "attributable_basis": attr.get("basis"),
        "collector_cpu_ms": attr.get("collector_cpu_ms"),
        "collector_max_rss_kb": attr.get("collector_max_rss_kb"),
        "impact_notes": list(d.get("notes") or []),
    })
    if d.get("remote_commands"):
        out["remote_commands"] = d["remote_commands"]
    return out


def impact_summary_lines(summary: Dict[str, Any]) -> List[str]:
    """Markdown bullet lines for the incident report's "collection impact" section."""
    def f(v: Any, unit: str = "", nd: int = 2) -> str:
        if v is None:
            return "not measured"
        return f"{v:.{nd}f}{unit}" if isinstance(v, float) else f"{v}{unit}"
    if not summary.get("impact_measured"):
        lines = ["- **Collection Impact**: not measured"]
    else:
        lines = [
            f"- **Target CPU during window** (target's own activity, not caused by us): `{f(summary.get('target_cpu_ms_during_window'), ' ms')}`"
            f" · context switches `{f(summary.get('target_ctx_switches_during_window'))}`"
            f" · run-queue wait `{f(summary.get('target_runqueue_wait_ms_during_window'), ' ms')}`",
            f"- **System CPU busy during window**: `{f(summary.get('system_cpu_busy_fraction'), '', 3)}`",
            f"- **Diagnosis-attributable CPU**: `{f(summary.get('attributable_cpu_ms'), ' ms')}` (basis: `{summary.get('attributable_basis') or 'n/a'}`)",
        ]
        if summary.get("collector_max_rss_kb") is not None or summary.get("collector_cpu_ms") is not None:
            lines.append(f"- **Collector process**: CPU `{f(summary.get('collector_cpu_ms'), ' ms')}` · peak RSS `{f(summary.get('collector_max_rss_kb'), ' KiB')}`")
    if summary.get("bytes_read") is not None:
        lines.append(f"- **Bytes Read**: `{summary['bytes_read']}`")
    if summary.get("budget_exhausted"):
        lines.append(f"- **Budget exhausted**: `{summary.get('budget_exhaustion_reason') or 'yes'}` (result is partial)")
    return lines
