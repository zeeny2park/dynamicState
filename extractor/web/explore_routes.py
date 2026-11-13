"""HTTP glue of the job-bound exploration routes (``/api/diagnose/{job_id}/...``).

The request handler (``server.DynamicStateRequestHandler``) has already checked the Host, the Origin and the session
token and validated the job id; this module validates every parameter, calls ``extractor.web.explore`` and answers
with plain data plus ko/en fragments (``extractor.web.ui.explore_fragments``).  No parameter names a pid, a host or a
file: those come from the job.

Routes (all read the target only; see docs/ui-redesign/API_CONTRACT.md "Exploration routes"):
  GET  {job}/chips                       related-information chips of each finding (no read)
  GET  {job}/thread/{tid}                stack, frame locals, locks held / waited for
  GET  {job}/threads?name=&limit=&filter= members of a thread group (/proc/pid/task, no memory read)
  GET  {job}/memory/maps                 mappings
  GET  {job}/memory/range?addr=&len= | ?expr=&len=   one bounded read (len <= 4096)
  GET  {job}/files                       open files (/proc/pid/fd)
  GET  {job}/modules                     modules, base addresses, debug information
  GET  {job}/vars?q=                     globals and statics from DWARF (no read)
  GET  {job}/value?expr=                 one evaluation
  GET  {job}/lock?name=                  a mutex, its owner and waiters
  GET  {job}/watch/events?after=         observation samples (SSE)
  GET  {job}/watch/status?after=         observation samples (polling)
  POST {job}/watch                       set what is observed and how often (server-side sampler; reads only)
  POST {job}/watch/stop                  stop sampling
  POST {job}/observation                 put the current observation into this job's report ("Add to report")
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from extractor.web import explore as X
from extractor.web.ui import explore_fragments as XF

GET_ACTIONS = frozenset({"chips", "thread", "threads", "memory", "files", "modules", "vars", "value", "lock", "watch"})
POST_ACTIONS = frozenset({"watch", "observation"})
QUERY_VALUE_MAX = 256


def _one(query: Dict[str, List[str]], name: str, default: Optional[str] = None) -> Optional[str]:
    vals = query.get(name)
    if not vals:
        return default
    if len(vals) != 1:
        raise X.ExploreError("INVALID_PARAM", f"{name} must be given once")
    if len(vals[0]) > QUERY_VALUE_MAX:
        raise X.ExploreError("INVALID_PARAM", f"{name} is too long")
    return vals[0]


def _int(raw: Optional[str], default: int, lo: int, hi: int, name: str) -> int:
    if raw is None:
        return default
    if not raw.isdigit() or len(raw) > 6 or not lo <= int(raw) <= hi:
        raise X.ExploreError("INVALID_PARAM", f"{name} must be an integer {lo}..{hi}")
    return int(raw)


def _frag(k: str, html: Dict[str, str], data: Dict[str, Any], cost: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {"success": True, "key": k, "html": html, "data": data, "cost": cost}


def _usable(job: Any) -> None:
    st = job.summary()["state"]
    if st not in ("running", "done"):
        raise X.ExploreError("NO_TARGET", "the diagnosis ended with an error; its target is not explored", 409)


def handle_get(h: Any, hub: X.ExploreHub, job: Any, rest: List[str], query: Dict[str, List[str]]) -> None:
    try:
        _usable(job)
        x = hub.get(job)
        act = rest[0]
        if act == "watch" and len(rest) == 2 and rest[1] in ("events", "status"):
            raw = (query.get("after") or ["0"])[0]
            if not raw.isdigit() or len(raw) > 9:
                raise X.ExploreError("INVALID_PARAM", "after must be a non-negative integer")
            ws = hub.watch(job, create=False)
            if ws is None and rest[1] == "status":
                h._send_json({"success": True, "version": 0, "watch": None})
                return
            if ws is None:
                raise X.ExploreError("NOT_FOUND", "nothing is observed for this diagnosis", 404)
            if rest[1] == "status":
                ws.touch()
                h._send_json({"success": True, "version": getattr(ws, "version", 0), "watch": ws.snapshot()})
            else:
                _stream_watch(h, ws, int(raw))
            return
        if len(rest) == 1 and act == "chips":
            if job.summary()["state"] != "done":
                raise X.ExploreError("NOT_FINISHED", "chips come with the verdict", 409)
            chips = x.chips()
            out = {n: XF.both(XF.chips_html, c, f"finding-{n}") for n, c in chips.items()}
            h._send_json({"success": True, "findings": out, "data": chips})
            return
        if act == "thread" and len(rest) == 2:
            tid = X.check_tid(rest[1])
            d = x.thread(tid)
            h._send_json(_frag(f"th:{tid}", XF.both(XF.thread_fragment, d),
                               {"frames": [{"i": f["i"], "fn": f["fn"]} for f in d["frames"]], "default_frame": d["default_frame"],
                                "name": d.get("name")}, d["cost"]))
            return
        if len(rest) == 1 and act == "threads":
            name = X.check_name(_one(query, "name"), "name")
            limit = _int(_one(query, "limit"), 20, 1, X.MEMBERS_MAX, "limit")
            flt = _one(query, "filter", "") or ""
            if flt and (not flt.isdigit() or len(flt) > 9):
                raise X.ExploreError("INVALID_PARAM", "filter must be digits of a tid")
            d = x.threads_named(name)
            h._send_json(_frag(f"members:{X._key(name)}", XF.both(XF.members_fragment, d, limit, flt),
                               {"count": len(d["members"])}, d["cost"]))
            return
        if act == "memory" and len(rest) == 2 and rest[1] == "maps":
            d = x.memory_maps()
            h._send_json(_frag("maps", XF.both(XF.maps_fragment, d), {"count": len(d["maps"])}, d["cost"]))
            return
        if act == "memory" and len(rest) == 2 and rest[1] == "range":
            a, e = _one(query, "addr"), _one(query, "expr")
            if (a is None) == (e is None):
                raise X.ExploreError("INVALID_PARAM", "give exactly one of addr and expr")
            length = X.parse_len(_one(query, "len"), 256)
            d = x.memory_range(X.parse_addr(a) if a is not None else None, length, X.check_expr(e) if e is not None else None)
            h._send_json(_frag("range:res", XF.both(XF.range_fragment, d),
                               {"addr": f"0x{d['addr']:x}", "len": d["len"], "status": d["status"]}, d["cost"]))
            return
        if len(rest) == 1 and act == "files":
            d = x.files()
            h._send_json(_frag("files", XF.both(XF.files_fragment, d), {"total": d["total"]}, d["cost"]))
            return
        if len(rest) == 1 and act == "modules":
            d = x.modules()
            h._send_json(_frag("mods", XF.both(XF.modules_fragment, d), {"total": d["total"]}, d["cost"]))
            return
        if len(rest) == 1 and act == "vars":
            q = X.check_query(_one(query, "q", ""))
            d = x.search(q)
            h._send_json(_frag("vars", XF.both(XF.vars_fragment, d), {"vars": [v["name"] for v in d["vars"]]}, d["cost"]))
            return
        if len(rest) == 1 and act == "value":
            expr = X.check_expr(_one(query, "expr"))
            d = x.value(expr)
            h._send_json(_frag(f"var:{X._key(expr)}", XF.both(XF.value_fragment, d),
                               {"status": d["status"], "type": d.get("type"), "pointer": d.get("pointer")}, d["cost"]))
            return
        if len(rest) == 1 and act == "lock":
            name = X.check_name(_one(query, "name"), "name")
            d = x.lock(name)
            h._send_json(_frag(f"lk:{X._key(name)}", XF.both(XF.lock_fragment, d),
                               {"owner_tid": d.get("owner_tid"), "waiters": d.get("waiter_count")}, d["cost"]))
            return
        raise X.ExploreError("NOT_FOUND", "route not found", 404)
    except X.ExploreError as exc:
        _error(h, exc)


def handle_post(h: Any, hub: X.ExploreHub, mgr: Any, job: Any, rest: List[str], body: Dict[str, Any]) -> None:
    try:
        _usable(job)
        if rest == ["watch"]:
            ws = hub.watch(job, create=True)
            ws.configure(body)
            h._send_json({"success": True, "version": getattr(ws, "version", 0), "watch": ws.snapshot()})
            return
        if rest == ["watch", "stop"]:
            ws = hub.watch(job, create=False)
            if ws is not None:
                ws.stop("stopped", "stopped by the user")
            h._send_json({"success": True, "watch": ws.snapshot() if ws else None})
            return
        if rest == ["observation"]:
            if job.summary()["state"] != "done":
                raise X.ExploreError("NOT_FINISHED", "the report exists once the diagnosis is finished", 409)
            if body.get("remove") is True:
                mgr.set_observation(job, None)
                h._send_json({"success": True, "observation": None})
                return
            ws = hub.watch(job, create=False)
            if ws is None or not ws.n:
                raise X.ExploreError("NOT_FOUND", "nothing has been observed yet", 404)
            snap = ws.snapshot()
            mgr.set_observation(job, snap)
            h._send_json({"success": True, "observation": {"samples": snap["samples"], "first_t": snap["first_t"],
                                                           "last_t": snap["last_t"], "seq": snap["seq"]}})
            return
        raise X.ExploreError("NOT_FOUND", "route not found", 404)
    except X.ExploreError as exc:
        _error(h, exc)


def _error(h: Any, exc: X.ExploreError) -> None:
    out = exc.to_dict()
    out["html"] = XF.both(XF.error_fragment, exc.code, exc.message)
    h._send_json(out, status=exc.status)


def _stream_watch(h: Any, ws: X.WatchSession, after: int) -> None:
    try:
        h.send_response(200)
        h.send_header("Content-Type", "text/event-stream; charset=utf-8")
        h.send_header("Cache-Control", "no-cache, no-transform")
        h.send_header("X-Accel-Buffering", "no")
        h.send_header("Connection", "close")
        h.end_headers()
        h.close_connection = True
        if h.command == "HEAD":
            return
        h.wfile.write(b"retry: 2000\n\n")
        h.wfile.flush()
        last = after
        while True:
            version, alive = ws.wait(last, 10.0)
            if version > last:
                payload = json.dumps({"version": version, "watch": ws.snapshot()}, ensure_ascii=False, default=str)
                h.wfile.write(f"id: {version}\nevent: watch\ndata: {payload}\n\n".encode("utf-8"))
                last = version
            elif not alive:
                break
            else:
                h.wfile.write(b": keepalive\n\n")
            h.wfile.flush()
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
