"""Result schema for the QEMU matrix (pure logic, no QEMU needed)."""
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

SCHEMA = "dynamicstate.qemu_matrix.v1"

PASS = "PASS"
FAIL = "FAIL"
UNSUPPORTED = "UNSUPPORTED-AS-EXPECTED"
BLOCKED = "BLOCKED"
SKIPPED = "SKIPPED"
CHECK_STATUSES = (PASS, FAIL, UNSUPPORTED, BLOCKED, SKIPPED)

CHECK_IDS = (
    "C1_collector_deploy_and_slice",
    "C1b_noexec_fallback_location",
    "C2a_daemon_channel",
    "C2b_no_collector_fallback",
    "C3_abi_detection",
    "C4a_deadlock_diagnosis",
    "C4b_glibc_only_gating",
    "C4c_futex_syscall_names",
    "C5_collection_cost",
    "C6_process_discovery_and_identity",
)


def check(check_id: str, name: str, status: str, summary: str, details: Optional[Dict[str, Any]] = None,
          duration_s: Optional[float] = None, remote_commands: Optional[int] = None,
          known_defect: Optional[str] = None) -> Dict[str, Any]:
    if status not in CHECK_STATUSES:
        raise ValueError(f"bad check status {status!r}")
    d: Dict[str, Any] = {"id": check_id, "name": name, "status": status, "summary": summary,
                         "details": details or {}}
    if duration_s is not None:
        d["duration_s"] = round(float(duration_s), 2)
    if remote_commands is not None:
        d["remote_commands"] = int(remote_commands)
    if known_defect:
        d["known_defect"] = known_defect
    return d


def overall(checks: List[Dict[str, Any]], infrastructure_error: Optional[str] = None) -> str:
    """PASS: no FAIL (known defects excluded), INCOMPLETE: guest never ran, FAIL otherwise."""
    if infrastructure_error:
        return "INCOMPLETE"
    bad = [c for c in checks if c["status"] == FAIL and not c.get("known_defect")]
    return "FAIL" if bad else "PASS"


def new_result(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "entry": entry["name"],
        "title": entry["title"],
        "started_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_s": None,
        "overall": None,
        "infrastructure_error": None,
        "guest": {},
        "checks": [],
        "teardown": {},
    }


def validate_result(doc: Dict[str, Any]) -> List[str]:
    """Return a list of schema problems (empty == valid)."""
    errs: List[str] = []
    if doc.get("schema") != SCHEMA:
        errs.append("schema")
    for k in ("entry", "title", "started_utc", "overall", "checks", "guest", "teardown"):
        if k not in doc:
            errs.append(f"missing {k}")
    if doc.get("overall") not in ("PASS", "FAIL", "INCOMPLETE", None):
        errs.append("overall value")
    seen = set()
    for c in doc.get("checks", []):
        for k in ("id", "name", "status", "summary", "details"):
            if k not in c:
                errs.append(f"check missing {k}")
        if c.get("status") not in CHECK_STATUSES:
            errs.append(f"check {c.get('id')} status {c.get('status')!r}")
        if c.get("id") in seen:
            errs.append(f"duplicate check {c.get('id')}")
        seen.add(c.get("id"))
        if c.get("status") == BLOCKED and not c.get("summary"):
            errs.append(f"BLOCKED check {c.get('id')} needs a reason")
    return errs


def table_rows(docs: List[Dict[str, Any]]) -> List[List[str]]:
    """Rows for the markdown summary: one row per check id, one column per entry."""
    ids: List[str] = []
    for d in docs:
        for c in d["checks"]:
            if c["id"] not in ids:
                ids.append(c["id"])
    rows = []
    for cid in ids:
        row = [cid]
        for d in docs:
            m = next((c for c in d["checks"] if c["id"] == cid), None)
            row.append(m["status"] if m else "-")
        rows.append(row)
    return rows
