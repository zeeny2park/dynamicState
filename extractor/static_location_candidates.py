"""Static location candidates for a finding (roadmap stage 3, "정적 위치 후보").

When a finding names a variable, lock, function or thread but the engine could not observe *where in the code* the
defect happens, this module proposes candidate source lines: the call sites that grow, free, copy into or lock the
named object, found from the debug information (DWARF subprograms, variable DIEs and types, the line table) and the
source text of the debug image's own compilation units.

Honesty rules (they are the contract of this module):

* Every candidate is **statically derived, not observed**: ``basis`` is ``"static"`` and ``observed`` is ``False``.
  A candidate is never written into a finding's ``subjects`` (the confirmed names / locations), never changes a
  status or a verdict, and carries no confidence number.  The reader-facing text says "후보" / "candidate".
* Candidates are ranked, capped (``CANDIDATE_CAP``) and each one states the reason it was chosen.
* A finding with no defensible candidate gets none (``status`` says why: no debug information, no source text on
  this host, source newer than the binary, nothing in the code matches, category not covered).
* No target-process access at all: only the debug image (a local file, also for an SSH target where the adapter
  copied it) and the source files named by its DWARF.  Nothing under ``/proc`` is read, so a remote target goes
  through the same path as a local one.  Process data is used only as it already is in the result (thread rows of
  the process profile, the leak size class of the failing check), and only to rank candidates.

Entry point: :func:`attach_location_candidates` (one call from ``expert_diagnostic_engine._diagnose_run`` and one
from ``incident_report.result_from_session``).
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

CANDIDATE_CAP = 3
TIME_BUDGET_S = 4.0                 # whole-call cap; a big binary degrades to "not finished" instead of slowing diagnosis
LINE_TABLE_MAX_ROWS = 2_000_000     # decoded line-table rows read per binary
MAX_SOURCE_FILES = 400
MAX_SOURCE_BYTES = 16 << 20
MAX_FUNCTIONS = 20_000
_SUBPROCESS_TIMEOUT_S = 20

BASIS = "static"
METHOD = ("DWARF subprograms, variables and types + the DWARF line table + the source text of the debug image's "
          "compilation units (read on the diagnosing host)")
NOTE_EN = ("Candidates are statically derived from the debug information and the source text; they were not "
           "observed at runtime and do not confirm where the defect happened.")
NOTE_KO = "정적 분석으로 고른 후보입니다. 실행 중에 관측한 위치가 아니며, 결함이 생긴 위치를 확인한 것도 아닙니다."

STATUS_FOUND = "FOUND"
STATUS_NONE = "NO_CANDIDATE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"
STATUS_NO_DEBUG_INFO = "NO_DEBUG_INFO"
STATUS_NO_SOURCE = "NO_SOURCE"
STATUS_TIME_LIMIT = "TIME_LIMIT"
STATUS_ERROR = "ERROR"

_STATUS_TEXT = {
    STATUS_NONE: ("nothing in the code matched the finding's subjects", "발견의 대상과 맞는 코드 위치를 찾지 못함"),
    STATUS_NOT_APPLICABLE: ("no static candidate rule for this finding", "이 발견 유형에는 정적 후보 규칙이 없음"),
    STATUS_NO_DEBUG_INFO: ("no usable debug information in the debug image", "디버그 이미지에 쓸 수 있는 디버그 정보가 없음"),
    STATUS_NO_SOURCE: ("the source files named by the debug information are not on this host (or are newer than the "
                       "binary)", "디버그 정보가 가리키는 소스 파일이 이 호스트에 없거나 바이너리보다 새로움"),
    STATUS_TIME_LIMIT: ("static analysis stopped at its time limit", "정적 분석이 시간 한도에서 멈춤"),
    STATUS_ERROR: ("static analysis failed", "정적 분석 실패"),
}

_CATEGORIES = ("MEMORY_LEAK", "MAPPING_GROWTH", "MEMORY_CORRUPTION", "USE_AFTER_FREE", "INVALID_DOUBLE_FREE",
               "DEADLOCK_INDICATORS", "ORPHAN_LOCK", "SELF_DEADLOCK", "LOCK_CONTENTION", "THREAD_LEAK",
               "PROCESS_INSTABILITY")

# ------------------------------------------------------------------------------------------------ statement patterns
_ALLOC_RE = re.compile(r"\b(malloc|calloc|realloc|reallocarray|strdup|strndup|aligned_alloc|memalign|valloc|pvalloc)"
                       r"\s*\(|\bnew\s+[A-Za-z_]")
_MMAP_RE = re.compile(r"\b(mmap|mmap64|mremap)\s*\(")
_FREE_RE = re.compile(r"\b(free|cfree)\s*\(")
_DELETE_RE = re.compile(r"\bdelete\s*(\[\s*\])?\s*([A-Za-z_][\w.\->\[\]]*)")
_COPY_DEST_ARG = {"strcpy": 0, "strcat": 0, "sprintf": 0, "vsprintf": 0, "gets": 0, "memcpy": 0, "memmove": 0,
                  "strncpy": 0, "strncat": 0, "snprintf": 0, "vsnprintf": 0, "memset": 0, "fread": 0, "read": 1,
                  "recv": 1, "fgets": 0, "stpcpy": 0, "wcscpy": 0}
_COPY_LEN_ARG = {"memcpy": 2, "memmove": 2, "strncpy": 2, "strncat": 2, "memset": 2, "snprintf": 1, "vsnprintf": 1,
                 "read": 2, "recv": 2, "fgets": 1, "fread": 2}
_UNBOUNDED_COPY = {"strcpy", "strcat", "sprintf", "vsprintf", "gets", "stpcpy", "wcscpy"}
_COPY_RE = re.compile(r"\b(" + "|".join(sorted(_COPY_DEST_ARG, key=len, reverse=True)) + r")\s*\(")
_LOCK_FUNCS = ("pthread_mutex_lock", "pthread_mutex_trylock", "pthread_mutex_timedlock", "pthread_rwlock_wrlock",
               "pthread_rwlock_rdlock", "pthread_spin_lock", "mtx_lock", "mtx_timedlock")
_UNLOCK_FUNCS = ("pthread_mutex_unlock", "pthread_rwlock_unlock", "pthread_spin_unlock", "mtx_unlock")
_BLOCKING_RE = re.compile(r"\b(sleep|usleep|nanosleep|clock_nanosleep|pause|poll|ppoll|select|pselect|epoll_wait|"
                          r"epoll_pwait|read|recv|recvfrom|recvmsg|accept|accept4|pthread_cond_wait|"
                          r"pthread_cond_timedwait|sem_wait|sem_timedwait|pthread_join|futex|wait|waitpid|sigwait|"
                          r"sigsuspend|msgrcv|getchar|fgets|scanf|pthread_mutex_lock|pthread_barrier_wait|"
                          r"this_thread::sleep_for|sleep_for|sleep_until|wait_for|wait_until)\s*\(")
_LOOP_RE = re.compile(r"(?<![\w])(while|for)\s*\(|(?<![\w])do\s*(\{|$)")
_THREAD_CREATE_RE = re.compile(r"\bpthread_create\s*\(")
_STD_THREAD_RE = re.compile(r"\bstd::(thread|jthread)\s*[\w]*\s*[({]\s*&?\s*([A-Za-z_]\w*)")
_SETNAME_RE = re.compile(r"\b(pthread_setname_np|prctl)\s*\([^\"]*\"([^\"]{1,31})\"")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_C_KEYWORDS = frozenset("""if else while for do switch case default return break continue goto sizeof typeof struct
union enum const volatile static extern unsigned signed int long short char float double void bool _Bool NULL nullptr
true false auto register inline restrict new delete this""".split())


def _ident(name: str) -> "re.Pattern[str]":
    """``name`` as a stand-alone identifier, not a struct member (``x.name`` / ``x->name``)."""
    return re.compile(r"(?<![\w.])(?<!->)\b" + re.escape(name) + r"\b")


def _member(name: str) -> "re.Pattern[str]":
    return re.compile(r"(?:\.|->)\s*" + re.escape(name) + r"\b")


def _call_args(text: str, open_paren: int) -> List[str]:
    """Top-level comma-separated arguments of the call whose ``(`` is at ``open_paren``."""
    depth, cur, out = 0, [], []
    for ch in text[open_paren:]:
        if ch in "([{":
            depth += 1
            if depth == 1:
                continue
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                out.append("".join(cur).strip())
                return out
        elif ch == "," and depth == 1:
            out.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    out.append("".join(cur).strip())
    return out


_ASSIGN_RE = re.compile(r"^(?P<lhs>[^=]*?[^=!<>+\-*/%&|^])(?P<op>[+\-*/%&|^]?=)(?!=)(?P<rhs>.*)$")


def _strip_control(stmt: str) -> str:
    """``if (c) x = y`` -> ``x = y``; ``else x = y`` -> ``x = y`` (balanced parentheses of the condition)."""
    s = stmt.strip()
    while True:
        m = re.match(r"^(\}\s*)?(else\b\s*)", s)
        if m:
            s = s[m.end():].strip()
            continue
        m = re.match(r"^(if|while|switch)\s*\(", s)
        if not m:
            return s.lstrip("{").strip()
        depth = 0
        for i in range(m.end() - 1, len(s)):
            if s[i] == "(":
                depth += 1
            elif s[i] == ")":
                depth -= 1
                if depth == 0:
                    s = s[i + 1:].strip()
                    break
        else:
            return ""


def _assigns(code: str) -> List[Tuple[str, str]]:
    """(lhs, rhs) of every assignment statement on a line; declarations keep their declarator
    (``struct node *x = calloc(..)`` -> (``struct node *x``, ``calloc(..)``)).  Comparisons and loop headers are not
    assignments."""
    out: List[Tuple[str, str]] = []
    if re.match(r"^\s*for\s*\(", code):
        return out
    for stmt in code.split(";"):
        s = _strip_control(stmt)
        m = _ASSIGN_RE.match(s)
        if not m:
            continue
        lhs = m.group("lhs").strip()
        if not lhs or re.search(r"[A-Za-z_]\w*\s*\(", lhs) or lhs.startswith("return"):
            continue
        out.append((lhs, m.group("rhs").strip()))
    return out


def _assignment(code: str) -> Optional[Tuple[str, str]]:
    a = _assigns(code)
    return a[0] if a else None


def _lhs_name(lhs: str) -> Optional[str]:
    """The declared/assigned plain variable of an assignment's left side (``struct node *x`` -> ``x``)."""
    m = re.match(r"^[\w\s\*]*?\**\s*([A-Za-z_]\w*)\s*$", lhs)
    return m.group(1) if m else None


# ------------------------------------------------------------------------------------------------ program model
@dataclass
class _Var:
    name: str
    type_offset: Optional[int]
    is_parameter: bool = False


@dataclass
class _Func:
    name: str
    path: str
    file: str
    decl_line: int
    lines: List[int]                        # source lines with machine code (DWARF line table), sorted
    first: int
    last: int
    locals: Dict[str, _Var] = field(default_factory=dict)

    def code_lines(self) -> Set[int]:
        return set(self.lines)


@dataclass
class _Program:
    path: str
    status: str
    idx: Any = None
    funcs: Dict[str, _Func] = field(default_factory=dict)
    source: Dict[str, List[str]] = field(default_factory=dict)        # path -> raw lines
    clean: Dict[str, List[str]] = field(default_factory=dict)         # path -> lines without comments / string text
    globals: Dict[str, Any] = field(default_factory=dict)             # name -> DwarfVariable
    detail: str = ""

    # ---- text helpers
    def raw(self, f: _Func, line: int) -> str:
        src = self.source.get(f.path) or []
        return src[line - 1].strip() if 0 < line <= len(src) else ""

    def code(self, f: _Func, line: int) -> str:
        src = self.clean.get(f.path) or []
        return src[line - 1] if 0 < line <= len(src) else ""

    def body(self, f: _Func) -> Iterable[Tuple[int, str]]:
        for ln in range(f.first, f.last + 1):
            c = self.code(f, ln)
            if c.strip():
                yield ln, c

    def has_code(self, f: _Func, line: int) -> bool:
        """The line (or, for a statement continued on the next lines, one of the next two) has machine code."""
        if line in f.code_lines():
            return True
        c = self.code(f, line).rstrip()
        return not c.endswith((";", "{", "}")) and bool({line + 1, line + 2} & f.code_lines())


_PROGRAM_CACHE: Dict[Tuple[str, int, int], _Program] = {}
_PROGRAM_LOCK = threading.Lock()


def _strip_code(lines: List[str]) -> List[str]:
    """Comments removed and string / char literal contents blanked, line structure kept."""
    out, in_block = [], False
    for raw in lines:
        res, i, n = [], 0, len(raw)
        while i < n:
            if in_block:
                j = raw.find("*/", i)
                if j < 0:
                    i = n
                    break
                in_block, i = False, j + 2
                continue
            ch = raw[i]
            if raw.startswith("/*", i):
                in_block, i = True, i + 2
                continue
            if raw.startswith("//", i):
                break
            if ch in "\"'":
                j = i + 1
                while j < n and raw[j] != ch:
                    j += 2 if raw[j] == "\\" else 1
                res.append(ch + ch)
                i = j + 1
                continue
            res.append(ch)
            i += 1
        out.append("".join(res).rstrip("\n"))
    return out


def _run(cmd: List[str], max_lines: int, deadline: float) -> Optional[List[str]]:
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    except OSError:
        return None
    out: List[str] = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            out.append(line.rstrip("\n"))
            if len(out) >= max_lines or time.monotonic() > deadline:
                proc.kill()
                break
    finally:
        try:
            proc.stdout.close()  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001
            pass
        try:
            proc.wait(timeout=_SUBPROCESS_TIMEOUT_S)
        except Exception:  # noqa: BLE001
            proc.kill()
    return out


def _comp_dirs(path: str, deadline: float) -> List[Tuple[str, str]]:
    """(DW_AT_name, DW_AT_comp_dir) of every compilation unit (top-level DIEs only)."""
    out = _run(["readelf", "--debug-dump=info", "--dwarf-depth=1", path], 400_000, deadline) or []
    cus: List[Tuple[str, str]] = []
    name = comp = None
    for line in out:
        if "Compilation Unit @" in line:
            if name is not None or comp is not None:
                cus.append((name or "", comp or ""))
            name = comp = None
        elif "DW_AT_name" in line and name is None:
            name = line.split(":", 1)[1].split("):")[-1].strip() if ":" in line else None
            name = line.rsplit("): ", 1)[-1].strip() if "): " in line else (line.split(":", 2)[-1].strip())
        elif "DW_AT_comp_dir" in line and comp is None:
            comp = line.rsplit("): ", 1)[-1].strip() if "): " in line else line.split(":", 2)[-1].strip()
    if name is not None or comp is not None:
        cus.append((name or "", comp or ""))
    return cus


def _line_rows(path: str, deadline: float) -> List[Tuple[int, str, int]]:
    """(address, file basename, line) rows of the decoded DWARF line table, sorted by address."""
    out = _run(["readelf", "--debug-dump=decodedline", path], LINE_TABLE_MAX_ROWS, deadline) or []
    rows: List[Tuple[int, str, int]] = []
    rx = re.compile(r"^(\S+)\s+(\d+)\s+(0x[0-9a-fA-F]+)")
    for line in out:
        m = rx.match(line)
        if m:
            rows.append((int(m.group(3), 16), os.path.basename(m.group(1)), int(m.group(2))))
    rows.sort()
    return rows


def _is_system(path: str) -> bool:
    return path.startswith(("/usr/", "/lib/", "/opt/rh/")) or "/include/" in path and path.startswith("/")


def _load_program(debug_image: str, deadline: float) -> _Program:
    try:
        st = os.stat(debug_image)
    except OSError:
        return _Program(debug_image, STATUS_NO_DEBUG_INFO, detail="debug image not found")
    key = (os.path.abspath(debug_image), st.st_mtime_ns, st.st_size)
    with _PROGRAM_LOCK:
        hit = _PROGRAM_CACHE.get(key)
    if hit is not None:
        return hit
    prog = _build_program(key[0], st.st_mtime, deadline)
    if prog.status != STATUS_TIME_LIMIT:
        with _PROGRAM_LOCK:
            if len(_PROGRAM_CACHE) > 16:
                _PROGRAM_CACHE.clear()
            _PROGRAM_CACHE[key] = prog
    return prog


def _build_program(path: str, image_mtime: float, deadline: float) -> _Program:
    try:
        from .dwarf_indexer import DwarfIndexer
        idx = DwarfIndexer.get_index(path)
    except Exception as exc:  # noqa: BLE001
        return _Program(path, STATUS_NO_DEBUG_INFO, detail=f"{type(exc).__name__}: {exc}")
    # Every defined function with a source position, inlined-only ones (no code range of their own) included; a
    # function's source extent runs from its declaration line to the line before the next function of its file,
    # clipped to the last line with machine code (DWARF line table).  So a statement is attributed to the function
    # it is written in, also when the compiler inlined that function elsewhere.
    subs: Dict[str, Any] = {}
    for sp in idx.subprograms or []:
        if not sp.name or not sp.decl_file or not sp.decl_line or sp.is_declaration or _is_system(sp.decl_file):
            continue
        prev = subs.get(sp.name)
        if prev is None or (not prev.low_pc and sp.low_pc) or (len(sp.variables or []) > len(prev.variables or [])
                                                                and bool(prev.low_pc) == bool(sp.low_pc)):
            subs[sp.name] = sp
    if not subs:
        return _Program(path, STATUS_NO_DEBUG_INFO, idx=idx, detail="no DWARF subprograms with a source position")
    cus = _comp_dirs(path, deadline)
    rows = _line_rows(path, deadline)
    if time.monotonic() > deadline:
        return _Program(path, STATUS_TIME_LIMIT, idx=idx)
    if not rows:
        return _Program(path, STATUS_NO_DEBUG_INFO, idx=idx, detail="no DWARF line table")
    code_lines: Dict[str, Set[int]] = {}
    for _addr, base, ln in rows:
        if ln > 0:
            code_lines.setdefault(base, set()).add(ln)
    prog = _Program(path, STATUS_FOUND, idx=idx)
    resolved: Dict[str, Optional[str]] = {}
    newer: List[str] = []
    total_bytes = 0

    def _resolve(decl_file: str) -> Optional[str]:
        nonlocal total_bytes
        if decl_file in resolved:
            return resolved[decl_file]
        found: Optional[str] = None
        cands = [decl_file] if os.path.isabs(decl_file) else (
            [os.path.join(comp, decl_file) for name, comp in cus if comp and (name == decl_file)]
            + [os.path.join(comp, decl_file) for name, comp in cus if comp])
        for c in dict.fromkeys(cands):
            if _is_system(c) or not os.path.isfile(c):
                continue
            try:
                stc = os.stat(c)
            except OSError:
                continue
            if stc.st_mtime > image_mtime + 1.0:
                newer.append(c)   # edited after the build: its lines need not match the binary any more
                continue
            if len(prog.source) >= MAX_SOURCE_FILES or total_bytes + stc.st_size > MAX_SOURCE_BYTES:
                break
            try:
                with open(c, encoding="utf-8", errors="replace") as fh:
                    lines = fh.read().split("\n")
            except OSError:
                continue
            total_bytes += stc.st_size
            prog.source[c] = lines
            prog.clean[c] = _strip_code(lines)
            found = c
            break
        resolved[decl_file] = found
        return found

    by_file: Dict[str, List[Any]] = {}
    for sp in list(subs.values())[:MAX_FUNCTIONS]:
        if time.monotonic() > deadline:
            prog.status = STATUS_TIME_LIMIT
            break
        src = _resolve(sp.decl_file)
        if src:
            by_file.setdefault(src, []).append(sp)
    for src, sps in by_file.items():
        sps.sort(key=lambda x: int(x.decl_line))
        code = code_lines.get(os.path.basename(src), set())
        nlines = len(prog.source.get(src) or [])
        for k, sp in enumerate(sps):
            lo = int(sp.decl_line)
            hi = (int(sps[k + 1].decl_line) - 1) if k + 1 < len(sps) else nlines
            lines = sorted(ln for ln in code if lo <= ln <= hi)
            if not lines:
                continue
            f = _Func(name=sp.name, path=src, file=os.path.basename(src), decl_line=lo, lines=lines, first=lo,
                      last=lines[-1])
            for v in sp.variables or []:
                if v.name:
                    f.locals[v.name] = _Var(v.name, v.type_offset, bool(v.is_parameter))
            prog.funcs[sp.name] = f
    for v in list(idx.global_variables or []) + list(idx.static_variables or []):
        if v.name and v.name not in prog.globals and not v.is_declaration:
            prog.globals[v.name] = v
    if not prog.funcs and prog.status == STATUS_FOUND:
        prog.status = STATUS_NO_SOURCE
        prog.detail = "source not found" + (f" (newer than the binary: {', '.join(newer[:3])})" if newer else "")
    return prog


# ------------------------------------------------------------------------------------------------ DWARF type helpers
def _tag(t: Any) -> str:
    """DWARF tag without the ``DW_TAG_`` prefix (the indexer keeps the prefix)."""
    tag = str(getattr(t, "tag", "") or "")
    return tag[7:] if tag.startswith("DW_TAG_") else tag


def _canon(idx: Any, off: Optional[int], depth: int = 0) -> Any:
    t = idx.types_by_die.get(off) if off is not None else None
    while t is not None and depth < 12 and _tag(t) in ("typedef", "const_type", "volatile_type", "restrict_type",
                                                        "atomic_type"):
        t = idx.types_by_die.get(t.target_type_offset) if t.target_type_offset is not None else None
        depth += 1
    return t


def _pointee(idx: Any, off: Optional[int]) -> Any:
    """The type a pointer (or an array of pointers) points to, canonical; None for anything else."""
    t = _canon(idx, off)
    if t is not None and _tag(t) == "array_type":
        t = _canon(idx, t.target_type_offset)
    if t is not None and _tag(t) in ("pointer_type", "reference_type", "rvalue_reference_type"):
        return _canon(idx, t.target_type_offset)
    return None


def _type_key(t: Any) -> Optional[Tuple[str, str, int]]:
    if t is None or not getattr(t, "name", None):
        return None
    return (_tag(t), t.name, int(t.byte_size or 0))


def _type_label(t: Any) -> str:
    if t is None:
        return "?"
    word = {"structure_type": "struct ", "union_type": "union ", "class_type": "class "}.get(_tag(t), "")
    return f"{word}{t.name}"


def _malloc_chunk(n: int, pointer_size: int = 8) -> int:
    """glibc chunk size of a malloc(n) (64-bit: 16-byte alignment, 8-byte header, 32-byte minimum)."""
    align = 2 * pointer_size
    size = n + pointer_size
    size = (size + align - 1) & ~(align - 1)
    return max(size, 4 * pointer_size)


# ------------------------------------------------------------------------------------------------ candidates
@dataclass
class _Cand:
    func: _Func
    line: int
    action: str
    score: int
    reasons: List[Tuple[str, str]] = field(default_factory=list)

    def add(self, pts: int, en: str, ko: str) -> "_Cand":
        self.score += pts
        self.reasons.append((en, ko))
        return self


class _Ctx:
    def __init__(self, prog: _Program, finding: Dict[str, Any], report: Optional[Dict[str, Any]],
                 profile: Optional[Dict[str, Any]]):
        self.prog = prog
        self.idx = prog.idx
        self.finding = finding
        self.report = report if isinstance(report, dict) else {}
        self.profile = profile if isinstance(profile, dict) else {}
        det = [d for d in (finding.get("subject_details") or []) if isinstance(d, dict)]
        self.variables = [str(d.get("name")) for d in det if d.get("kind") == "variable"]
        self.locks = [str(d.get("name")) for d in det if d.get("kind") == "lock"]
        self.functions = [str(d.get("name")) for d in det if d.get("kind") == "function"]
        self.thread_names = [str(d.get("name")) for d in det if d.get("kind") == "thread_name"]
        self._calls: Dict[str, Set[str]] = {}

    # ---- subjects
    def roots(self) -> List[str]:
        """Leading identifiers of the variable subjects that are DWARF variables (``store.head`` -> ``store``)."""
        out: List[str] = []
        for v in self.variables:
            m = re.match(r"^\s*\(?\*?([A-Za-z_]\w*)", v)
            if not m or v.startswith("0x"):
                continue
            r = m.group(1)
            if (r in self.prog.globals or any(r in f.locals for f in self.prog.funcs.values())) and r not in out:
                out.append(r)
        return out

    def members(self) -> List[str]:
        out: List[str] = []
        for v in self.variables:
            for m in re.findall(r"(?:\.|->)([A-Za-z_]\w*)", v):
                if m not in out:
                    out.append(m)
        return out

    def root_type(self, root: str) -> Any:
        g = self.prog.globals.get(root)
        return _canon(self.idx, g.type_offset) if g is not None else None

    def var_type(self, f: _Func, name: str) -> Any:
        v = f.locals.get(name)
        if v is not None:
            return _canon(self.idx, v.type_offset)
        g = self.prog.globals.get(name)
        return _canon(self.idx, g.type_offset) if g is not None else None

    def var_pointee(self, f: _Func, name: str) -> Any:
        v = f.locals.get(name)
        if v is not None:
            return _pointee(self.idx, v.type_offset)
        g = self.prog.globals.get(name)
        return _pointee(self.idx, g.type_offset) if g is not None else None

    def shadowed(self, f: _Func, root: str) -> bool:
        return root in f.locals and root in self.prog.globals

    def refers(self, f: _Func, root: str, code: str) -> bool:
        if root not in self.prog.globals and root not in f.locals:
            return False
        if self.shadowed(f, root):
            return False
        return bool(_ident(root).search(code))

    # ---- call graph (from the source text of the analysed functions)
    def calls(self, f: _Func) -> Set[str]:
        if f.name not in self._calls:
            out: Set[str] = set()
            names = self.prog.funcs
            for _ln, code in self.prog.body(f):
                for m in re.finditer(r"([A-Za-z_]\w*)\s*\(", code):
                    n = m.group(1)
                    if n in names and n != f.name:
                        out.add(n)
                # a function passed as a value (thread start routine, callback)
                for m in _IDENT_RE.finditer(code):
                    if m.group(0) in names and m.group(0) != f.name and _THREAD_CREATE_RE.search(code):
                        out.add(m.group(0))
            self._calls[f.name] = out
        return self._calls[f.name]

    def reachable(self, starts: Iterable[str], depth: int = 5) -> Set[str]:
        seen: Set[str] = set()
        frontier = [s for s in starts if s in self.prog.funcs]
        for _ in range(depth):
            nxt = []
            for n in frontier:
                if n in seen:
                    continue
                seen.add(n)
                nxt.extend(self.calls(self.prog.funcs[n]))
            frontier = nxt
        seen.update(f for f in frontier if f in self.prog.funcs)
        return seen

    def thread_starts(self) -> Set[str]:
        """Functions handed to pthread_create / std::thread anywhere in the analysed code."""
        out: Set[str] = set()
        for f in self.prog.funcs.values():
            for ln, code in self.prog.body(f):
                m = _THREAD_CREATE_RE.search(code)
                if m:
                    args = _call_args(code, m.end() - 1)
                    if len(args) >= 3:
                        n = re.sub(r"[&()\s]|\(void\s*\*\s*\(\*\)\s*\(void\s*\*\)\)", "", args[2])
                        n = n.split(")")[-1]
                        if n in self.prog.funcs:
                            out.add(n)
                for m2 in _STD_THREAD_RE.finditer(code):
                    if m2.group(2) in self.prog.funcs:
                        out.add(m2.group(2))
        return out

    def named_thread_funcs(self) -> Dict[str, str]:
        """thread name -> the function that names the thread (``pthread_setname_np(.., "name")``) or, from the
        process profile (already collected), the function the thread of that name was observed in."""
        out: Dict[str, str] = {}
        wanted = set(self.thread_names)
        if not wanted:
            return out
        for f in self.prog.funcs.values():
            for _ln, raw in ((ln, self.prog.raw(f, ln)) for ln in range(f.first, f.last + 1)):
                m = _SETNAME_RE.search(raw)
                if m and m.group(2) in wanted and m.group(2) not in out:
                    out[m.group(2)] = f.name
        for row in ((self.profile.get("threads") or {}).get("rows") or []):
            if isinstance(row, dict) and row.get("name") in wanted and row.get("name") not in out \
                    and row.get("function") in self.prog.funcs:
                out[str(row["name"])] = str(row["function"])
        return out

    def observed_functions(self) -> Set[str]:
        """User functions seen on a thread's call stack in data the diagnosis already collected (unwound frames of
        the thread checks, not the estimated stack-scan ones; else the process profile's thread rows)."""
        out: Set[str] = set()
        sec = (self.report.get("section_d_detailed_inspection_results") or {}).get("checks") or []
        for c in sec:
            ao = c.get("actual_observations") if isinstance(c, dict) else None
            ci = ao.get("callstacks_info") if isinstance(ao, dict) else None
            for th in (ci.get("threads") if isinstance(ci, dict) else None) or []:
                for fr in (th.get("callstack") if isinstance(th, dict) else None) or []:
                    if isinstance(fr, dict) and not fr.get("estimated") and fr.get("function_name") in self.prog.funcs:
                        out.add(str(fr["function_name"]))
        if not out:
            for row in ((self.profile.get("threads") or {}).get("rows") or []):
                if isinstance(row, dict) and row.get("function") in self.prog.funcs:
                    out.add(str(row["function"]))
        return out

    def failing_observations(self) -> List[Dict[str, Any]]:
        rids = set(self.finding.get("recipe_ids") or [])
        sec = (self.report.get("section_d_detailed_inspection_results") or {}).get("checks") or []
        return [c.get("actual_observations") or {} for c in sec if isinstance(c, dict)
                and c.get("recipe_id") in rids and str(c.get("status")) == "FAIL"
                and isinstance(c.get("actual_observations"), dict)]

    def leak_size_classes(self) -> Set[int]:
        out: Set[int] = set()
        for ob in self.failing_observations():
            li = ob.get("leak_investigation")
            if not isinstance(li, dict):
                continue
            for row in list(li.get("unreachable_growth") or []) + list(li.get("growth_owners") or []):
                if isinstance(row, dict) and isinstance(row.get("chunk_size"), int) and not row.get("mmapped"):
                    out.add(int(row["chunk_size"]))
        return out


def _alloc_type(ctx: _Ctx, f: _Func, code: str, lhs_name: Optional[str]) -> Any:
    """The type an allocation statement allocates: ``sizeof(struct T)`` / ``sizeof *x`` / the pointee of the
    variable the result is stored in."""
    m = re.search(r"sizeof\s*\(?\s*(struct|union|class)?\s*([A-Za-z_]\w*)\s*\)?", code)
    if m:
        name = m.group(2)
        if m.group(1):
            for t in ctx.idx.types_by_name.get(name, []) or []:
                if _tag(t) in ("structure_type", "union_type", "class_type") and t.byte_size:
                    return t
        else:
            star = re.search(r"sizeof\s*\(?\s*\*\s*([A-Za-z_]\w*)", code)
            if star:
                return ctx.var_pointee(f, star.group(1))
    if lhs_name:
        return ctx.var_pointee(f, lhs_name)
    return None


def _size_reason(ctx: _Ctx, t: Any, classes: Set[int], cand: _Cand) -> None:
    if t is None or not classes or not t.byte_size:
        return
    chunk = _malloc_chunk(int(t.byte_size), int(getattr(ctx.idx, "pointer_size", 8) or 8))
    if chunk in classes:
        cand.add(2, f"`{_type_label(t)}` ({t.byte_size} B) fits the size class of the leaked blocks ({chunk} B)",
                 f"`{_type_label(t)}`({t.byte_size}B)가 누수된 블록의 크기 등급({chunk}B)과 맞음")


# ---- per category -----------------------------------------------------------------------------------------------
def _writes_root(ctx: _Ctx, f: _Func, root: str) -> List[int]:
    out = []
    for ln, code in ctx.prog.body(f):
        if any(ctx.refers(f, root, lhs) for lhs, _rhs in _assigns(code)):
            out.append(ln)
        elif re.search(r"(?<![\w.])" + re.escape(root) + r"\s*(\.|->)\s*(push_back|emplace_back|push_front|"
                       r"emplace_front|insert|emplace|append|add|push)\s*\(", code) and not ctx.shadowed(f, root):
            out.append(ln)
    return out


def _growth_candidates(ctx: _Ctx, alloc_re: "re.Pattern[str]", what_en: str, what_ko: str) -> List[_Cand]:
    """Owner known (leak owner / mapping owner): allocation sites in the functions that store into the owner, and in
    the functions they call; then the stores themselves."""
    out: List[_Cand] = []
    classes = ctx.leak_size_classes()
    observed = ctx.observed_functions()
    for root in ctx.roots():
        writers = {n: _writes_root(ctx, f, root) for n, f in ctx.prog.funcs.items()}
        writers = {n: ls for n, ls in writers.items() if ls}
        for n, wlines in writers.items():
            f = ctx.prog.funcs[n]
            for ln, code in ctx.prog.body(f):
                if alloc_re.search(code):
                    a = _assignment(code)
                    c = _Cand(f, ln, "allocation", 3, [(
                        f"{what_en} in `{n}`, which stores into `{root}` (line {wlines[0]})",
                        f"`{root}`에 저장하는 `{n}` 안의 {what_ko} ({wlines[0]}행)")])
                    _size_reason(ctx, _alloc_type(ctx, f, code, _lhs_name(a[0]) if a else None), classes, c)
                    if n in observed:
                        c.add(1, f"`{n}` was on a live thread's stack", f"`{n}`가 살아 있는 스레드의 스택에서 관측됨")
                    out.append(c)
            # one call level down: the allocation happens in a helper whose result the writer stores
            for callee in sorted(ctx.calls(f)):
                g = ctx.prog.funcs[callee]
                if callee in writers:
                    continue
                for ln, code in ctx.prog.body(g):
                    if alloc_re.search(code):
                        c = _Cand(g, ln, "allocation", 2, [(
                            f"{what_en} in `{callee}`, called from `{n}`, which stores into `{root}`",
                            f"`{root}`에 저장하는 `{n}`가 부르는 `{callee}` 안의 {what_ko}")])
                        a = _assignment(code)
                        _size_reason(ctx, _alloc_type(ctx, g, code, _lhs_name(a[0]) if a else None), classes, c)
                        out.append(c)
            for ln in wlines:
                out.append(_Cand(f, ln, "store", 1, [(f"stores into the growing owner `{root}`",
                                                      f"늘어나는 소유 변수 `{root}`에 저장")]))
    return out


def _escapes(ctx: _Ctx, f: _Func, p: str, after: int) -> bool:
    """``p`` (a local pointer) is freed, returned, stored or handed to a user function that stores its parameter."""
    pid = _ident(p)
    for ln, code in ctx.prog.body(f):
        if ln < after or not pid.search(code):
            continue
        if re.search(r"\breturn\b", code) or _FREE_RE.search(code) or _DELETE_RE.search(code):
            return True
        if any(not pid.search(lhs) and re.fullmatch(r"\s*(\([^()]*\)\s*)?&?\s*" + re.escape(p) + r"\s*", rhs)
               for lhs, rhs in _assigns(code)):
            return True
        for m in re.finditer(r"([A-Za-z_]\w*)\s*\(", code):
            g = ctx.prog.funcs.get(m.group(1))
            if g is None:
                continue
            args = _call_args(code, m.end() - 1)
            for i, arg in enumerate(args):
                if not pid.search(arg):
                    continue
                params = [v.name for v in g.locals.values() if v.is_parameter]
                pname = params[i] if i < len(params) else None
                if pname is None or _stores_param(ctx, g, pname):
                    return True
    return False


def _stores_param(ctx: _Ctx, g: _Func, pname: str) -> bool:
    for _ln, code in ctx.prog.body(g):
        if any(re.fullmatch(r"\s*(\([^()]*\)\s*)?&?\s*" + re.escape(pname) + r"\s*", rhs)
               for _lhs, rhs in _assigns(code)):
            return True
        if re.search(r"\breturn\s+" + re.escape(pname) + r"\b", code) or (
                (_FREE_RE.search(code) or _DELETE_RE.search(code)) and _ident(pname).search(code)):
            return True
    return False


def _unreachable_leak_candidates(ctx: _Ctx) -> List[_Cand]:
    """Owner unknown (no reference remains): the code that drops the last reference — an allocation kept only in a
    local the function never frees, returns or stores, or a node unlinked from a structure that way."""
    funcs = ctx.prog.funcs
    named = ctx.named_thread_funcs()
    scope = ctx.reachable(named.values()) if named else set(funcs)
    workers = ctx.reachable(ctx.thread_starts())
    observed = ctx.observed_functions()
    classes = ctx.leak_size_classes()
    out: List[_Cand] = []
    for n in sorted(scope):
        f = funcs[n]
        for p, var in f.locals.items():
            if var.is_parameter or _pointee(ctx.idx, var.type_offset) is None:
                continue
            pid = _ident(p)
            for ln, code in ctx.prog.body(f):
                a = next(((lhs, rhs) for lhs, rhs in _assigns(code) if _lhs_name(lhs) == p), None)
                if a is None:
                    continue
                if _ALLOC_RE.search(a[1]):
                    if _escapes(ctx, f, p, ln):
                        continue
                    c = _Cand(f, ln, "allocation", 3, [(
                        f"the result is kept only in local `{p}`; `{n}` neither frees, returns nor stores it",
                        f"결과를 지역 변수 `{p}`에만 두고 `{n}`에서 해제·반환·저장하지 않음")])
                    _size_reason(ctx, _alloc_type(ctx, f, code, p), classes, c)
                elif re.search(r"(->|\.)\s*\w+\s*$", a[1]) or re.search(r"(->|\.)\s*\w+\s*\]?\s*$", a[1]):
                    # p taken from a structure; it is unlinked if a later line stores one of p's links elsewhere
                    link_rx = re.compile(r"(?<![\w.])" + re.escape(p) + r"\s*->\s*\w+\s*$")
                    unlinks = [l2 for l2, c2 in ctx.prog.body(f) if l2 > ln and any(
                        link_rx.search(rhs) and not pid.search(lhs) for lhs, rhs in _assigns(c2))]
                    if not unlinks or _escapes(ctx, f, p, ln):
                        continue
                    t = _pointee(ctx.idx, var.type_offset)
                    c = _Cand(f, unlinks[-1], "unlink", 3, [(
                        f"unlinks `{p}` (a `{_type_label(t)}`) from the structure it was taken from; `{n}` neither "
                        f"frees, returns nor stores it",
                        f"`{p}`(`{_type_label(t)}`)를 꺼낸 구조에서 떼어 내고 `{n}`에서 해제·반환·저장하지 않음")])
                    _size_reason(ctx, t, classes, c)
                else:
                    continue
                if named and n in scope:
                    who = ", ".join(f"`{k}`" for k in sorted(named))
                    c.add(1, f"reached from the start function of thread {who}, which the leak was attributed to",
                          f"누수가 귀속된 스레드 {who}의 시작 함수에서 도달함")
                elif n in workers and n != "main":
                    c.add(1, f"`{n}` runs on a thread started by pthread_create", f"`{n}`는 pthread_create로 시작한 스레드에서 실행됨")
                if n in observed:
                    c.add(1, f"`{n}` was on a live thread's stack", f"`{n}`가 살아 있는 스레드의 스택에서 관측됨")
                out.append(c)
    return out


def _leak(ctx: _Ctx) -> List[_Cand]:
    return _growth_candidates(ctx, _ALLOC_RE, "allocation", "할당") if ctx.roots() else _unreachable_leak_candidates(ctx)


def _mapping(ctx: _Ctx) -> List[_Cand]:
    return _growth_candidates(ctx, _MMAP_RE, "mmap call", "mmap 호출") if ctx.roots() else []


def _same_type_base(ctx: _Ctx, f: _Func, expr: str, root: str) -> Optional[str]:
    """The local/parameter in ``expr`` (``r->buf``) whose type is the type of ``root`` or a pointer to it."""
    rt = ctx.root_type(root)
    rk = _type_key(rt)
    if rk is None:
        return None
    for m in re.finditer(r"(?<![\w.])(?<!->)([A-Za-z_]\w*)\s*(->|\.|\[)", expr):
        b = m.group(1)
        if b == root or b not in f.locals:
            continue
        if _type_key(ctx.var_pointee(f, b)) == rk or _type_key(ctx.var_type(f, b)) == rk:
            return b
    return None


def _corruption(ctx: _Ctx) -> List[_Cand]:
    out: List[_Cand] = []
    roots, members = ctx.roots(), ctx.members()
    for f in ctx.prog.funcs.values():
        for ln, code in ctx.prog.body(f):
            for m in _COPY_RE.finditer(code):
                fn = m.group(1)
                args = _call_args(code, m.end() - 1)
                di = _COPY_DEST_ARG[fn]
                if di >= len(args):
                    continue
                dest = args[di]
                c: Optional[_Cand] = None
                for root in roots:
                    if ctx.refers(f, root, dest):
                        c = _Cand(f, ln, "copy", 3, [(f"`{fn}` writes into `{root}`'s memory (`{dest}`)",
                                                      f"`{fn}`가 `{root}`의 메모리(`{dest}`)에 씀")])
                        break
                    b = _same_type_base(ctx, f, dest, root)
                    if b:
                        c = _Cand(f, ln, "copy", 3, [(
                            f"`{fn}` writes through `{b}`, which has the type of `{root}` (`{_type_label(ctx.root_type(root))}`)",
                            f"`{fn}`가 `{root}`와 같은 타입(`{_type_label(ctx.root_type(root))}`)인 `{b}`를 통해 씀")])
                        break
                if c is None and any(_member(mm).search(dest) for mm in members):
                    mm = next(mm for mm in members if _member(mm).search(dest))
                    c = _Cand(f, ln, "copy", 1, [(f"`{fn}` writes into a field named `{mm}`",
                                                  f"`{fn}`가 `{mm}` 필드에 씀")])
                if c is None:
                    continue
                if fn in _UNBOUNDED_COPY:
                    c.add(1, "the copy has no length bound", "복사 길이 제한이 없음")
                else:
                    li = _COPY_LEN_ARG.get(fn)
                    ln_arg = args[li] if li is not None and li < len(args) else ""
                    if re.fullmatch(r"\s*(\d+[uUlL]*|sizeof\b.*)\s*", ln_arg):
                        c.score -= 1
                        c.reasons.append(("the length is a constant", "복사 길이가 상수임"))
                    elif ln_arg:
                        c.add(1, f"the length comes from `{ln_arg}`", f"복사 길이가 `{ln_arg}`에서 옴")
                if re.search(r"[^+]\+[^+=]", dest):
                    c.add(1, "it writes at a computed offset", "계산된 위치에 씀")
                out.append(c)
    return out


def _free_args(code: str) -> List[str]:
    out = []
    for m in _FREE_RE.finditer(code):
        args = _call_args(code, m.end() - 1)
        if args:
            out.append(args[0])
    for m in _DELETE_RE.finditer(code):
        out.append(m.group(2))
    return out


def _cleared_after(ctx: _Ctx, f: _Func, line: int, expr: str) -> bool:
    for ln in range(line, min(f.last, line + 3) + 1):
        for lhs, rhs in _assigns(ctx.prog.code(f, ln)):
            if lhs.replace(" ", "") == expr.replace(" ", "") and re.fullmatch(r"\s*(NULL|0|nullptr)\s*", rhs):
                return True
    return False


def _free_sites(ctx: _Ctx, double: bool) -> Tuple[List[_Cand], Dict[str, int]]:
    """free/delete sites of the named pointer (or of a pointer of its type); returns the candidates and, per function,
    the line where it frees the named pointer itself."""
    out: List[_Cand] = []
    frees_root: Dict[str, int] = {}
    for root in ctx.roots():
        rt = _pointee(ctx.idx, (ctx.prog.globals.get(root) or _Var(root, None)).type_offset)
        rk = _type_key(rt)
        for f in ctx.prog.funcs.values():
            stores = [ln for ln, code in ctx.prog.body(f)
                      if any(ctx.refers(f, root, lhs) for lhs, _rhs in _assigns(code))]
            for ln, code in ctx.prog.body(f):
                for arg in _free_args(code):
                    if ctx.refers(f, root, arg):
                        c = _Cand(f, ln, "free", 3, [(f"frees `{arg}`", f"`{arg}`를 해제함")])
                        frees_root.setdefault(f.name, ln)
                    else:
                        base = re.match(r"^\s*\(?\s*([A-Za-z_]\w*)", arg)
                        b = base.group(1) if base else None
                        if not b or rk is None or _type_key(ctx.var_pointee(f, b)) != rk:
                            continue
                        c = _Cand(f, ln, "free", 2, [(
                            f"frees `{arg}`, a `{_type_label(rt)} *` like `{root}`",
                            f"`{root}`와 같은 `{_type_label(rt)} *` 타입인 `{arg}`를 해제함")])
                        later = [s for s in stores if s <= ln]
                        if later:
                            c.add(2, f"the same function stored that pointer in `{root}` (line {later[-1]})",
                                  f"같은 함수가 그 포인터를 `{root}`에 저장함({later[-1]}행)")
                        if double and f.locals.get(b) is not None and f.locals[b].is_parameter:
                            c.add(1, "it frees a pointer its caller passed in and may still hold",
                                  "호출한 쪽이 넘겨 계속 가지고 있을 수 있는 포인터를 해제함")
                    if _cleared_after(ctx, f, ln, arg):
                        c.score -= 2
                        c.reasons.append((f"`{arg}` is set to NULL right after", f"해제 직후 `{arg}`를 NULL로 지움"))
                    else:
                        c.add(1, "the pointer is not cleared afterwards", "해제 뒤 포인터를 지우지 않음")
                    out.append(c)
    return out, frees_root


def _deref(root: str) -> "re.Pattern[str]":
    return re.compile(r"(?<![\w.])(?<!->)(\*\s*)?\b" + re.escape(root) + r"\b\s*(\[[^\]]*\]\s*)*(->|\.|\[)|"
                      r"\*\s*" + re.escape(root) + r"\b")


def _uaf(ctx: _Ctx) -> List[_Cand]:
    out, frees_root = _free_sites(ctx, double=False)
    for root in ctx.roots():
        dr = _deref(root)
        for f in ctx.prog.funcs.values():
            if ctx.shadowed(f, root):
                continue
            free_ln = frees_root.get(f.name)
            freeing_calls: List[Tuple[int, str]] = []
            for ln, code in ctx.prog.body(f):
                for m in re.finditer(r"([A-Za-z_]\w*)\s*\(", code):
                    if m.group(1) in frees_root and m.group(1) != f.name:
                        freeing_calls.append((ln, m.group(1)))
            for ln, code in ctx.prog.body(f):
                if not dr.search(code) or _free_args(code):
                    continue
                if free_ln is not None and ln > free_ln:
                    out.append(_Cand(f, ln, "use", 3, [(f"uses `{root}` after the free on line {free_ln}",
                                                        f"{free_ln}행에서 해제한 뒤 `{root}`를 사용함")]))
                    continue
                prior = [(l2, g) for l2, g in freeing_calls if l2 < ln]
                if prior:
                    l2, g = prior[-1]
                    out.append(_Cand(f, ln, "use", 3, [(f"uses `{root}` after calling `{g}()` (line {l2}), which frees it",
                                                        f"`{root}`를 해제하는 `{g}()`를 부른 뒤({l2}행) 사용함")]))
    return out


def _double_free(ctx: _Ctx) -> List[_Cand]:
    return _free_sites(ctx, double=True)[0]


def _lock_lines(ctx: _Ctx, f: _Func, lock: str) -> Tuple[List[int], List[int]]:
    lk, ul = [], []
    name = re.escape(lock)
    lock_re = re.compile(r"\b(" + "|".join(_LOCK_FUNCS) + r")\s*\(\s*&?\s*\(?\s*" + name + r"\b|"
                         r"\b(lock_guard|unique_lock|scoped_lock|shared_lock)\b[^;]*[({]\s*" + name + r"\b|"
                         r"(?<![\w.])" + name + r"\s*(\.|->)\s*(lock|lock_shared|try_lock)\s*\(")
    unlock_re = re.compile(r"\b(" + "|".join(_UNLOCK_FUNCS) + r")\s*\(\s*&?\s*\(?\s*" + name + r"\b|"
                           r"(?<![\w.])" + name + r"\s*(\.|->)\s*(unlock|unlock_shared)\s*\(")
    if ctx.shadowed(f, lock):
        return lk, ul
    for ln, code in ctx.prog.body(f):
        if lock_re.search(code):
            lk.append(ln)
        if unlock_re.search(code):
            ul.append(ln)
    return lk, ul


def _locks(ctx: _Ctx, kind: str) -> List[_Cand]:
    out: List[_Cand] = []
    subj_funcs = set(ctx.functions) | set(ctx.named_thread_funcs().values())
    sites: Dict[str, Dict[str, Tuple[List[int], List[int]]]] = {}
    for lock in ctx.locks:
        if lock not in ctx.prog.globals and not any(lock in f.locals for f in ctx.prog.funcs.values()):
            continue
        for f in ctx.prog.funcs.values():
            lk, ul = _lock_lines(ctx, f, lock)
            if lk:
                sites.setdefault(lock, {})[f.name] = (lk, ul)
    for lock, per in sites.items():
        for n, (lk, ul) in per.items():
            f = ctx.prog.funcs[n]
            for ln in lk:
                c = _Cand(f, ln, "lock", 1, [(f"takes `{lock}`", f"`{lock}`를 잠금")])
                if n in subj_funcs:
                    c.add(1, f"`{n}` is named by the finding", f"`{n}`는 발견이 가리킨 함수임")
                if kind == "ORPHAN_LOCK" and len(ul) < len(lk):
                    c.add(2, f"`{n}` has no matching unlock of `{lock}`", f"`{n}`에 `{lock}`의 짝이 되는 해제가 없음")
                if kind == "SELF_DEADLOCK":
                    end = next((u for u in ul if u > ln), f.last)
                    for l2 in range(ln + 1, end):
                        for m in re.finditer(r"([A-Za-z_]\w*)\s*\(", ctx.prog.code(f, l2)):
                            g = m.group(1)
                            if g in per and g != n:
                                c.add(2, f"while holding it, calls `{g}()` (line {l2}), which takes `{lock}` again",
                                      f"잠근 채로 `{lock}`를 다시 잠그는 `{g}()`를 부름({l2}행)")
                                for gl in per[g][0]:
                                    out.append(_Cand(ctx.prog.funcs[g], gl, "lock", 3, [(
                                        f"takes `{lock}` again while its caller `{n}` holds it (call on line {l2})",
                                        f"호출한 `{n}`가 `{lock}`를 쥔 채로 다시 잠금({l2}행에서 호출)")]))
                if kind == "DEADLOCK_INDICATORS":
                    for other, per2 in sites.items():
                        if other == lock or n not in per2:
                            continue
                        if any(o > ln for o in per2[n][0]) and not any(ln < u < min(o for o in per2[n][0] if o > ln)
                                                                         for u in ul):
                            c.add(2, f"takes `{lock}` and then `{other}` while still holding it",
                                  f"`{lock}`를 쥔 채로 `{other}`를 잠금")
                        elif any(o < ln for o in per2[n][0]):
                            c.add(1, f"takes `{lock}` while holding `{other}`", f"`{other}`를 쥔 채로 `{lock}`를 잠금")
                out.append(c)
    return out


def _thread_leak(ctx: _Ctx) -> List[_Cand]:
    out: List[_Cand] = []
    targets = set(f for f in ctx.functions if f in ctx.prog.funcs) | set(ctx.named_thread_funcs().values())
    if not targets:
        return out
    for f in ctx.prog.funcs.values():
        joins = any(re.search(r"\bpthread_(join|detach)\s*\(", c) for _l, c in ctx.prog.body(f))
        for ln, code in ctx.prog.body(f):
            m = _THREAD_CREATE_RE.search(code)
            started = None
            if m:
                args = _call_args(code, m.end() - 1)
                if len(args) >= 3:
                    started = next((t for t in targets if _ident(t).search(args[2])), None)
            else:
                m2 = _STD_THREAD_RE.search(code)
                if m2 and m2.group(2) in targets:
                    started = m2.group(2)
            if not started:
                continue
            c = _Cand(f, ln, "thread_create", 3, [(f"starts `{started}`, the function of the accumulating threads",
                                                   f"쌓이는 스레드의 함수 `{started}`를 시작함")])
            if not joins:
                c.add(1, f"`{f.name}` neither joins nor detaches the thread", f"`{f.name}`가 스레드를 join·detach하지 않음")
            out.append(c)
    return out


def _loop_body_end(ctx: _Ctx, f: _Func, line: int) -> int:
    """Last line of the loop whose header is on ``line`` (brace matching; a braceless body is the next statement)."""
    depth, seen_open = 0, False
    for ln in range(line, f.last + 1):
        code = ctx.prog.code(f, ln)
        for ch in code:
            if ch == "{":
                depth += 1
                seen_open = True
            elif ch == "}":
                depth -= 1
                if seen_open and depth == 0:
                    return ln
        if not seen_open and ln > line and code.strip().endswith(";"):
            return ln
        if not seen_open and ln == line and code.rstrip().endswith(";") and not code.rstrip().endswith(");"):
            return ln
        if not seen_open and ln == line and re.search(r"\)\s*[^;{]+;\s*$", code):
            return ln
    return f.last


def _busy_loop(ctx: _Ctx) -> List[_Cand]:
    out: List[_Cand] = []
    spinning: Dict[str, str] = {}
    for ob in ctx.failing_observations():
        for row in ob.get("runaway_threads") or []:
            if isinstance(row, dict):
                for fn in (row.get("top_function"), row.get("function")):
                    if fn in ctx.prog.funcs and fn not in spinning:
                        spinning[str(fn)] = str(row.get("name") or row.get("tid") or "")
    for n, who in spinning.items():
        f = ctx.prog.funcs[n]
        for ln, code in ctx.prog.body(f):
            if not _LOOP_RE.search(code):
                continue
            end = _loop_body_end(ctx, f, ln)
            body = " ".join(ctx.prog.code(f, x) for x in range(ln, end + 1))
            # calls into a user function that blocks count as blocking too (one level)
            blocking = bool(_BLOCKING_RE.search(body)) or any(
                _BLOCKING_RE.search(" ".join(c for _l, c in ctx.prog.body(ctx.prog.funcs[g])))
                for g in re.findall(r"([A-Za-z_]\w*)\s*\(", body) if g in ctx.prog.funcs and g != n)
            if blocking:
                continue
            c = _Cand(f, ln, "loop", 3, [(f"loop in `{n}`, where thread `{who}` was observed spinning; nothing in the "
                                          f"loop blocks", f"스레드 `{who}`가 공회전하는 것이 관측된 `{n}`의 반복문이며, "
                                          f"반복문 안에 대기하는 호출이 없음")])
            cond = re.search(r"(while|for)\s*\((.*)\)", code)
            polled = []
            if cond:
                for m in _IDENT_RE.finditer(cond.group(2)):
                    v = m.group(0)
                    if v in ctx.prog.globals and v not in f.locals and v not in polled and v not in _C_KEYWORDS:
                        polled.append(v)
            if polled:
                inner = " ".join(ctx.prog.code(f, x) for x in range(ln + 1, end + 1))
                unchanged = [v for v in polled if not any(_ident(v).search(lhs) for lhs, _rhs in _assigns(inner))
                             and not re.search(r"(\+\+|--)\s*" + re.escape(v) + r"\b|\b" + re.escape(v) + r"\s*(\+\+|--)", inner)]
                names = ", ".join(f"`{v}`" for v in polled)
                c.add(1, f"its condition polls {names}" + (", which nothing in the loop changes" if unchanged else ""),
                      f"조건이 {names}를 반복해서 읽음" + (" (반복문 안에서 바꾸지 않음)" if unchanged else ""))
            out.append(c)
    return out


_HANDLERS = {
    "MEMORY_LEAK": _leak,
    "MAPPING_GROWTH": _mapping,
    "MEMORY_CORRUPTION": _corruption,
    "USE_AFTER_FREE": _uaf,
    "INVALID_DOUBLE_FREE": _double_free,
    "DEADLOCK_INDICATORS": lambda c: _locks(c, "DEADLOCK_INDICATORS"),
    "ORPHAN_LOCK": lambda c: _locks(c, "ORPHAN_LOCK"),
    "SELF_DEADLOCK": lambda c: _locks(c, "SELF_DEADLOCK"),
    "LOCK_CONTENTION": lambda c: _locks(c, "LOCK_CONTENTION"),
    "THREAD_LEAK": _thread_leak,
    "PROCESS_INSTABILITY": _busy_loop,
}


def _finalize(prog: _Program, cands: List[_Cand], cap: int) -> List[Dict[str, Any]]:
    best: Dict[Tuple[str, int], _Cand] = {}
    for c in cands:
        if c.score <= 0 or not prog.has_code(c.func, c.line):
            continue
        k = (c.func.path, c.line)
        if k not in best or c.score > best[k].score:
            best[k] = c
    ranked = sorted(best.values(), key=lambda c: (-c.score, c.func.path, c.line))[:cap]
    out = []
    for i, c in enumerate(ranked, 1):
        out.append({
            "rank": i,
            "location": f"{c.func.file}:{c.line}",
            "file": c.func.file,
            "path": c.func.path,
            "line": c.line,
            "function": c.func.name,
            "action": c.action,
            "statement": prog.raw(c.func, c.line)[:160],
            "reason": "; ".join(en for en, _ko in c.reasons),
            "reason_ko": "; ".join(ko for _en, ko in c.reasons),
            "basis": BASIS,
            "observed": False,
        })
    return out


def _empty(status: str, detail: str = "") -> Dict[str, Any]:
    en, ko = _STATUS_TEXT.get(status, ("", ""))
    return {"basis": BASIS, "observed": False, "status": status, "status_text": en, "status_text_ko": ko,
            "detail": detail, "method": METHOD, "note": NOTE_EN, "note_ko": NOTE_KO, "candidates": []}


def location_candidates(finding: Dict[str, Any], debug_image: Optional[str], *,
                        report: Optional[Dict[str, Any]] = None, profile: Optional[Dict[str, Any]] = None,
                        cap: int = CANDIDATE_CAP, deadline: Optional[float] = None) -> Dict[str, Any]:
    """Static location candidates for one finding (a ``DiagnoseResult.findings`` row); never raises."""
    cat = str(finding.get("category") or "")
    if cat not in _HANDLERS:
        return _empty(STATUS_NOT_APPLICABLE)
    if not debug_image:
        return _empty(STATUS_NO_DEBUG_INFO, "no debug image")
    deadline = deadline if deadline is not None else time.monotonic() + TIME_BUDGET_S
    try:
        prog = _load_program(debug_image, deadline)
        if prog.status != STATUS_FOUND:
            return _empty(prog.status, prog.detail)
        cands = _HANDLERS[cat](_Ctx(prog, finding, report, profile))
        res = _finalize(prog, cands, cap)
    except Exception as exc:  # noqa: BLE001 - candidates are an aid; they never break a diagnosis
        return _empty(STATUS_ERROR, f"{type(exc).__name__}: {exc}")
    if not res:
        return _empty(STATUS_NONE)
    out = _empty(STATUS_FOUND)
    out["status_text"], out["status_text_ko"] = "", ""
    out["candidates"] = res
    return out


def attach_location_candidates(findings: List[Dict[str, Any]], debug_image: Optional[str], *,
                               report: Optional[Dict[str, Any]] = None, profile: Optional[Dict[str, Any]] = None,
                               cap: int = CANDIDATE_CAP) -> float:
    """Sets ``finding["location_candidates"]`` on every finding (see :func:`location_candidates`).  Adds nothing to
    ``subjects``, ``status`` or any verdict.  Returns the seconds spent.  Never raises."""
    t0 = time.monotonic()
    deadline = t0 + TIME_BUDGET_S
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        t1 = time.monotonic()
        try:
            f["location_candidates"] = location_candidates(f, debug_image, report=report, profile=profile, cap=cap,
                                                           deadline=deadline)
        except Exception as exc:  # noqa: BLE001
            f["location_candidates"] = _empty(STATUS_ERROR, f"{type(exc).__name__}: {exc}")
        f["location_candidates"]["elapsed_s"] = round(time.monotonic() - t1, 3)
    return round(time.monotonic() - t0, 3)
