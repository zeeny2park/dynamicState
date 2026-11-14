"""Symptom text -> symptom class -> requested investigation plan (roadmap stage 2).

The same problem described in different words must give the same investigation plan.  This module is the one
place that interprets a symptom.  It is pure (no process access, no LLM): ``interpret_symptom(text, fields)``.

Interpretation steps
  1. Normalise: NFKC, case-fold, every character that is not a letter or digit becomes a space (so ``use-after-free``,
     ``free()`` and ``Use After Free`` read alike).  Two views are kept: an English view (single spaces, word
     boundaries are enforced) and a compact view without spaces (Korean has no reliable spacing: ``메모리 누수``
     and ``메모리누수`` are the same words).
  2. Each symptom class has a vocabulary in both languages: phrases (strong / medium / weak) and *pairs*, a
     subject word near a trend word (``memory`` ... ``growing``; ``메모리`` ... ``늘어``) in either order.  A
     pair is what lets ``memory usage of this process keeps growing`` and ``it eats more and more memory`` mean
     the same without listing both sentences.
  3. Longest match first: a word used by a longer phrase is not counted again by a shorter one (so the ``leak``
     of ``file descriptor leak`` is not a memory leak).  A generic class gives way to a specific one (a crash
     that is a ``double free`` is a double free; anything specific beats ``general health check``).
  4. Confidence (explicit, see ``classify_scores``):
       HIGH  the best class scored >= MIN_CLASS_SCORE and at least DOMINANCE times the runner-up;
       LOW   otherwise: nothing matched ("no_match"), only weak evidence ("weak_evidence") or two classes
             compete ("conflicting_classes").
     LOW confidence never selects a narrow plan: the planner takes the broad multi-domain plan and the result and
     report say that the symptom was not understood specifically.
  5. Optional structured fields (``SymptomFields``) are shared by the CLI, the MCP tool and the web API.  When
     ``symptom_kind`` is given it decides the class; free text alone behaves as in step 4.

Negation ("not a deadlock") is not interpreted: a negated term still counts, which at worst yields conflicting
classes and therefore the broad plan.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .diagnostic_recipes import (
    CATEGORY_ABNORMAL_VARIABLE_CHANGES, CATEGORY_DATA_RACE_INDICATORS, CATEGORY_DEADLOCK_INDICATORS,
    CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY, CATEGORY_INVALID_DOUBLE_FREE, CATEGORY_MEMORY_CORRUPTION,
    CATEGORY_MEMORY_LEAK, CATEGORY_PROCESS_INSTABILITY, CATEGORY_RESOURCE_EXHAUSTION, CATEGORY_STACK_CORRUPTION,
    CATEGORY_UNEXPECTED_STATE_TRANSITIONS, CATEGORY_USE_AFTER_FREE,
)

# Categories registered by recipe definition files (their string values; importing the plugin modules here
# would be circular).
_CAT_THREAD_LEAK = "THREAD_LEAK"
_CAT_FD_LEAK = "FD_LEAK"
_CAT_LOCK_CONTENTION = "LOCK_CONTENTION"

# --------------------------------------------------------------------------------------------- confidence rule
STRONG, MEDIUM, WEAK = 3.0, 2.0, 1.0
MIN_CLASS_SCORE = 2.0      # below this the evidence is "weak": one medium phrase is enough, a lone weak word is not
DOMINANCE = 2.0            # the best class must score at least this many times the runner-up
CONF_HIGH, CONF_LOW = "HIGH", "LOW"
REASON_OK, REASON_NO_MATCH, REASON_WEAK, REASON_CONFLICT = "clear", "no_match", "weak_evidence", "conflicting_classes"
SOURCE_TEXT, SOURCE_STRUCTURED, SOURCE_DEFAULT = "text", "structured", "default"
HEALTH_CHECK = "health_check"
NOT_UNDERSTOOD_CLASS = "unspecific"   # the class name reported when LOW confidence selected the broad plan

# --------------------------------------------------------------------------------------------- classes


@dataclass(frozen=True)
class SymptomClass:
    id: str
    primary_category: str                      # the engine category reported as the classification
    categories: Tuple[Tuple[str, float], ...]  # (recipe category, relevance weight) the plan is built from
    label_en: str
    label_ko: str
    broad: bool = False                        # plan = broad multi-domain screening


def _c(id_: str, primary: str, cats: Sequence[Tuple[str, float]], en: str, ko: str, broad: bool = False) -> SymptomClass:
    return SymptomClass(id_, primary, tuple(cats), en, ko, broad)


_P, _R = 0.8, 0.5
CLASSES: Dict[str, SymptomClass] = {c.id: c for c in (
    _c("memory_growth", CATEGORY_MEMORY_LEAK, [(CATEGORY_MEMORY_LEAK, _P)], "memory growth / leak", "메모리 증가·누수"),
    _c("hang_deadlock", CATEGORY_DEADLOCK_INDICATORS, [(CATEGORY_DEADLOCK_INDICATORS, _P)],
       "hang / deadlock", "멈춤·교착 상태"),
    _c("cpu_spin", CATEGORY_PROCESS_INSTABILITY, [(CATEGORY_DEADLOCK_INDICATORS, _P)],
       "busy CPU / spinning thread", "CPU 과다 사용·스핀"),
    _c("crash_corruption", CATEGORY_MEMORY_CORRUPTION, [(CATEGORY_MEMORY_CORRUPTION, _P)],
       "crash / memory corruption", "크래시·메모리 손상"),
    _c("use_after_free", CATEGORY_USE_AFTER_FREE, [(CATEGORY_USE_AFTER_FREE, _P)], "use after free", "해제 후 사용"),
    _c("double_free", CATEGORY_INVALID_DOUBLE_FREE, [(CATEGORY_INVALID_DOUBLE_FREE, _P)],
       "double free", "이중 해제"),
    _c("stack_corruption", CATEGORY_STACK_CORRUPTION, [(CATEGORY_STACK_CORRUPTION, _P), (CATEGORY_MEMORY_CORRUPTION, _R)],
       "stack corruption", "스택 손상"),
    _c("data_race", CATEGORY_DATA_RACE_INDICATORS, [(CATEGORY_DATA_RACE_INDICATORS, _P)], "data race", "데이터 레이스"),
    _c("thread_growth", CATEGORY_RESOURCE_EXHAUSTION, [(_CAT_THREAD_LEAK, _P)],
       "growing thread count", "스레드 수 증가"),
    _c("fd_leak", CATEGORY_RESOURCE_EXHAUSTION, [(_CAT_FD_LEAK, _P)],
       "file descriptor / socket leak", "파일 디스크립터·소켓 누수"),
    _c("slow_contended", _CAT_LOCK_CONTENTION, [(_CAT_LOCK_CONTENTION, _P), (CATEGORY_DEADLOCK_INDICATORS, _R)],
       "slowness / lock contention", "느림·락 경합"),
    _c("process_instability", CATEGORY_PROCESS_INSTABILITY, [(CATEGORY_PROCESS_INSTABILITY, _P)],
       "unstable process / restarts", "프로세스 불안정·재시작"),
    _c("variable_anomaly", CATEGORY_ABNORMAL_VARIABLE_CHANGES, [(CATEGORY_ABNORMAL_VARIABLE_CHANGES, _P)],
       "abnormal variable value", "변수 값 이상"),
    _c("state_transition", CATEGORY_UNEXPECTED_STATE_TRANSITIONS, [(CATEGORY_UNEXPECTED_STATE_TRANSITIONS, _P)],
       "unexpected state transition", "예상 밖 상태 전이"),
    _c("state_inconsistency", CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY, [(CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY, _P)],
       "inconsistent state", "상태 불일치"),
    _c("resource_exhaustion", CATEGORY_RESOURCE_EXHAUSTION, [(CATEGORY_RESOURCE_EXHAUSTION, _P)],
       "resource exhaustion", "자원 고갈"),
    _c(HEALTH_CHECK, CATEGORY_PROCESS_INSTABILITY, [], "general health check", "전반적 상태 점검", broad=True),
)}

# A generic class gives way to a specific one that scored >= MIN_CLASS_SCORE.
YIELDS_TO: Dict[str, Tuple[str, ...]] = {
    "crash_corruption": ("use_after_free", "double_free", "stack_corruption", "process_instability"),
    "resource_exhaustion": ("fd_leak", "thread_growth", "memory_growth"),
    "state_inconsistency": ("state_transition", "variable_anomaly"),
    HEALTH_CHECK: tuple(i for i in CLASSES if i != HEALTH_CHECK),
}

# --------------------------------------------------------------------------------------------- vocabulary
# English terms: lower case words.  ``*`` inside a word = any letters (``leak*`` = leak, leaks, leaking);
# ``~`` = up to four other words.  Without ``*`` a word must match whole.  Korean terms: written without spaces.
# Pairs: (subjects, trends): a subject and a trend within a few words / characters, either order.

_P2 = MEDIUM


def _v(strong: Sequence[str] = (), medium: Sequence[str] = (), weak: Sequence[str] = (),
       pairs: Sequence[Tuple[Sequence[str], Sequence[str]]] = ()) -> Dict[str, Any]:
    return {"strong": list(strong), "medium": list(medium), "weak": list(weak), "pairs": [(list(s), list(t)) for s, t in pairs]}


_GROW_EN = ["grow*", "increas*", "climb*", "go* up", "went up", "ris*", "keeps going", "bloat*", "balloon*", "expand*",
            "more and more", "never come* down", "never drop*", "accumulat*", "pil* up", "only go* up"]
_GROW_KO = ["늘어", "늘고", "늘수록", "늘기만", "늘었", "증가", "커지", "커져", "불어", "올라", "쌓", "많아"]

VOCAB: Dict[str, Dict[str, Any]] = {
    "memory_growth": _v(
        strong=["memory leak*", "leak* ~ memory", "memory growth", "heap growth", "rss growth", "unbounded growth", "out of memory",
                "oom", "memory exhaust*", "unfreed", "never freed", "allocations accumulat*", "alloc* free imbalance",
                "alloc* imbalance", "memory bloat*",
                "메모리 누수", "메모리 증가", "힙 증가", "rss 증가", "메모리 고갈", "해제되지않", "할당 해제 불균형", "할당 불균형",
                "해제 불균형", "메모리 릭"],
        medium=["leak*", "누수", "새는", "새고", "샌다"],
        pairs=[(["memory", "rss", "heap", "footprint", "ram", "메모리", "힙"],
                _GROW_EN + ["high", "huge", "too much", "eats", "eating", "eat", "grabs"]
                + _GROW_KO + ["높", "잡아먹", "먹어", "차지"])]),
    "hang_deadlock": _v(
        strong=["deadlock*", "lock inversion", "circular wait", "livelock*", "wait* for each other", "wait* for ~ lock*",
                "mutex stuck", "데드락", "교착", "락 역전", "뮤텍스 대기", "락 대기", "서로 기다"],
        medium=["hang*", "hung", "stuck", "frozen", "froze", "freez*", "unresponsive", "not respond*", "stopped respond*",
                "stop* respond*", "no response", "stall*", "blocked", "not being processed", "nothing happens",
                "stopped working", "halted", "멈췄", "멈춤", "멈춘", "멈추", "먹통", "응답없", "응답이없", "응답하지",
                "프리징", "블록", "대기중", "안돌아", "안움직"]),
    "cpu_spin": _v(
        strong=["busy loop*", "busy wait*", "spin*", "infinite loop*", "stuck at 100", "full cpu core", "무한 루프", "스핀",
                "바쁜 대기"],
        pairs=[(["cpu", "processor", "코어"],
                ["100", "high", "busy", "burn*", "max*", "full", "pinned", "hog*", "eat*", "spik*", "heavy", "lot of",
                 "높", "많이", "점유", "잡아먹", "사용률", "쓰고", "사용하고"])]),
    "crash_corruption": _v(
        strong=["corrupt*", "segfault*", "segmentation fault*", "sigsegv", "sigbus", "sigill", "bus error", "buffer overflow",
                "heap overflow", "buffer overrun", "wild pointer", "bad pointer", "invalid memory access", "trampl*",
                "clobber*", "overwrit*", "garbled", "메모리 오염", "메모리 손상", "메모리 깨", "오염", "손상", "세그폴트",
                "세그멘테이션", "오버플로우", "침범", "잘못된 포인터", "유효하지 않은 메모리"],
        medium=["crash*", "core dump*", "abort*", "sigabrt", "크래시", "죽었", "죽고", "죽네", "죽는", "강제종료", "코어 덤프"],
        weak=["깨졌", "깨진"],   # "broken" alone says little: any object can be broken
        pairs=[(["data", "데이터"], ["wrong", "strange", "weird", "odd", "bad", "garbage", "garbled", "broken",
                                    "이상", "깨", "틀", "망가", "꼬"])]),
    "use_after_free": _v(
        strong=["use after free", "uaf", "dangling*", "freed memory", "freed object*", "freed pointer*", "freed buffer*",
                "freed block*", "after ~ freed", "already ~ freed", "dereferenc* ~ freed", "access* ~ freed",
                "read* ~ freed", "유즈 애프터 프리", "해제 후 사용", "해제된 객체", "해제된 포인터", "해제된 메모리", "댄글링",
                "이미 해제", "이미 free", "free한포인터"]),
    "double_free": _v(
        strong=["double free*", "double dealloc*", "double delete*", "free* twice", "freed twice", "release* twice",
                "delet* twice", "free* ~ two times", "free* ~ twice", "dealloc* ~ twice", "이중 해제", "더블 프리", "두 번 해제",
                "두 번 free", "free 두 번", "중복 해제", "해제 두 번", "이미 해제된 메모리 해제"]),
    "stack_corruption": _v(
        strong=["stack corruption", "stack smash*", "stack overflow", "stack canary", "stack trampl*", "return address",
                "call stack ~ trash*", "call stack ~ corrupt*", "call stack ~ garbage", "스택 손상", "스택 깨",
                "스택 오버플로", "스택 카나리", "스택 침범", "스택 스매싱", "스택 망가"],
        pairs=[(["stack", "스택"], ["trash*", "smash*", "corrupt*", "clobber*", "overflow", "canary", "overrun", "깨", "손상",
                                    "오염", "침범", "망가", "카나리"])]),
    "data_race": _v(
        strong=["data race*", "race condition*", "unsynchroni*", "torn", "without ~ lock*", "without ~ synchroni*",
                "missing lock*", "concurrent write*", "데이터 레이스", "경쟁 상태", "레이스 컨디션", "동시 접근", "동시 쓰기",
                "동기화 누락", "락 없이"],
        medium=["race", "레이스", "동기화"]),
    "thread_growth": _v(
        strong=["thread leak*", "leak* ~ thread*", "thread explosion", "too many threads", "스레드 누수", "쓰레드 누수",
                "스레드 폭증", "스레드 너무 많", "스레드 계속 생성", "스레드 계속 늘"],
        pairs=[(["thread", "threads", "스레드", "쓰레드"],
                _GROW_EN + ["never exit*", "never finish*", "never end*", "never terminat*", "created and never"]
                + _GROW_KO + ["생성되기만", "종료가안", "종료되지않"])]),
    "fd_leak": _v(
        strong=["file descriptor leak*", "fd leak*", "socket leak*", "handle leak*", "leak* ~ socket*", "leak* ~ descriptor*",
                "leak* ~ handle*", "too many open files", "emfile", "fd 누수", "파일 디스크립터 누수", "소켓 누수",
                "핸들 누수", "파일 핸들 누수"],
        pairs=[(["file descriptor*", "descriptor*", "fd", "fds", "open file*", "file handle*", "handle*", "socket*",
                 "파일디스크립터", "디스크립터", "열린파일", "파일핸들", "핸들", "소켓"],
                _GROW_EN + ["leak*", "never ~ clos*", "not clos*", "keep* ~ open"]
                + _GROW_KO + ["누수", "닫히지", "닫지", "안닫"])]),
    "slow_contended": _v(
        strong=["lock contention", "contended", "contention", "lock convoy", "convoy", "락 경합", "경합", "락 병목"],
        medium=["slow*", "sluggish", "latency", "lag", "laggy", "bad performance", "poor performance", "throughput",
                "bottleneck", "queue* up", "느려", "느린", "느리", "느림", "버벅", "지연", "렉", "성능 저하", "병목"],
        weak=["lock*", "mutex*", "락", "뮤텍스", "wait* on ~ lock*", "wait* on ~ mutex*"]),
    "process_instability": _v(
        strong=["process instability", "unstable", "instability", "crash loop*", "flapping", "flaky", "restart*", "respawn*",
                "keeps dying", "dies every", "keeps exiting", "keeps terminating", "keeps crashing", "crash* repeatedly",
                "frequent crash*", "crash* again and again", "dying", "terminating on its own",
                "프로세스 불안정", "불안정", "잦은 크래시", "재시작", "재부팅", "비정상 종료", "자주 죽", "자꾸 죽", "계속 죽",
                "간헐적 종료", "간헐적으로 종료", "종료되는", "꺼지"]),
    "variable_anomaly": _v(
        strong=["abnormal variable*", "variable jump*", "boundary value*", "boundary violat*", "out of range",
                "unexpected value*", "wrong value*", "변수 비정상", "카운터 이상", "카운터 값", "예상치 못한 값", "경계값",
                "범위 초과", "범위 벗어", "엉뚱한 값", "값 튀", "값 이상", "값 갑자기", "변수 갑자기"],
        medium=["jumped", "changes suddenly", "suddenly chang*", "비정상적으로 바뀌"],
        pairs=[(["counter*", "variable*", "global*", "value*", "카운터", "변수", "값"],
                ["unexpected", "wrong", "crazy", "weird", "strange", "odd", "bogus", "jump*", "spik*", "suddenly", "invalid",
                 "abnormal", "이상", "튀", "갑자기", "비정상", "엉뚱", "예상치"])]),
    "state_transition": _v(
        strong=["state transition*", "invalid state", "illegal transition*", "illegal state", "state machine*",
                "unexpected state", "state violation*", "상태 전이", "상태 머신", "유효하지 않은 상태", "불법 전이",
                "예상치 못한 상태", "상태 위반"],
        medium=["went from ~ to", "goes from ~ to", "changed from ~ to", "switched from ~ to", "moved from ~ to"]),
    "state_inconsistency": _v(
        strong=["state inconsisten*", "inconsistent*", "invariant*", "mismatch*", "contradict*", "disagree*", "out of sync",
                "상태 불일치", "불변식", "내부 상태", "불일치", "일치하지 않", "맞지않", "모순", "정합성", "일관성", "어긋"]),
    "resource_exhaustion": _v(
        strong=["resource exhaustion", "exhaust*", "out of resources", "out of ~ resources", "resources exhausted",
                "out of sockets", "fd exhaustion", "thread limit*", "quota exceeded", "resource limit*", "no more ~ handles",
                "no more ~ sockets", "no more ~ available", "리소스 고갈", "자원 고갈", "자원 부족", "리소스 부족", "리소스 한도",
                "자원 바닥", "바닥났", "소켓 부족", "fd 고갈", "스레드 한도", "한도 걸", "고갈"]),
    HEALTH_CHECK: _v(
        strong=["health check*", "healthy", "status check*", "overall check*", "general check*", "any problem*",
                "anything ~ wrong", "anything ~ off", "something ~ wrong", "is ~ process ok", "is it ok",
                "look over", "take a look", "check whether ~ process", "check if ~ process", "diagnose process",
                "investigate process", "find bug*", "find problem*", "상태 점검", "상태 검사", "이상 유무",
                "이상 없", "문제 있는지", "문제있는지", "프로세스 점검", "건강 상태", "전체적", "종합 분석", "종합 점검",
                "뭐가문제", "무슨 문제"]),
}

# --------------------------------------------------------------------------------------------- normalisation


def normalise(text: Optional[str]) -> Tuple[str, str]:
    """Return ``(en_view, compact_view)``: lower-cased text with every non-alphanumeric run turned into one space
    (padded with spaces), and the same text without any space."""
    t = unicodedata.normalize("NFKC", str(text or "")).casefold()
    t = "".join(ch if (ch.isalnum()) else " " for ch in t)
    words = t.split()
    return " " + " ".join(words) + " ", "".join(words)


_HANGUL = re.compile(r"[ㄱ-ㆎ가-힣]")
_GAP_WORDS = 4


def _is_ko(term: str) -> bool:
    return bool(_HANGUL.search(term))


def _en_regex(term: str) -> "re.Pattern[str]":
    """Compile an English term: words separated by single spaces; ``*`` suffix = any letters; ``~`` = 0..4 words."""
    toks = term.split()
    out = ""
    for i, w in enumerate(toks):
        if w == "~":
            out += r"(?:[a-z0-9]+ ){0,%d}" % _GAP_WORDS      # the gap carries its own trailing space
            continue
        out += re.escape(w.rstrip("*")) + (r"[a-z0-9]*" if w.endswith("*") else r"(?![a-z0-9])")
        if i < len(toks) - 1:
            out += " "
    return re.compile(r"(?<![a-z0-9])" + out)


_KO_PARTICLE = r"(?:에서|으로|에는|에도|[이가은는을를도만에의과와로])?"


def _ko_regex(term: str) -> "re.Pattern[str]":
    """Korean term: matched in the compact view.  A space in the term is a word boundary where a particle
    (이/가/은/는/을/를/에/의 ...) may sit, so ``메모리 누수`` also matches ``메모리가 누수`` (compact: 메모리가누수)."""
    segs = [re.escape(x.replace("*", "")) for x in term.lower().split() if x.replace("*", "")]
    return re.compile(_KO_PARTICLE.join(segs))


@dataclass
class _Term:
    cls: str
    weight: float
    view: str                 # "en" | "ko"
    pat: "re.Pattern[str]"
    label: str


@dataclass
class _Pair:
    cls: str
    weight: float
    subject: _Term
    trend: _Term
    view: str                 # view the pair is matched in ("en": token window, "ko": compact char window)
    label: str


def _compile_term(cls: str, weight: float, term: str, force_ko_view: bool = False) -> _Term:
    if _is_ko(term) or force_ko_view:
        if _is_ko(term):
            return _Term(cls, weight, "ko", _ko_regex(term), term)
        # an English word inside the compact view: match it without word boundaries
        return _Term(cls, weight, "ko", re.compile(re.escape("".join(term.split()).lower().replace("*", ""))), term)
    return _Term(cls, weight, "en", _en_regex(term), term)


def _build() -> Tuple[List[_Term], List[_Pair]]:
    terms: List[_Term] = []
    pairs: List[_Pair] = []
    for cls, v in VOCAB.items():
        for tier, w in (("strong", STRONG), ("medium", MEDIUM), ("weak", WEAK)):
            for t in v[tier]:
                terms.append(_compile_term(cls, w, t))
        for subjects, trends in v["pairs"]:
            for s in subjects:
                for t in trends:
                    ko = _is_ko(s) or _is_ko(t)
                    view = "ko" if ko else "en"
                    pairs.append(_Pair(cls, _P2, _compile_term(cls, _P2, s, ko), _compile_term(cls, _P2, t, ko), view,
                                       f"{s}~{t}"))
    return terms, pairs


_TERMS, _PAIRS = _build()
_EN_WINDOW_WORDS = 6
_KO_WINDOW_CHARS = 24

# --------------------------------------------------------------------------------------------- matching


@dataclass
class _Match:
    cls: str
    weight: float
    view: str
    spans: List[Tuple[int, int]]
    label: str

    @property
    def covered(self) -> int:
        return sum(e - s for s, e in self.spans)


def _find_matches(en: str, ko: str) -> List[_Match]:
    views = {"en": en, "ko": ko}
    found: List[_Match] = []
    for t in _TERMS:
        for m in t.pat.finditer(views[t.view]):
            if m.end() > m.start():
                found.append(_Match(t.cls, t.weight, t.view, [(m.start(), m.end())], t.label))
    for p in _PAIRS:
        text = views[p.view]
        subj = [m.span() for m in p.subject.pat.finditer(text) if m.end() > m.start()]
        if not subj:
            continue
        trn = [m.span() for m in p.trend.pat.finditer(text) if m.end() > m.start()]
        for ss in subj:
            for ts in trn:
                if ss[0] < ts[1] and ts[0] < ss[1]:
                    continue  # the same characters cannot be both
                a, b = (ss, ts) if ss[0] < ts[0] else (ts, ss)
                if p.view == "en":
                    gap = text[a[1]:b[0]].count(" ") - 1
                    ok = gap <= _EN_WINDOW_WORDS
                else:
                    ok = b[0] - a[1] <= _KO_WINDOW_CHARS
                if ok:
                    found.append(_Match(p.cls, p.weight, p.view, [ss, ts], p.label))
    return found


def score_classes(text: Optional[str]) -> Tuple[Dict[str, float], List[_Match]]:
    """Score every class: longest match first, a character is used by one match only."""
    en, ko = normalise(text)
    matches = _find_matches(en, ko)
    matches.sort(key=lambda m: (-m.covered, -m.weight))
    used: Dict[str, List[Tuple[int, int]]] = {"en": [], "ko": []}
    scores: Dict[str, float] = {}
    accepted: List[_Match] = []
    for m in matches:
        if any(s < ue and us < e for s, e in m.spans for us, ue in used[m.view]):
            continue
        used[m.view].extend(m.spans)
        scores[m.cls] = scores.get(m.cls, 0.0) + m.weight
        accepted.append(m)
    # a very short request that only says "check" / "점검" is a broad request
    if len(en.split()) <= 4 and (re.search(r"(?<![a-z])(check|inspect)", en) or any(w in ko for w in ("검사", "점검", "확인"))):
        scores[HEALTH_CHECK] = max(scores.get(HEALTH_CHECK, 0.0), MEDIUM)
    for generic, specifics in YIELDS_TO.items():
        if scores.get(generic) and any(scores.get(s, 0.0) >= MIN_CLASS_SCORE for s in specifics):
            scores[generic] = 0.0
    return {k: v for k, v in scores.items() if v > 0}, accepted


def classify_scores(scores: Mapping[str, float]) -> Tuple[Optional[str], str, str, float, Optional[str]]:
    """Apply the confidence rule.  Returns ``(class or None, level, reason, confidence 0..1, runner_up)``.

    HIGH  <=>  best >= MIN_CLASS_SCORE and best >= DOMINANCE * runner_up.  Otherwise LOW with reason
    no_match (nothing scored), weak_evidence (best < MIN_CLASS_SCORE) or conflicting_classes.
    The numeric confidence is best / (best + runner_up + 1), capped at 0.95, and 0 when LOW.
    """
    ranked = sorted(((s, c) for c, s in scores.items() if s > 0), key=lambda x: (-x[0], x[1]))
    if not ranked:
        return None, CONF_LOW, REASON_NO_MATCH, 0.0, None
    best, best_cls = ranked[0]
    second, second_cls = ranked[1] if len(ranked) > 1 else (0.0, None)
    if best < MIN_CLASS_SCORE:
        return None, CONF_LOW, REASON_WEAK, 0.0, best_cls
    if second > 0 and best < DOMINANCE * second:
        return None, CONF_LOW, REASON_CONFLICT, 0.0, second_cls
    return best_cls, CONF_HIGH, REASON_OK, round(min(0.95, best / (best + second + 1.0)), 2), second_cls


# --------------------------------------------------------------------------------------------- structured input
SYMPTOM_FIELD_NAMES: Tuple[str, ...] = ("symptom_kind", "symptom_frequency", "symptom_duration", "affected_area",
                                         "related_objects")
KIND_VALUES: Tuple[str, ...] = tuple(CLASSES)
FREQUENCY_VALUES: Tuple[str, ...] = ("constant", "intermittent", "once")
AREA_VALUES: Tuple[str, ...] = ("memory", "threads", "cpu", "locks", "files", "network", "state", "other")
_AREA_HINT: Dict[str, str] = {"memory": "memory_growth", "threads": "thread_growth", "cpu": "cpu_spin",
                              "locks": "slow_contended", "files": "fd_leak"}
MAX_TEXT, MAX_OBJECTS = 200, 20

FIELD_HELP: Dict[str, str] = {
    "symptom_kind": "kind of symptom (decides the investigation plan; free text is then only context): "
                    + ", ".join(KIND_VALUES),
    "symptom_frequency": "how often it happens: " + ", ".join(FREQUENCY_VALUES),
    "symptom_duration": "how long it has been going on (free text, e.g. '3 hours')",
    "affected_area": "what is affected: " + ", ".join(AREA_VALUES),
    "related_objects": "functions, variables, locks or other names the reporter associates with it",
}


class SymptomFieldError(ValueError):
    """An invalid structured symptom field; the message names the field and the allowed values."""


@dataclass(frozen=True)
class SymptomFields:
    symptom_kind: Optional[str] = None
    symptom_frequency: Optional[str] = None
    symptom_duration: Optional[str] = None
    affected_area: Optional[str] = None
    related_objects: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        for k in SYMPTOM_FIELD_NAMES:
            v = getattr(self, k)
            if v not in (None, ()):
                d[k] = list(v) if isinstance(v, tuple) else v
        return d

    def is_empty(self) -> bool:
        return not self.to_dict()


def _enum(name: str, value: Any, allowed: Sequence[str]) -> Optional[str]:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, str):
        raise SymptomFieldError(f"{name} must be a string, one of: {', '.join(allowed)}")
    v = re.sub(r"[\s\-]+", "_", value.strip().lower())
    if v not in allowed:
        raise SymptomFieldError(f"{name} must be one of: {', '.join(allowed)} (got {value!r})")
    return v


def parse_symptom_fields(raw: Any) -> Optional[SymptomFields]:
    """Validate structured symptom input (a mapping with any of ``SYMPTOM_FIELD_NAMES``, a ``SymptomFields`` or None).

    Returns None when no field is given.  Raises ``SymptomFieldError`` on an invalid value or an unknown field.
    """
    if raw is None:
        return None
    if isinstance(raw, SymptomFields):
        return None if raw.is_empty() else raw
    if not isinstance(raw, Mapping):
        raise SymptomFieldError("symptom fields must be an object")
    unknown = sorted(set(raw) - set(SYMPTOM_FIELD_NAMES))
    if unknown:
        raise SymptomFieldError(f"unknown symptom field(s): {', '.join(unknown)}; allowed: {', '.join(SYMPTOM_FIELD_NAMES)}")
    dur = raw.get("symptom_duration")
    if dur is not None and (not isinstance(dur, str) or len(dur) > MAX_TEXT):
        raise SymptomFieldError(f"symptom_duration must be a string of at most {MAX_TEXT} characters")
    objs = raw.get("related_objects")
    if objs is None:
        objs_t: Tuple[str, ...] = ()
    else:
        if isinstance(objs, str):
            objs = [objs]
        if (not isinstance(objs, (list, tuple)) or len(objs) > MAX_OBJECTS
                or any(not isinstance(o, str) or len(o) > MAX_TEXT for o in objs)):
            raise SymptomFieldError(f"related_objects must be a list of at most {MAX_OBJECTS} strings "
                                    f"of at most {MAX_TEXT} characters")
        objs_t = tuple(o.strip() for o in objs if o.strip())
    f = SymptomFields(
        symptom_kind=_enum("symptom_kind", raw.get("symptom_kind"), KIND_VALUES),
        symptom_frequency=_enum("symptom_frequency", raw.get("symptom_frequency"), FREQUENCY_VALUES),
        symptom_duration=(dur.strip() or None) if isinstance(dur, str) else None,
        affected_area=_enum("affected_area", raw.get("affected_area"), AREA_VALUES),
        related_objects=objs_t,
    )
    return None if f.is_empty() else f


_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:(?:::|->|\.)[A-Za-z_][A-Za-z0-9_]*)*$")


def related_identifiers(objs: Iterable[str]) -> Tuple[List[str], List[str]]:
    """Split related objects into ``(variables, functions)`` that look like C/C++ identifiers; the rest is context only."""
    variables: List[str] = []
    functions: List[str] = []
    for o in objs:
        o = o.strip()
        if o.endswith("()") and _IDENT.match(o[:-2]):
            functions.append(o[:-2])
        elif _IDENT.match(o):
            variables.append(o)
    return variables, functions


# --------------------------------------------------------------------------------------------- result


@dataclass
class SymptomInterpretation:
    symptom_class: str                        # a CLASSES id, or NOT_UNDERSTOOD_CLASS
    source: str                               # text | structured | default
    understood: bool                          # False <=> the broad plan was used because the text was unclear
    confidence_level: str                     # HIGH | LOW
    confidence: float
    reason: str                               # clear | no_match | weak_evidence | conflicting_classes
    primary_category: str
    candidate_categories: List[Tuple[str, float]]
    broad_plan: bool
    scores: Dict[str, float] = field(default_factory=dict)
    competing_class: Optional[str] = None
    text_class: Optional[str] = None          # structured kind given: what the text alone would have said
    fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "symptom_class": self.symptom_class, "source": self.source, "understood": self.understood,
            "confidence_level": self.confidence_level, "confidence": self.confidence, "reason": self.reason,
            "primary_category": self.primary_category, "broad_plan": self.broad_plan,
            "scores": dict(self.scores), "competing_class": self.competing_class, "text_class": self.text_class,
            "fields": dict(self.fields),
        }


_FALLBACK_PRIMARY = CATEGORY_PROCESS_INSTABILITY


def interpret_symptom(text: Optional[str], fields: Any = None) -> SymptomInterpretation:
    """Interpret a symptom (free text and/or structured fields).  Pure and deterministic."""
    f = parse_symptom_fields(fields)
    fdict = f.to_dict() if f else {}
    raw_text = (text or "").strip()
    scores, _ = score_classes(raw_text)
    if f and f.affected_area in _AREA_HINT:
        hint = _AREA_HINT[f.affected_area]
        # a hint next to a text only supports it; without any text the area is all there is
        scores[hint] = scores.get(hint, 0.0) + (WEAK if raw_text else MEDIUM)
    text_cls, level, reason, conf, runner = classify_scores(scores)

    if f and f.symptom_kind:
        cls = CLASSES[f.symptom_kind]
        return SymptomInterpretation(cls.id, SOURCE_STRUCTURED, True, CONF_HIGH, 1.0, REASON_OK, cls.primary_category,
                                     list(cls.categories), cls.broad, scores, None, text_cls, fdict)
    if not raw_text and not (f and f.affected_area):
        cls = CLASSES[HEALTH_CHECK]
        return SymptomInterpretation(cls.id, SOURCE_DEFAULT, True, CONF_HIGH, 1.0, REASON_OK, cls.primary_category,
                                     [], True, {}, None, None, fdict)
    if text_cls is None:
        return SymptomInterpretation(NOT_UNDERSTOOD_CLASS, SOURCE_TEXT, False, CONF_LOW, 0.0, reason, _FALLBACK_PRIMARY,
                                     [], True, scores, runner, None, fdict)
    cls = CLASSES[text_cls]
    return SymptomInterpretation(cls.id, SOURCE_TEXT, True, CONF_HIGH, conf, REASON_OK, cls.primary_category,
                                 list(cls.categories), cls.broad, scores, runner, None, fdict)


# --------------------------------------------------------------------------------------------- entry points
# The CLI, the MCP tool and the web API take the same optional fields (SYMPTOM_FIELD_NAMES); these helpers are
# the only place that knows how each front end spells them.

def add_cli_arguments(parser: Any) -> None:
    """Add the structured symptom options to an argparse parser (``--symptom-kind`` ... ``--related-object``)."""
    parser.add_argument("--symptom-kind", dest="symptom_kind", choices=KIND_VALUES, default=None,
                        help=FIELD_HELP["symptom_kind"])
    parser.add_argument("--symptom-frequency", dest="symptom_frequency", choices=FREQUENCY_VALUES, default=None,
                        help=FIELD_HELP["symptom_frequency"])
    parser.add_argument("--symptom-duration", dest="symptom_duration", type=str, default=None,
                        help=FIELD_HELP["symptom_duration"])
    parser.add_argument("--affected-area", dest="affected_area", choices=AREA_VALUES, default=None,
                        help=FIELD_HELP["affected_area"])
    parser.add_argument("--related-object", dest="related_objects", action="append", default=None,
                        help=FIELD_HELP["related_objects"] + " (repeatable)")


def fields_from_mapping(values: Mapping[str, Any]) -> Optional[SymptomFields]:
    """Structured fields from any mapping that may carry other keys too (web request body, argparse namespace
    as a dict, MCP tool arguments).  Raises ``SymptomFieldError`` on an invalid value."""
    return parse_symptom_fields({k: values[k] for k in SYMPTOM_FIELD_NAMES if values.get(k) not in (None, "", [])})
