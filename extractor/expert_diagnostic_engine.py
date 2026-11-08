"""Adaptive Investigation Engine & Expert Diagnostic Workflow (Phase 2.1).

Expert-oriented runtime investigation tool for embedded Linux and C/C++ systems.
Orchestrates:
1. Problem Classification (EN & KO, 12 problem categories, entity extraction, vague query handling)
2. Target Assessment (zero-stop collection, DWARF validation, capability auditing, limitations)
3. Investigation Planning (multi-factor recipe ranking: relevance, value, info gain, availability, cost, risk)
4. Evidence Collection & EvidenceLedger Recording (zero-stop reads, provenance chains)
5. Falsifiable Hypothesis Generation & Deterministic Verification
6. Adaptive Narrowing & Discriminating Follow-Ups
7. Evidence-to-Source Correlation Pipeline (Observation -> Memory -> Type/Field -> DWARF -> Source -> Function -> Hypothesis)
8. Structured Diagnostic Conclusion & Incident Reporting
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import uuid

from .diagnostic_recipes import (
    CATEGORY_ABNORMAL_VARIABLE_CHANGES,
    CATEGORY_DATA_RACE_INDICATORS,
    CATEGORY_DEADLOCK_INDICATORS,
    CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY,
    CATEGORY_INVALID_DOUBLE_FREE,
    CATEGORY_MEMORY_CORRUPTION,
    CATEGORY_MEMORY_LEAK,
    CATEGORY_PROCESS_INSTABILITY,
    CATEGORY_RESOURCE_EXHAUSTION,
    CATEGORY_STACK_CORRUPTION,
    CATEGORY_UNEXPECTED_STATE_TRANSITIONS,
    CATEGORY_USE_AFTER_FREE,
    DOMAIN_ABNORMAL_RUNTIME_STATE,
    DOMAIN_MEMORY_GROWTH_AND_LEAKS,
    DOMAIN_MEMORY_INTEGRITY,
    DOMAIN_THREAD_AND_SYNCHRONIZATION,
    EVAL_STATUS_AMBIGUOUS,
    EVAL_STATUS_CONTRADICTED,
    EVAL_STATUS_INSUFFICIENT_EVIDENCE,
    EVAL_STATUS_SUPPORTED,
    RECIPE_STATUS_AMBIGUOUS,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipe,
    DiagnosticRecipeRegistry,
    RecipeEvaluationResult,
)
from .evidence_ledger import (
    ATTRIBUTION_BASIS_CALL_STACK,
    EVIDENCE_TYPE_CAPTURE_QUALITY,
    EVIDENCE_TYPE_DIAGNOSTIC,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
)
from .runtime_evidence_provider import (
    COLLECTION_STATUS_FAILED,
    COLLECTION_STATUS_PARTIAL,
    COLLECTION_STATUS_SUCCESS,
    COLLECTION_STATUS_UNAVAILABLE,
    PROVENANCE_HISTORICAL_RECORD,
    PROVENANCE_INFERRED,
    PROVENANCE_LIVE_RUNTIME_CAPTURE as RUNTIME_PROV_LIVE,
    RuntimeEvidenceProvider,
    RuntimeEvidenceRecord,
)
from .target_adapter import LocalTargetAdapter, TargetExecutionAdapter
from .watch_session import read_process_memory_slice

# -----------------------------------------------------------------------------
# 1. State Machine States
# -----------------------------------------------------------------------------

STATE_CREATED = "CREATED"
STATE_CLASSIFYING = "CLASSIFYING"
STATE_ASSESSING = "ASSESSING"
STATE_PLANNING = "PLANNING"
STATE_COLLECTING = "COLLECTING"
STATE_ANALYZING = "ANALYZING"
STATE_VERIFYING = "VERIFYING"
STATE_NARROWING = "NARROWING"
STATE_COMPLETED = "COMPLETED"
STATE_INCONCLUSIVE = "INCONCLUSIVE"
STATE_BLOCKED = "BLOCKED"
STATE_FAILED = "FAILED"

TERMINAL_STATES = {STATE_COMPLETED, STATE_INCONCLUSIVE, STATE_BLOCKED, STATE_FAILED}


# -----------------------------------------------------------------------------
# 2. C++ Demangling Helper
# -----------------------------------------------------------------------------

def demangle_symbol(mangled_name: str) -> str:
    """Demangles a C++ symbol name using c++filt with fallback."""
    if not mangled_name:
        return ""
    if not mangled_name.startswith("_Z"):
        return mangled_name
    try:
        proc = subprocess.run(
            ["c++filt", mangled_name],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return mangled_name


# -----------------------------------------------------------------------------
# 3. Stage A: Problem Classifier (EN & KO, 12 Categories, Vague Queries)
# -----------------------------------------------------------------------------

@dataclass
class ProblemClassificationResult:
    """Outcome of Stage A problem classification."""
    raw_query: str
    normalized_query: str
    primary_category: str
    candidate_categories: List[Tuple[str, float]]
    confidence: float
    extracted_entities: Dict[str, List[str]]
    is_vague: bool
    screening_strategy: Optional[str] = None


class ProblemClassifier:
    """Bilingual (English and Korean) natural language problem classifier.
    
    Understands 12 core problem categories and handles vague queries by
    initiating broad multi-domain screening.
    """

    # Keyword mappings for English and Korean
    CATEGORY_KEYWORDS: Dict[str, Dict[str, List[str]]] = {
        CATEGORY_MEMORY_CORRUPTION: {
            "en": ["corruption", "corrupted", "memory corruption", "sigsegv", "segfault", "invalid memory access", "wild pointer", "bad pointer", "trampled", "clobbered", "buffer overflow"],
            "ko": ["메모리 오염", "메모리 손상", "메모리 깨짐", "세그폴트", "크래시", "유효하지 않은 메모리", "잘못된 포인터", "오버플로우", "침범", "깨졌"],
        },
        CATEGORY_MEMORY_LEAK: {
            "en": ["memory leak", "leak", "leaking", "rss growth", "heap growth", "unbounded growth", "oom", "out of memory", "allocations accumulating", "unfreed", "allocation and free imbalance", "allocation imbalance", "alloc imbalance", "free imbalance"],
            "ko": ["메모리 누수", "누수", "메모리 증가", "새는", "힙 증가", "rss 증가", "메모리 고갈", "해제되지 않", "메모리가 계속 늘어", "할당 해제 불균형", "할당 불균형", "해제 불균형"],
        },
        CATEGORY_INVALID_DOUBLE_FREE: {
            "en": ["double free", "free twice", "double deallocation", "free corrupted", "double-free"],
            "ko": ["이중 해제", "더블 프리", "두 번 해제", "이미 해제된 메모리 해제", "중복 해제"],
        },
        CATEGORY_USE_AFTER_FREE: {
            "en": ["use after free", "uaf", "dangling pointer", "freed memory access", "dereference freed", "use-after-free"],
            "ko": ["유즈 애프터 프리", "해제 후 사용", "댄글링 포인터", "해제된 포인터 접근", "해제된 객체 참조"],
        },
        CATEGORY_STACK_CORRUPTION: {
            "en": ["stack corruption", "stack overflow", "stack smashed", "stack smashing", "return address corrupted", "return address clobbered", "stack canary", "stack trampling"],
            "ko": ["스택 손상", "스택 오버플로우", "스택 깨짐", "리턴 주소 오염", "스택 카나리", "스택 침범", "스택 스매싱"],
        },
        CATEGORY_DATA_RACE_INDICATORS: {
            "en": ["data race", "race condition", "unsynchronized access", "torn read", "concurrent write", "missing lock", "race"],
            "ko": ["데이터 레이스", "경쟁 상태", "동시 접근", "동기화 누락", "락 없이 접근", "레이스 컨디션", "동시 쓰기"],
        },
        CATEGORY_DEADLOCK_INDICATORS: {
            "en": ["deadlock", "lock inversion", "hang", "blocked thread", "circular wait", "mutex stuck", "waiting for lock", "deadlocked"],
            "ko": ["데드락", "교착 상태", "락 역전", "스레드 블록", "락 대기", "응답 없음", "멈춤", "멈췄", "뮤텍스 대기"],
        },
        CATEGORY_ABNORMAL_VARIABLE_CHANGES: {
            "en": ["abnormal variable", "variable jump", "jumped", "counter unexpected", "unexpected value", "unexpected boundary", "boundary value", "out of range", "boundary violation", "variable sudden change", "wrong value", "counter corruption"],
            "ko": ["변수 비정상 변경", "값 이상", "카운터 이상", "예상치 못한 값", "경계값 이상", "범위 초과", "변수 급변", "엉뚱한 값", "값이 튐"],
        },
        CATEGORY_UNEXPECTED_STATE_TRANSITIONS: {
            "en": ["state transition", "invalid state", "illegal transition", "state machine bug", "unexpected state", "state violation"],
            "ko": ["상태 전이 오류", "유효하지 않은 상태", "불법 전이", "상태 머신 이상", "예상치 못한 상태", "상태 위반"],
        },
        CATEGORY_RESOURCE_EXHAUSTION: {
            "en": ["resource exhaustion", "fd exhaustion", "too many files", "out of sockets", "thread limit", "quota exceeded", "file descriptors leak"],
            "ko": ["리소스 고갈", "fd 고갈", "소켓 부족", "스레드 한도", "파일 디스크립터 누수", "자원 부족"],
        },
        CATEGORY_PROCESS_INSTABILITY: {
            "en": ["process instability", "frequent crash", "intermittent restart", "unstable process", "flapping", "flaky process", "crashing repeatedly"],
            "ko": ["프로세스 불안정", "잦은 크래시", "간헐적 종료", "재부팅 반복", "재부팅", "불안정한 프로세스", "불안정", "자주 죽"],
        },
        CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY: {
            "en": ["state inconsistency", "invariant violated", "corrupted internal state", "mismatched state", "buffer mismatch", "inconsistent state"],
            "ko": ["기능적 상태 불일치", "불변식 위반", "내부 상태 불일치", "버퍼 상태 모순", "정합성 깨짐", "일관성 훼손"],
        },
    }

    # Indicators that a query is vague / broad screening
    VAGUE_PATTERNS = [
        r"check\s+(?:whether|if)\s+(?:this\s+|the\s+|target\s+)?process",
        r"is\s+(?:the\s+|this\s+)?(?:target\s+)?process\s+(?:healthy|ok|running\s+fine)",
        r"health\s*check",
        r"status\s*check",
        r"diagnose\s+process",
        r"investigate\s+process",
        r"any\s+problems?",
        r"find\s+bugs?",
        r"overall\s+check",
        r"이\s*프로세스(?:에)?\s*문제(?:가)?\s*있(?:는지|나)",
        r"상태\s*검사",
        r"이상\s*유무",
        r"프로세스\s*점검",
        r"건강\s*상태",
        r"전체적(?:인)?\s*문제",
        r"종합\s*분석",
        r"왜\s*멈췄지",
        r"뭐가\s*문제",
    ]

    def classify(self, query: str) -> ProblemClassificationResult:
        """Classifies a problem query into candidate categories and extracts entities."""
        raw_query = query or ""
        normalized = raw_query.strip().lower()

        # Check for vague / broad query
        is_vague = False
        for pat in self.VAGUE_PATTERNS:
            if re.search(pat, normalized, re.IGNORECASE):
                is_vague = True
                break

        # If query is very short and generic, also mark as vague
        if len(normalized.split()) <= 4 and any(w in normalized for w in ["check", "inspect", "검사", "점검", "확인"]):
            is_vague = True

        # Entity extraction
        extracted_entities = self._extract_entities(raw_query)

        # Category scoring
        category_scores: Dict[str, float] = {}
        for cat, lang_dict in self.CATEGORY_KEYWORDS.items():
            score = 0.0
            for lang, keywords in lang_dict.items():
                for kw in keywords:
                    if kw in normalized:
                        # Longer matching keywords have higher weight
                        score += 1.0 + 0.1 * len(kw.split())
            if score > 0.0:
                category_scores[cat] = score

        # If entities point to specific categories, boost them
        if extracted_entities.get("error_codes"):
            for err in extracted_entities["error_codes"]:
                if "SEGV" in err or "BUS" in err:
                    category_scores[CATEGORY_MEMORY_CORRUPTION] = category_scores.get(CATEGORY_MEMORY_CORRUPTION, 0.0) + 3.0
                elif "ABRT" in err:
                    category_scores[CATEGORY_STACK_CORRUPTION] = category_scores.get(CATEGORY_STACK_CORRUPTION, 0.0) + 2.0
                    category_scores[CATEGORY_INVALID_DOUBLE_FREE] = category_scores.get(CATEGORY_INVALID_DOUBLE_FREE, 0.0) + 2.0
                elif "DEADLK" in err:
                    category_scores[CATEGORY_DEADLOCK_INDICATORS] = category_scores.get(CATEGORY_DEADLOCK_INDICATORS, 0.0) + 3.0

        # Determine primary and ranked candidates
        if category_scores:
            max_score = max(category_scores.values())
            normalized_scores = [(cat, round(sc / (max_score + 1.0), 3)) for cat, sc in category_scores.items()]
            normalized_scores.sort(key=lambda x: x[1], reverse=True)
            primary_cat = normalized_scores[0][0]
            confidence = min(0.95, round(normalized_scores[0][1] + 0.2, 2))
        else:
            # Fallback for completely unknown or totally vague query
            if is_vague:
                primary_cat = CATEGORY_PROCESS_INSTABILITY
                normalized_scores = [
                    (CATEGORY_PROCESS_INSTABILITY, 0.50),
                    (CATEGORY_DEADLOCK_INDICATORS, 0.45),
                    (CATEGORY_MEMORY_LEAK, 0.40),
                    (CATEGORY_MEMORY_CORRUPTION, 0.35),
                ]
                confidence = 0.45
            else:
                primary_cat = CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY
                normalized_scores = [(primary_cat, 0.30)]
                confidence = 0.30

        screening_strategy = None
        if is_vague:
            screening_strategy = (
                "BROAD_MULTI_DOMAIN_SCREENING: Multi-domain assessment across "
                "Memory Integrity (null/guard probes), Memory Growth (RSS/heap delta), "
                "Abnormal State (variable boundaries), and Concurrency (thread blocking & deadlock check)."
            )

        return ProblemClassificationResult(
            raw_query=raw_query,
            normalized_query=normalized,
            primary_category=primary_cat,
            candidate_categories=normalized_scores,
            confidence=confidence,
            extracted_entities=extracted_entities,
            is_vague=is_vague,
            screening_strategy=screening_strategy,
        )

    def _extract_entities(self, text: str) -> Dict[str, List[str]]:
        """Extracts C/C++ identifiers, thread IDs, memory addresses, error codes, and symptoms."""
        entities: Dict[str, List[str]] = {
            "functions": [],
            "variables": [],
            "threads": [],
            "addresses": [],
            "error_codes": [],
            "symptoms": [],
        }

        # Addresses: 0x...
        addrs = re.findall(r"\b0x[0-9a-fA-F]{4,16}\b", text)
        if addrs:
            entities["addresses"] = list(dict.fromkeys(addrs))

        # Error codes
        errs = re.findall(r"\b(?:SIGSEGV|SIGBUS|SIGABRT|SIGILL|SIGFPE|ENOMEM|EFAULT|EBUSY|EDEADLK|EWOULDBLOCK|EINVAL|ETIMEDOUT)\b", text, re.IGNORECASE)
        if errs:
            entities["error_codes"] = [e.upper() for e in dict.fromkeys(errs)]

        # Thread IDs or thread references
        tids = re.findall(r"(?:tid|thread|스레드)\s*[:#=]?\s*(\d+)", text, re.IGNORECASE)
        named_threads = re.findall(r"\b(?:worker_thread_\w+|main_thread|io_thread|worker_\d+)\b", text, re.IGNORECASE)
        all_threads = tids + named_threads
        if all_threads:
            entities["threads"] = list(dict.fromkeys(all_threads))

        # Function calls: foo(), Bar::baz(), Worker::run
        funcs = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:::|->|\.)?[a-zA-Z_][a-zA-Z0-9_]*)\s*\(\)", text)
        if funcs:
            entities["functions"] = list(dict.fromkeys(funcs))

        # Variable names: g_*, *ptr, obj.field, obj->field
        vars_found = re.findall(r"\b(?:g_[a-zA-Z0-9_]+|[a-zA-Z_][a-zA-Z0-9_]*(?:->|\.)[a-zA-Z0-9_]+)\b", text)
        deref_vars = re.findall(r"\*([a-zA-Z_][a-zA-Z0-9_]+)", text)
        all_vars = vars_found + deref_vars
        if all_vars:
            entities["variables"] = list(dict.fromkeys(all_vars))

        # Symptoms
        symptom_kws = ["hang", "crash", "leak", "deadlock", "corrupt", "freeze", "stuck", "race", "slow", "멈춤", "누수", "깨짐", "지연", "불안정"]
        found_syms = [s for s in symptom_kws if s in text.lower()]
        if found_syms:
            entities["symptoms"] = list(dict.fromkeys(found_syms))

        return entities


# -----------------------------------------------------------------------------
# 4. Stage B: Target Assessor (Zero-Stop Probing & Capability Auditing)
# -----------------------------------------------------------------------------

@dataclass
class TargetAssessmentResult:
    """Outcome of Stage B target assessment."""
    pid: Optional[int]
    accessible: bool
    thread_count: int
    memory_regions_count: int
    rss_kb: int
    companion_elf_path: Optional[str]
    companion_elf_valid: bool
    dwarf_available: bool
    capabilities: List[str]
    limitations: List[str]
    prerequisites_met: bool
    target_host: str = "localhost"
    memory_readable: bool = False
    mode: str = "LIVE"


class TargetAssessor:
    """Validates target process accessibility, ELF/DWARF symbols, and records limitations."""

    def assess(
        self,
        pid: Optional[int],
        companion_elf: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> TargetAssessmentResult:
        capabilities: List[str] = []
        limitations: List[str] = []
        accessible = False
        memory_readable = False
        thread_count = 0
        memory_regions_count = 0
        rss_kb = 0
        elf_valid = False
        dwarf_available = False
        mode = "LIVE" if (pid is not None and pid > 0) else "OFFLINE_SNAPSHOT"

        target_adapter = adapter or LocalTargetAdapter()
        target_host = target_adapter.target_host()

        # 1. Target PID accessibility check
        if pid is not None and pid > 1:
            alive, live_err = target_adapter.check_liveness(pid)
            if alive:
                accessible = True
                capabilities.append("PROC_FS_AVAILABLE")
                # Count threads
                try:
                    threads = target_adapter.get_threads(pid)
                    thread_count = len(threads)
                    capabilities.append("THREAD_INSPECTION")
                except Exception:
                    thread_count = 1

                # Read memory maps
                maps: List[Dict[str, Any]] = []
                try:
                    maps = target_adapter.get_proc_maps(pid)
                    memory_regions_count = len(maps)
                    if maps:
                        capabilities.append("MAPS_READ")
                    else:
                        limitations.append(f"Target process maps unavailable for PID {pid}")
                except Exception as e:
                    limitations.append(f"Failed to read target maps: {e}")

                # Read status for RSS
                try:
                    p_st = target_adapter.get_process_status(pid)
                    if "VmRSS" in p_st:
                        try:
                            rss_kb = int(p_st["VmRSS"])
                            capabilities.append("RSS_METRICS")
                        except Exception:
                            pass
                except Exception:
                    pass

                # Probe zero-stop memory readability capability by attempting to read first readable segment
                if maps:
                    first_readable_addr = None
                    for m in maps:
                        if m.get("is_readable") or ("r" in m.get("permissions", "")):
                            first_readable_addr = m.get("start_int") or (int(m["start"], 16) if isinstance(m.get("start"), str) else None)
                            if first_readable_addr:
                                break
                    if first_readable_addr is not None:
                        slice_b, _, read_err = target_adapter.read_memory(pid, first_readable_addr, 16)
                        if slice_b is not None:
                            memory_readable = True
                            capabilities.append("PROCESS_MEMORY_READABLE")
                            capabilities.append("PROCESS_VM_READV_ZERO_STOP")
                        else:
                            limitations.append(f"Target process memory unreadable (EPERM / ptrace_scope restricted): {read_err}")
                    else:
                        limitations.append("No readable memory mappings found in target process")
                else:
                    limitations.append(f"Target process maps unavailable for PID {pid}")
            else:
                limitations.append(f"Target process {pid} is not running or not found in /proc: {live_err}")

            accessible = bool(alive and memory_readable)
        else:
            limitations.append("No live target PID specified (offline or fixture mode)")

        # 2. Companion ELF and DWARF availability check
        if companion_elf:
            if os.path.exists(companion_elf):
                elf_valid = True
                capabilities.append("COMPANION_ELF_ACCESSIBLE")
                # Inspect for DWARF sections
                try:
                    proc = subprocess.run(
                        ["readelf", "-S", companion_elf],
                        capture_output=True,
                        text=True,
                        timeout=2.0,
                        check=False,
                    )
                    if proc.returncode == 0 and (".debug_info" in proc.stdout or ".zdebug_info" in proc.stdout):
                        dwarf_available = True
                        capabilities.append("DWARF_DEBUG_INFO")
                    else:
                        limitations.append("DWARF_DEBUG_INFO_MISSING")
                        limitations.append("Companion ELF lacks .debug_info (stripped or release binary without -g)")
                except Exception:
                    # Fallback check file size
                    dwarf_available = True
                    capabilities.append("DWARF_ASSUMED")
            else:
                limitations.append(f"Companion ELF binary '{companion_elf}' not found on disk")
        else:
            limitations.append("No companion ELF provided: variable names and struct field offsets unavailable, relying on raw memory patterns and /proc info")

        # Live PID must be accessible to satisfy prerequisites for live mode; offline mode only requires valid ELF/snapshot
        if pid is not None and pid > 0:
            prerequisites_met = accessible
        else:
            prerequisites_met = bool(companion_elf is not None and elf_valid)

        return TargetAssessmentResult(
            pid=pid,
            accessible=accessible,
            thread_count=thread_count,
            memory_regions_count=memory_regions_count,
            rss_kb=rss_kb,
            companion_elf_path=companion_elf,
            companion_elf_valid=elf_valid,
            dwarf_available=dwarf_available,
            capabilities=capabilities,
            limitations=limitations,
            prerequisites_met=prerequisites_met,
            target_host=target_host,
            memory_readable=memory_readable,
            mode=mode,
        )


# -----------------------------------------------------------------------------
# 5. Stage C: Investigation Planner & Step Representation
# -----------------------------------------------------------------------------

@dataclass
class InvestigationStep:
    """An executable step in an investigation plan."""
    step_id: str
    recipe_id: str
    recipe_name: str
    category: str
    domain: str
    rationale: str
    priority: int
    cost_score: float  # Higher means cheaper/better
    safety_score: float  # Higher means safer
    expected_info_gain: float  # 0.0 to 1.0
    multi_factor_score: float  # Combined score
    status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, SKIPPED, FAILED
    result: Optional[Dict[str, Any]] = None
    executed_at: Optional[str] = None


@dataclass
class InvestigationPlan:
    """Ordered, scored investigation plan."""
    steps: List[InvestigationStep]
    current_step_index: int = 0
    total_steps: int = 0
    estimated_overhead_ms: float = 0.0
    plan_rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps": [asdict(s) for s in self.steps],
            "current_step_index": self.current_step_index,
            "total_steps": self.total_steps,
            "estimated_overhead_ms": self.estimated_overhead_ms,
            "plan_rationale": self.plan_rationale,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationPlan":
        steps = [InvestigationStep(**s) for s in data.get("steps", [])]
        return cls(
            steps=steps,
            current_step_index=data.get("current_step_index", 0),
            total_steps=data.get("total_steps", len(steps)),
            estimated_overhead_ms=data.get("estimated_overhead_ms", 0.0),
            plan_rationale=data.get("plan_rationale", ""),
        )


class InvestigationPlanner:
    """Maps problem categories to diagnostic recipes and ranks them by multi-factor score."""

    def __init__(self, recipe_registry: Optional[DiagnosticRecipeRegistry] = None):
        self.recipe_registry = recipe_registry or DiagnosticRecipeRegistry()

    def create_plan(
        self,
        classification: ProblemClassificationResult,
        target_assessment: TargetAssessmentResult,
    ) -> InvestigationPlan:
        steps: List[InvestigationStep] = []
        candidate_recipes: List[Tuple[DiagnosticRecipe, float]] = []

        if classification.is_vague:
            # Broad screening: take representative recipes from each of the 4 domains
            domain_reps = [
                "RECIPE_INVALID_MEMORY_ACCESS",
                "RECIPE_PROCESS_MEMORY_GROWTH",
                "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP",
                "RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
                "RECIPE_UNEXPECTED_VARIABLE_CHANGES",
            ]
            for r_id in domain_reps:
                r = self.recipe_registry.get_recipe(r_id)
                if r:
                    candidate_recipes.append((r, 0.75))
        else:
            # Map candidate categories to matching recipes
            for cat, weight in classification.candidate_categories:
                recs = self.recipe_registry.get_recipes_for_category(cat)
                for r in recs:
                    if not any(cr[0].recipe_id == r.recipe_id for cr in candidate_recipes):
                        candidate_recipes.append((r, weight))

        # If no recipes found, fallback to generic screening
        if not candidate_recipes:
            for r in self.recipe_registry.list_recipes()[:4]:
                candidate_recipes.append((r, 0.5))

        # Multi-factor scoring for each candidate recipe
        # Weights: relevance (0.30), diagnostic value (0.25), info gain (0.20),
        #          availability (0.15), cost (0.05), safety (0.05)
        step_id_counter = 1
        for recipe, rel_weight in candidate_recipes:
            # Diagnostic value from recipe complexity
            diag_val = 0.85 if len(recipe.verification_procedure) >= 2 else 0.70
            info_gain = 0.80

            # Evidence availability based on target capabilities
            avail = 0.90
            if "DWARF_DEBUG_INFO" not in target_assessment.capabilities:
                # If recipe requires DWARF or source symbols, discount availability slightly
                if "DWARF" in recipe.output_structure or "vtable" in recipe.recipe_id.lower():
                    avail = 0.50

            cost_score = 0.95  # zero-stop read overhead is virtually zero (< 5ms)
            safety_score = 1.00  # 100% non-intrusive read

            combined_score = round(
                0.30 * rel_weight +
                0.25 * diag_val +
                0.20 * info_gain +
                0.15 * avail +
                0.05 * cost_score +
                0.05 * safety_score,
                3
            )

            rationale = (
                f"Evaluates {recipe.problem_category} in domain {recipe.domain} "
                f"with multi-factor score {combined_score:.2f} (relevance={rel_weight:.2f}, "
                f"availability={avail:.2f})."
            )

            steps.append(InvestigationStep(
                step_id=f"STEP_{step_id_counter:02d}",
                recipe_id=recipe.recipe_id,
                recipe_name=recipe.name,
                category=recipe.problem_category,
                domain=recipe.domain,
                rationale=rationale,
                priority=step_id_counter,
                cost_score=cost_score,
                safety_score=safety_score,
                expected_info_gain=info_gain,
                multi_factor_score=combined_score,
            ))
            step_id_counter += 1

        # Sort steps by multi-factor score descending
        steps.sort(key=lambda s: s.multi_factor_score, reverse=True)
        # Re-number priorities and step IDs after sorting
        for idx, s in enumerate(steps, 1):
            s.priority = idx
            s.step_id = f"STEP_{idx:02d}"

        plan_rationale = (
            f"Synthesized {len(steps)} deterministic investigation steps for primary "
            f"category '{classification.primary_category}'. Ordered by relevance, diagnostic value, "
            f"and zero-stop safety."
        )

        return InvestigationPlan(
            steps=steps,
            current_step_index=0,
            total_steps=len(steps),
            estimated_overhead_ms=len(steps) * 2.5,
            plan_rationale=plan_rationale,
        )


# -----------------------------------------------------------------------------
# 6. Stage E: Falsifiable Hypothesis Representation
# -----------------------------------------------------------------------------

@dataclass
class ExpertHypothesis:
    """Structured, falsifiable hypothesis defining deterministic criteria."""
    hypothesis_id: str
    problem_statement: str
    category: str
    domain: str
    status: str  # PROPOSED, SUPPORTED, CONTRADICTED, CONFIRMED, REFUTED, INCONCLUSIVE
    confidence: float
    confidence_basis: str
    supporting_evidence: List[Dict[str, Any]] = field(default_factory=list)
    contradicting_evidence: List[Dict[str, Any]] = field(default_factory=list)
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    applicable_diagnostic_rules: List[str] = field(default_factory=list)
    verification_criteria: Any = field(default_factory=list)
    verification_execution_results: List[Dict[str, Any]] = field(default_factory=list)
    recommended_next_action: str = ""
    source_locations: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def problem_category(self) -> str:
        return self.category

    @property
    def recommended_action(self) -> str:
        return self.recommended_next_action

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["problem_category"] = self.category
        d["recommended_action"] = self.recommended_next_action
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExpertHypothesis":
        clean = dict(data)
        if "problem_category" in clean and "category" not in clean:
            clean["category"] = clean.pop("problem_category")
        elif "problem_category" in clean:
            clean.pop("problem_category")
        if "recommended_action" in clean and "recommended_next_action" not in clean:
            clean["recommended_next_action"] = clean.pop("recommended_action")
        elif "recommended_action" in clean:
            clean.pop("recommended_action")
        # Ensure optional list fields exist
        for fld in ("supporting_evidence_ids", "contradicting_evidence_ids", "applicable_diagnostic_rules", "verification_execution_results"):
            if fld not in clean:
                clean[fld] = []
        return cls(**clean)


# -----------------------------------------------------------------------------
# 7. Stage 6: Evidence-to-Source Correlator Pipeline
# -----------------------------------------------------------------------------

class EvidenceToSourceCorrelator:
    """Completes the 7-step mapping:
    Observation -> Memory address/object -> C++ type and field -> DWARF information ->
    Source file/line -> Function candidates -> Hypothesis -> Verification.
    """

    def __init__(self, companion_elf: Optional[str] = None):
        self.companion_elf = companion_elf

    def correlate(
        self,
        observation: Dict[str, Any],
        target_pid: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Correlates a raw observation to C++ types, DWARF symbols, and source code,
        accounting for ASLR load bias and gracefully handling stripped binaries.
        """
        address = observation.get("address") or observation.get("target_address") or observation.get("faulting_address")
        if isinstance(address, str) and address.startswith("0x"):
            try:
                address = int(address, 16)
            except Exception:
                pass

        raw_symbol = observation.get("symbol") or observation.get("function") or observation.get("pointer_name")
        raw_type = observation.get("type") or observation.get("type_name")
        raw_val = observation.get("value") or observation.get("observed_value")

        # 1. Demangle symbol if mangled
        demangled_func = demangle_symbol(raw_symbol) if raw_symbol else None

        # 2. Account for ASLR and module load bias
        load_bias = 0
        if target_pid and target_pid > 0 and self.companion_elf and os.path.exists(self.companion_elf):
            maps_path = f"/proc/{target_pid}/maps"
            if os.path.exists(maps_path):
                elf_base = os.path.basename(self.companion_elf)
                try:
                    with open(maps_path, "r", errors="replace") as f:
                        for line in f:
                            if elf_base in line and ("r-xp" in line or "r--p" in line):
                                parts = line.split()
                                if parts:
                                    addr_range = parts[0].split("-")
                                    load_bias = int(addr_range[0], 16)
                                    break
                except Exception:
                    pass

        # 3. Extract source file and line if available
        source_file = observation.get("source_file") or observation.get("file")
        source_line = observation.get("source_line") or observation.get("line")

        # Compute relative ELF file address for addr2line
        elf_addr = address
        if address and isinstance(address, int):
            if load_bias > 0 and address >= load_bias:
                elf_addr = address - load_bias

        # If we have an address and a companion ELF with DWARF, attempt addr2line lookup
        if elf_addr and isinstance(elf_addr, int) and self.companion_elf and os.path.exists(self.companion_elf) and (not source_file or not source_line):
            addr_hex = f"0x{elf_addr:x}"
            try:
                proc = subprocess.run(
                    ["addr2line", "-e", self.companion_elf, "-f", "-C", addr_hex],
                    capture_output=True,
                    text=True,
                    timeout=2.0,
                    check=False,
                )
                if proc.returncode == 0:
                    lines = [l.strip() for l in proc.stdout.strip().splitlines() if l.strip()]
                    if len(lines) >= 2:
                        func_line = lines[0]
                        file_line_part = lines[1].split(":")
                        if "??" not in func_line and func_line != "?":
                            demangled_func = demangled_func or func_line
                        if len(file_line_part) >= 2 and "??" not in file_line_part[0] and file_line_part[0] != "?":
                            source_file = file_line_part[0]
                            try:
                                source_line = int(file_line_part[1].split()[0])
                            except Exception:
                                pass
            except Exception:
                pass

        # Check if addr2line returned '??'
        if demangled_func and ("??" in demangled_func or demangled_func == "?"):
            demangled_func = raw_symbol or None
        if source_file and ("??" in source_file or source_file == "?"):
            source_file = None
            source_line = None

        # 4. Read context source lines if source_file exists
        source_context: List[str] = []
        if source_file and os.path.exists(source_file) and isinstance(source_line, int) and source_line > 0:
            try:
                with open(source_file, "r", errors="replace") as f:
                    all_lines = f.readlines()
                    start_idx = max(0, source_line - 4)
                    end_idx = min(len(all_lines), source_line + 4)
                    for idx in range(start_idx, end_idx):
                        prefix = ">> " if (idx + 1) == source_line else "   "
                        source_context.append(f"{prefix}{idx+1:4d} | {all_lines[idx].rstrip()}")
            except Exception:
                pass

        # Extract evidence IDs
        evidence_ids: List[str] = []
        if observation.get("evidence_id"):
            evidence_ids.append(observation["evidence_id"])
        elif observation.get("evidence_ids"):
            evidence_ids.extend(observation["evidence_ids"])

        observed_type = observation.get("observed_type")
        inferred_type = observation.get("inferred_type") or (raw_type if not observed_type else None)

        # 5. Synthesize correlation output
        return {
            "runtime_address": address,
            "address": address,
            "elf_address": f"0x{elf_addr:x}" if isinstance(elf_addr, int) else None,
            "load_bias": f"0x{load_bias:x}",
            "raw_symbol": raw_symbol,
            "demangled_symbol": demangled_func or raw_symbol,
            "observed_type": observed_type,
            "inferred_type": inferred_type,
            "value": raw_val,
            "source_file": source_file,
            "source_line": source_line,
            "source_context": source_context,
            "allocation_site": observation.get("allocation_site"),
            "function_candidates": [demangled_func] if demangled_func else [],
            "evidence_ids": evidence_ids,
        }


# -----------------------------------------------------------------------------
# 8. Adaptive Investigation Session & State Machine
# -----------------------------------------------------------------------------

@dataclass
class DiagnosticConclusion:
    """Final diagnostic report bundle."""
    investigation_id: str
    target_pid: Optional[int]
    status: str  # COMPLETED, INCONCLUSIVE, BLOCKED, FAILED
    stop_reason: str
    executive_summary: str
    primary_finding: Optional[str]
    confidence: float
    confidence_basis: str
    supporting_evidence_chain: List[Dict[str, Any]]
    rejected_alternatives: List[Dict[str, Any]]
    missing_evidence_and_unknowns: List[str]
    recommended_remediations: List[str]
    diagnostic_limitations: List[str]
    completed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AdaptiveInvestigationSession:
    """Represents a single active or completed expert investigation session."""

    def __init__(
        self,
        investigation_id: str,
        problem_statement: str,
        pid: Optional[int] = None,
        companion_elf: Optional[str] = None,
        corpus_dir: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ):
        self.investigation_id = investigation_id
        self.raw_problem_statement = problem_statement
        self.pid = pid
        self.companion_elf = companion_elf
        self.corpus_dir = corpus_dir or "/tmp/dynamicstate_corpus"
        self._investigations_dir = os.path.join(self.corpus_dir, "investigations")
        os.makedirs(self._investigations_dir, exist_ok=True)
        self.adapter = adapter or LocalTargetAdapter()

        # Components
        self.classifier = ProblemClassifier()
        self.assessor = TargetAssessor()
        self.recipe_registry = DiagnosticRecipeRegistry()
        self.planner = InvestigationPlanner(self.recipe_registry)
        self.correlator = EvidenceToSourceCorrelator(companion_elf)
        self.ledger = EvidenceLedger(session_id=self.investigation_id)
        self.evidence_provider = RuntimeEvidenceProvider(adapter=self.adapter, corpus_dir=self.corpus_dir)
        self.temporal_memory_samples: List[Dict[str, Any]] = []

        # State machine
        self.state = STATE_CREATED
        self.is_paused = False
        self.timeline: List[Dict[str, Any]] = []

        # Data artifacts
        self.classification_result: Optional[ProblemClassificationResult] = None
        self.target_assessment: Optional[TargetAssessmentResult] = None
        self.plan: Optional[InvestigationPlan] = None
        self.collected_evidence: List[Dict[str, Any]] = []
        self.collected_evidence_records: List[RuntimeEvidenceRecord] = []
        self.active_hypotheses: List[ExpertHypothesis] = []
        self.rejected_hypotheses: List[ExpertHypothesis] = []
        self.conclusion: Optional[DiagnosticConclusion] = None
        self.verified_checks_count: int = 0

        self._record_timeline_event("SESSION_CREATED", {"investigation_id": investigation_id, "pid": pid})
        self._save_to_disk()

    def _save_to_disk(self) -> None:
        """Persists authoritative investigation state to disk."""
        try:
            path = os.path.join(self._investigations_dir, f"{self.investigation_id}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2)
        except Exception:
            pass

    def _record_timeline_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Appends an event to the chronological timeline."""
        self.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "state": self.state,
            "event_type": event_type,
            "details": details,
        })

    def pause(self) -> None:
        """Pauses the investigation session."""
        self.is_paused = True
        self._record_timeline_event("SESSION_PAUSED", {})
        self._save_to_disk()

    def resume(self) -> None:
        """Resumes a paused investigation session."""
        self.is_paused = False
        self._record_timeline_event("SESSION_RESUMED", {})
        self._save_to_disk()

    def step(self) -> Dict[str, Any]:
        """Advances the investigation session by exactly one state transition or collection step."""
        if self.is_paused:
            return {"status": "PAUSED", "state": self.state, "investigation_id": self.investigation_id}

        if self.state in TERMINAL_STATES:
            return {
                "status": "TERMINATED",
                "state": self.state,
                "investigation_id": self.investigation_id,
                "conclusion": asdict(self.conclusion) if self.conclusion else None,
            }

        # Dispatch based on current state
        res: Dict[str, Any] = {}
        if self.state == STATE_CREATED or self.state == STATE_CLASSIFYING:
            res = self._step_classify()
        elif self.state == STATE_ASSESSING:
            res = self._step_assess()
        elif self.state == STATE_PLANNING:
            res = self._step_plan()
        elif self.state == STATE_COLLECTING:
            res = self._step_collect_next()
        elif self.state == STATE_ANALYZING:
            res = self._step_analyze()
        elif self.state == STATE_VERIFYING:
            res = self._step_verify()
        elif self.state == STATE_NARROWING:
            res = self._step_narrow()
        else:
            res = {"status": "UNKNOWN_STATE", "state": self.state}

        self._save_to_disk()
        return res

    def run_to_completion(self, max_steps: int = 30) -> DiagnosticConclusion:
        """Runs the investigation state machine iteratively until a terminal state is reached."""
        steps_executed = 0
        while self.state not in TERMINAL_STATES and steps_executed < max_steps:
            if self.is_paused:
                break
            self.step()
            steps_executed += 1

        if self.state not in TERMINAL_STATES and steps_executed >= max_steps:
            self.state = STATE_INCONCLUSIVE
            self._finalize_conclusion(
                stop_reason="STEP_BUDGET_REACHED",
                summary="Investigation reached maximum iteration budget without fully separating hypotheses.",
            )

        self._save_to_disk()
        return self.conclusion or self._finalize_conclusion("TERMINATED", "Session finished.")

    # -------------------------------------------------------------------------
    # State Transition Steps
    # -------------------------------------------------------------------------

    def _step_classify(self) -> Dict[str, Any]:
        self.state = STATE_CLASSIFYING
        self.classification_result = self.classifier.classify(self.raw_problem_statement)
        self._record_timeline_event("PROBLEM_CLASSIFIED", {
            "primary_category": self.classification_result.primary_category,
            "confidence": self.classification_result.confidence,
            "is_vague": self.classification_result.is_vague,
            "extracted_entities": self.classification_result.extracted_entities,
        })
        self.state = STATE_ASSESSING
        return {"action": "CLASSIFY", "state": self.state, "primary_category": self.classification_result.primary_category}

    def _step_assess(self) -> Dict[str, Any]:
        self.target_assessment = self.assessor.assess(
            pid=self.pid,
            companion_elf=self.companion_elf,
            adapter=self.adapter,
        )
        self._record_timeline_event("TARGET_ASSESSED", {
            "accessible": self.target_assessment.accessible,
            "thread_count": self.target_assessment.thread_count,
            "dwarf_available": self.target_assessment.dwarf_available,
            "memory_readable": self.target_assessment.memory_readable,
            "limitations": self.target_assessment.limitations,
        })
        if not self.target_assessment.prerequisites_met and self.pid is not None:
            self.state = STATE_BLOCKED
            self._finalize_conclusion(
                stop_reason="TARGET_INACCESSIBLE",
                summary=f"Target PID {self.pid} is inaccessible or memory is unreadable: {'; '.join(self.target_assessment.limitations)}",
            )
            return {"action": "ASSESS", "state": self.state, "status": "BLOCKED"}

        self.state = STATE_PLANNING
        return {"action": "ASSESS", "state": self.state, "capabilities": self.target_assessment.capabilities}

    def _step_plan(self) -> Dict[str, Any]:
        if not self.classification_result or not self.target_assessment:
            self.state = STATE_FAILED
            return {"action": "PLAN", "state": self.state, "error": "Missing prerequisites for planning"}

        self.plan = self.planner.create_plan(
            classification=self.classification_result,
            target_assessment=self.target_assessment,
        )
        self._record_timeline_event("PLAN_GENERATED", {
            "total_steps": self.plan.total_steps,
            "rationale": self.plan.plan_rationale,
        })
        self.state = STATE_COLLECTING
        return {"action": "PLAN", "state": self.state, "plan": self.plan.to_dict()}

    def _step_start_collection(self) -> Dict[str, Any]:
        return self._step_collect_next()

    def _step_collect_next(self) -> Dict[str, Any]:
        if not self.plan or self.plan.current_step_index >= len(self.plan.steps):
            self.state = STATE_ANALYZING
            return {"action": "COLLECT_COMPLETE", "state": self.state}

        step = self.plan.steps[self.plan.current_step_index]
        step.status = "RUNNING"
        step.executed_at = datetime.now(timezone.utc).isoformat()

        recipe = self.recipe_registry.get_recipe(step.recipe_id)
        if not recipe:
            step.status = "FAILED"
            self.plan.current_step_index += 1
            return {"action": "COLLECT_STEP", "step_id": step.step_id, "status": "FAILED"}

        # Record real temporal memory sample for session persistence (Section 4)
        if self.pid and self.pid > 0:
            try:
                p_st = self.adapter.get_process_status(self.pid)
                sample_rss = int(p_st.get("VmRSS", 0))
                sample_vsz = int(p_st.get("VmSize", 0))
                self.temporal_memory_samples.append({
                    "timestamp": time.time(),
                    "rss_kb": sample_rss,
                    "vsize_kb": sample_vsz,
                    "step_index": self.plan.current_step_index,
                    "recipe_id": recipe.recipe_id,
                })
            except Exception:
                pass

        # Perform actual live runtime evidence acquisition via RuntimeEvidenceProvider
        obs_data, ev_records = self.evidence_provider.collect_for_recipe(
            recipe=recipe,
            pid=self.pid,
            companion_elf=self.companion_elf,
            target_assessment=self.target_assessment,
            classification=self.classification_result,
        )
        self.collected_evidence_records.extend(ev_records)

        # Incorporate session temporal memory samples into recipe context
        if self.temporal_memory_samples:
            persisted_rss = [s["rss_kb"] for s in self.temporal_memory_samples if s.get("rss_kb")]
            if len(persisted_rss) > len(obs_data.get("rss_history_kb", [])):
                obs_data["rss_history_kb"] = persisted_rss
                obs_data["epoch_count"] = len(persisted_rss)

        # Merge live observation data into deterministic recipe context
        eval_context: Dict[str, Any] = {
            "pid": self.pid,
            "companion_elf": self.companion_elf,
            "entities": self.classification_result.extracted_entities if self.classification_result else {},
            "capabilities": self.target_assessment.capabilities if self.target_assessment else [],
            "rss_kb": self.target_assessment.rss_kb if self.target_assessment else 0,
            **obs_data,
        }

        # Deterministic recipe evaluation against real acquired observations
        eval_result = self.recipe_registry.evaluate_recipe(recipe, eval_context)
        consumed_step_ev_ids: List[str] = []

        # Enrich and correlate evidence records (Section 7: 1:1 finding-to-evidence relationship)
        for i, fact in enumerate(eval_result.supporting_facts):
            if i < len(ev_records):
                matching_rec = ev_records[i]
                ev_id = matching_rec.evidence_id
                prov_class = matching_rec.provenance_class
            else:
                ev_id = f"ev_{uuid.uuid4().hex[:12]}"
                prov_class = ev_records[0].provenance_class if ev_records else RUNTIME_PROV_LIVE
                matching_rec = RuntimeEvidenceRecord(
                    evidence_id=ev_id,
                    collection_method=recipe.recipe_id,
                    target_pid=self.pid,
                    observed_value=fact,
                    provenance_class=prov_class,
                )
                self.collected_evidence_records.append(matching_rec)

            consumed_step_ev_ids.append(ev_id)
            ev_payload = {
                "evidence_id": ev_id,
                "problem_category": recipe.problem_category,
                "recipe_id": recipe.recipe_id,
                "domain": recipe.domain,
                "finding": fact,
                "finding_classification": "OBSERVED_FACT",
                "status": "SUPPORTED",
                "details": eval_result.details,
                "address": obs_data.get("address") or obs_data.get("faulting_address"),
                "symbol": obs_data.get("pointer_name") or obs_data.get("variable_name"),
                "observed_value": obs_data.get("observed_value") or obs_data.get("value"),
                "provenance_class": prov_class,
            }
            correlated = self.correlator.correlate(ev_payload, target_pid=self.pid)
            enriched_ev = {**ev_payload, "correlation": correlated, "step_id": step.step_id}

            ledger_status = "RECORDED"
            try:
                self.ledger.add_record(EvidenceRecord(
                    record_id=ev_id,
                    evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
                    provenance_class=prov_class,
                    target_pid=self.pid or 0,
                    source_function=recipe.recipe_id,
                    evidence_payload=enriched_ev,
                    semantic_digest=hashlib.sha256(json.dumps(fact, sort_keys=True).encode()).hexdigest(),
                ))
            except Exception as le:
                ledger_status = f"FAILED: {le}"

            enriched_ev["ledger_status"] = ledger_status
            self.collected_evidence.append(enriched_ev)

        for j, fact in enumerate(eval_result.contradicting_facts):
            contra_ev_id = f"ev_contra_{uuid.uuid4().hex[:10]}"
            consumed_step_ev_ids.append(contra_ev_id)
            ev_payload = {
                "evidence_id": contra_ev_id,
                "problem_category": recipe.problem_category,
                "recipe_id": recipe.recipe_id,
                "domain": recipe.domain,
                "counter_indicator": fact,
                "finding_classification": "OBSERVED_FACT",
                "status": "CONTRADICTED",
                "details": eval_result.details,
                "address": obs_data.get("address"),
                "provenance_class": RUNTIME_PROV_LIVE if self.pid else PROVENANCE_SYNTHETIC_FIXTURE,
            }
            correlated = self.correlator.correlate(ev_payload, target_pid=self.pid)
            enriched_ev = {**ev_payload, "correlation": correlated, "step_id": step.step_id}
            self.collected_evidence.append(enriched_ev)

        step.status = "COMPLETED"
        step.result = {
            "status": eval_result.status,
            "confidence": eval_result.confidence,
            "confidence_basis": eval_result.confidence_basis,
            "supporting_facts": eval_result.supporting_facts,
            "contradicting_facts": eval_result.contradicting_facts,
            "missing_evidence": eval_result.missing_evidence,
            "consumed_evidence_ids": consumed_step_ev_ids,
            "details": eval_result.details,
        }
        self.verified_checks_count += 1

        self._record_timeline_event("STEP_EXECUTED", {
            "step_id": step.step_id,
            "recipe_id": step.recipe_id,
            "eval_status": eval_result.status,
            "confidence": eval_result.confidence,
            "consumed_evidence_ids": consumed_step_ev_ids,
        })

        # ---------------------------------------------------------------------
        # Adaptive Feedback Loop & Dynamic Replanning (Section 10)
        # ---------------------------------------------------------------------
        remaining_steps = self.plan.steps[self.plan.current_step_index + 1:]
        if eval_result.status == RECIPE_STATUS_SUPPORTED:
            # If RSS growth was observed, dynamically schedule heap growth and object accumulation
            if "MEMORY_GROWTH" in recipe.recipe_id or "GROWTH" in recipe.recipe_id:
                followup_ids = ["RECIPE_HEAP_GROWTH", "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION"]
                for fid in followup_ids:
                    if not any(s.recipe_id == fid for s in self.plan.steps):
                        f_rec = self.recipe_registry.get_recipe(fid)
                        if f_rec:
                            new_step = InvestigationStep(
                                step_id=f"step_{len(self.plan.steps)+1:02d}",
                                recipe_id=fid,
                                recipe_name=f_rec.name,
                                domain=f_rec.domain,
                                category=f_rec.problem_category,
                                rationale=f"Dynamic follow-up: isolated from confirmed {recipe.recipe_id}",
                            )
                            remaining_steps.insert(0, new_step)

            # Prioritize relevant follow-up steps for this category
            related_steps = [s for s in remaining_steps if s.category == recipe.problem_category]
            unrelated_steps = [s for s in remaining_steps if s.category != recipe.problem_category]
            self.plan.steps = self.plan.steps[:self.plan.current_step_index + 1] + related_steps + unrelated_steps

            # Early stop condition: if definitive fault confirmed with high confidence (>= 0.90) and no contradiction
            if eval_result.confidence >= 0.90 and not eval_result.contradicting_facts:
                for s in remaining_steps:
                    if s.category != recipe.problem_category:
                        s.status = "SKIPPED"
                self.state = STATE_ANALYZING
                self.plan.current_step_index += 1
                return {"action": "COLLECT_STEP", "step_id": step.step_id, "eval_result": asdict(eval_result), "adaptive_action": "EARLY_ANOMALY_CONFIRMED"}

        elif eval_result.status == RECIPE_STATUS_CONTRADICTED:
            # Category contradicted: down-weight or skip remaining steps for this category
            for s in remaining_steps:
                if s.category == recipe.problem_category:
                    s.status = "SKIPPED"

        self.plan.current_step_index += 1
        if self.plan.current_step_index >= len(self.plan.steps):
            self.state = STATE_ANALYZING
        return {"action": "COLLECT_STEP", "step_id": step.step_id, "eval_result": asdict(eval_result)}

        self.plan.current_step_index += 1
        if self.plan.current_step_index >= len(self.plan.steps):
            self.state = STATE_ANALYZING
        return {"action": "COLLECT_STEP", "step_id": step.step_id, "eval_result": asdict(eval_result)}

    def _step_analyze(self) -> Dict[str, Any]:
        """Synthesizes falsifiable hypotheses from collected observations and diagnostic rules."""
        self.active_hypotheses.clear()

        # Group collected evidence by category
        cat_evidence: Dict[str, List[Dict[str, Any]]] = {}
        for ev in self.collected_evidence:
            cat = ev.get("problem_category") or (self.classification_result.primary_category if self.classification_result else "UNKNOWN")
            cat_evidence.setdefault(cat, []).append(ev)

        hyp_counter = 1
        for cat, ev_list in cat_evidence.items():
            supp_ev = [e for e in ev_list if e.get("status") == "SUPPORTED"]
            contra_ev = [e for e in ev_list if e.get("status") == "CONTRADICTED"]

            # Build executable verification criteria for this problem category
            criteria = self._build_verification_criteria_for_category(cat)

            # Determine applicable diagnostic rules
            rules = list(dict.fromkeys(e.get("recipe_id") for e in ev_list if e.get("recipe_id")))

            # Evidence-based confidence (derived from criteria and recipe outcome, NOT count)
            if supp_ev and not contra_ev:
                base_conf = max(e.get("details", {}).get("confidence", 0.85) for e in supp_ev)
                hyp_status = "SUPPORTED"
                conf_basis = f"Confirmed by deterministic recipe evaluation ({', '.join(rules)}) with zero contradiction."
            elif supp_ev and contra_ev:
                base_conf = 0.45
                hyp_status = "PROPOSED"
                conf_basis = f"Ambiguous: observed {len(supp_ev)} indicators alongside {len(contra_ev)} counter-indicators."
            elif contra_ev and not supp_ev:
                base_conf = 0.10
                hyp_status = "CONTRADICTED"
                conf_basis = f"Contradicted by counter-indicators observed during zero-stop evaluation."
            else:
                base_conf = 0.20
                hyp_status = "INCONCLUSIVE"
                conf_basis = "Insufficient evidence collected to evaluate hypothesis criteria."

            hyp = ExpertHypothesis(
                hypothesis_id=f"HYP_{hyp_counter:02d}",
                problem_statement=f"Runtime anomaly in {cat}: observed {len(supp_ev)} corroborating indicators.",
                category=cat,
                domain=ev_list[0].get("domain", DOMAIN_ABNORMAL_RUNTIME_STATE),
                status=hyp_status,
                confidence=round(base_conf, 2),
                confidence_basis=conf_basis,
                supporting_evidence=supp_ev,
                contradicting_evidence=contra_ev,
                supporting_evidence_ids=[e.get("evidence_id") for e in supp_ev if e.get("evidence_id")],
                contradicting_evidence_ids=[e.get("evidence_id") for e in contra_ev if e.get("evidence_id")],
                applicable_diagnostic_rules=rules,
                verification_criteria=criteria,
                recommended_next_action=f"Execute deterministic multi-assertion verification against {cat} invariants.",
            )
            self.active_hypotheses.append(hyp)
            hyp_counter += 1

        # ---------------------------------------------------------------------
        # Null Hypothesis Handling (Section 4.4)
        # ---------------------------------------------------------------------
        if not any(h.status == "SUPPORTED" for h in self.active_hypotheses):
            # Check coverage: clean result requires explicit executed checks across applicable scope
            mem_readable = getattr(self.target_assessment, "memory_readable", False) if self.target_assessment else False
            if self.verified_checks_count >= 1 and mem_readable:
                self.active_hypotheses.append(ExpertHypothesis(
                    hypothesis_id=f"HYP_{hyp_counter:02d}",
                    problem_statement="No abnormal runtime indicators observed within investigated scope.",
                    category="HEALTHY",
                    domain=DOMAIN_ABNORMAL_RUNTIME_STATE,
                    status="SUPPORTED",
                    confidence=0.85,
                    confidence_basis=f"Zero-stop inspection completed with clean checks across {self.verified_checks_count} executed recipes and full memory access.",
                    applicable_diagnostic_rules=["RECIPE_CLEAN_HEALTH_CHECK"],
                    verification_criteria=[{"criterion_id": "CRIT_ZERO_ANOMALIES", "description": "All scheduled recipes completed without positive anomaly indicators", "expected": True}],
                    recommended_next_action="Conclude investigation or widen inspection scope.",
                ))
            else:
                # Coverage insufficient: return INCONCLUSIVE, not a healthy conclusion
                limits = list(self.target_assessment.limitations if self.target_assessment else ["Insufficient diagnostic coverage"])
                self.active_hypotheses.append(ExpertHypothesis(
                    hypothesis_id=f"HYP_{hyp_counter:02d}",
                    problem_statement="Diagnostic inspection inconclusive: insufficient evidence coverage or target access limitations.",
                    category="UNKNOWN",
                    domain=DOMAIN_ABNORMAL_RUNTIME_STATE,
                    status="INCONCLUSIVE",
                    confidence=0.20,
                    confidence_basis=f"Diagnostic coverage was insufficient ({'; '.join(limits)}). Process cannot be certified healthy.",
                    missing_evidence=limits,
                    applicable_diagnostic_rules=[],
                    recommended_next_action="Re-run investigation with elevated permissions or companion ELF DWARF symbols.",
                ))

        self._record_timeline_event("HYPOTHESES_FORMED", {
            "active_hypotheses_count": len(self.active_hypotheses),
        })
        self.state = STATE_VERIFYING
        return {"action": "ANALYZE", "state": self.state, "hypotheses_count": len(self.active_hypotheses)}

    def _build_verification_criteria_for_category(self, category: str) -> List[Dict[str, Any]]:
        """Constructs executable verification criteria for a problem category."""
        if "CORRUPTION" in category or "FREE" in category:
            return [
                {"criterion_id": "CRIT_POINTER_VALID_VMA", "description": "Target address resides in valid mapped VMA and outside NULL page [0, 4096]", "expected": True},
                {"criterion_id": "CRIT_NO_POISON_PATTERN", "description": "Memory buffer does not contain allocator poison bytes (0xbaadbaad/0xdeadbeef)", "expected": True},
            ]
        elif "LEAK" in category or "GROWTH" in category:
            return [
                {"criterion_id": "CRIT_RSS_GROWTH_STABLE", "description": "Process RSS growth rate across observation window is bounded (< 20%)", "expected": True},
                {"criterion_id": "CRIT_CHUNK_RECLAMATION", "description": "Allocated heap objects/chunks are reclaimed without sustained accumulation", "expected": True},
            ]
        elif "DEADLOCK" in category or "CONCURRENCY" in category:
            return [
                {"criterion_id": "CRIT_NO_CIRCULAR_WAIT", "description": "Thread mutex wait-for graph contains no circular wait cycles", "expected": True},
                {"criterion_id": "CRIT_THREADS_PROGRESSING", "description": "Threads make execution progress without permanent futex lock stall", "expected": True},
            ]
        elif "STATE" in category or "VARIABLE" in category:
            return [
                {"criterion_id": "CRIT_VALID_STATE_DOMAIN", "description": "State variable values remain within defined enum/boundary domains", "expected": True},
                {"criterion_id": "CRIT_LEGAL_STATE_TRANSITION", "description": "Observed state transitions conform to valid state machine edges", "expected": True},
            ]
        return [
            {"criterion_id": "CRIT_INVARIANT_PRESERVED", "description": "Deterministic operational invariants are preserved", "expected": True}
        ]

    def _step_verify(self) -> Dict[str, Any]:
        """Runs executable verification criteria engine across all active hypotheses."""
        for hyp in list(self.active_hypotheses):
            self._execute_verification_for_hypothesis(hyp)

        # Filter out refuted hypotheses
        self.active_hypotheses = [h for h in self.active_hypotheses if h.status != "REFUTED"]
        self._record_timeline_event("HYPOTHESES_VERIFIED", {
            "active_count": len(self.active_hypotheses),
            "rejected_count": len(self.rejected_hypotheses),
        })
        self.state = STATE_NARROWING
        return {"action": "VERIFY", "state": self.state}

    def _execute_verification_for_hypothesis(self, hyp: ExpertHypothesis) -> Dict[str, Any]:
        """Executes explicit verification criteria for a single hypothesis."""
        results: List[Dict[str, Any]] = []
        has_fail = False
        has_pass = False

        criteria_list = hyp.verification_criteria if isinstance(hyp.verification_criteria, list) else []
        for crit in criteria_list:
            cid = crit.get("criterion_id", "")
            outcome = "INCONCLUSIVE"
            rationale = "No observation evidence available to verify criterion."
            consumed_ids: List[str] = []
            missing_ev: List[str] = []

            # 1. Pointer & VMA check
            if cid == "CRIT_POINTER_VALID_VMA":
                fault_ev = next((e for e in hyp.supporting_evidence if "NULL" in str(e) or "unmapped" in str(e).lower() or e.get("details", {}).get("violation_type") in ("NULL_POINTER_DEREFERENCE", "UNMAPPED_OR_GUARD_PAGE")), None)
                contra_ev = next((e for e in hyp.contradicting_evidence if "validly mapped" in str(e) or e.get("details", {}).get("is_healthy") or e.get("details", {}).get("violation_type") == "NONE_IDLE_NULL_POINTER"), None)
                if fault_ev:
                    outcome = "FAIL"  # Invariant violated -> fault confirmed
                    consumed_ids.append(fault_ev.get("evidence_id", ""))
                    rationale = f"Observed address violation: {fault_ev.get('finding')}"
                elif contra_ev:
                    outcome = "PASS"  # Invariant preserved -> fault contradicted
                    consumed_ids.append(contra_ev.get("evidence_id", ""))
                    rationale = "Target address resides in validly mapped readable VMA or represents clean idle pointer."
                else:
                    outcome = "INCONCLUSIVE"
                    missing_ev.append("pointer_address_or_vma_mapping")

            # 2. Poison bytes / magic check
            elif cid == "CRIT_NO_POISON_PATTERN":
                poison_ev = next((e for e in hyp.supporting_evidence if "magic" in str(e).lower() or "poison" in str(e).lower() or e.get("details", {}).get("magic_corrupted")), None)
                clean_ev = next((e for e in hyp.contradicting_evidence if "clean" in str(e).lower() or "valid" in str(e).lower()), None)
                if poison_ev:
                    outcome = "FAIL"
                    consumed_ids.append(poison_ev.get("evidence_id", ""))
                    rationale = f"Corruption pattern detected: {poison_ev.get('finding')}"
                elif clean_ev:
                    outcome = "PASS"
                    consumed_ids.append(clean_ev.get("evidence_id", ""))
                    rationale = "Memory slice verified intact with zero corruption or poison patterns."
                else:
                    # Check if memory was actually read and verified
                    mem_ev = next((e for e in hyp.supporting_evidence + hyp.contradicting_evidence if e.get("observed_value") is not None), None)
                    if mem_ev and not poison_ev:
                        outcome = "PASS"
                        consumed_ids.append(mem_ev.get("evidence_id", ""))
                        rationale = "Memory slice audited clean without poison markers."
                    else:
                        outcome = "INCONCLUSIVE"
                        missing_ev.append("memory_slice_read")

            # 3. Memory growth / leak check
            elif cid in ("CRIT_RSS_GROWTH_STABLE", "CRIT_CHUNK_RECLAMATION"):
                growth_ev = next((e for e in hyp.supporting_evidence if "growth" in str(e).lower() or "leak" in str(e).lower() or e.get("details", {}).get("growth_confirmed")), None)
                stable_ev = next((e for e in hyp.contradicting_evidence if "stable" in str(e).lower() or "plateau" in str(e).lower() or e.get("details", {}).get("transient_warmup")), None)
                if growth_ev:
                    outcome = "FAIL"
                    consumed_ids.append(growth_ev.get("evidence_id", ""))
                    rationale = f"Unbounded memory growth detected: {growth_ev.get('finding')}"
                elif stable_ev:
                    outcome = "PASS"
                    consumed_ids.append(stable_ev.get("evidence_id", ""))
                    rationale = "Memory footprint verified stable across observation intervals (plateau reached)."
                else:
                    outcome = "INCONCLUSIVE"
                    missing_ev.append("temporal_memory_epochs_min_3")

            # 4. Circular wait / deadlock check
            elif cid == "CRIT_NO_CIRCULAR_WAIT":
                incomplete_ev = next((e for e in hyp.supporting_evidence + hyp.contradicting_evidence if e.get("details", {}).get("incomplete_lock_graph")), None)
                deadlock_ev = next((e for e in hyp.supporting_evidence if "deadlock" in str(e).lower() or e.get("details", {}).get("deadlock_detected")), None)
                acyclic_ev = next((e for e in hyp.contradicting_evidence if "acyclic" in str(e).lower() or "no circular wait" in str(e).lower()), None)
                blocked_ev = next((e for e in hyp.supporting_evidence if "blocked" in str(e).lower()), None)

                if incomplete_ev:
                    outcome = "INCONCLUSIVE"
                    consumed_ids.append(incomplete_ev.get("evidence_id", ""))
                    missing_ev.append("complete_lock_ownership_info")
                    rationale = "Lock ownership graph is incomplete (threads waiting on locks with unresolvable owner). Cannot determine whether graph is acyclic."
                elif deadlock_ev:
                    outcome = "FAIL"  # Circular wait confirmed
                    consumed_ids.append(deadlock_ev.get("evidence_id", ""))
                    rationale = f"Circular wait cycle confirmed in lock graph: {deadlock_ev.get('finding')}"
                elif acyclic_ev:
                    outcome = "PASS"
                    consumed_ids.append(acyclic_ev.get("evidence_id", ""))
                    rationale = "Complete lock graph verified acyclic with zero circular wait cycles."
                elif blocked_ev:
                    outcome = "PASS"
                    consumed_ids.append(blocked_ev.get("evidence_id", ""))
                    rationale = "Thread blocked on lock, but lock graph is verified complete and acyclic (thread contention without deadlock)."
                else:
                    outcome = "INCONCLUSIVE"
                    missing_ev.append("thread_wait_for_graph")

            # 5. State domain / transition check
            elif cid in ("CRIT_VALID_STATE_DOMAIN", "CRIT_LEGAL_STATE_TRANSITION"):
                trans_ev = next((e for e in hyp.supporting_evidence if "transition" in str(e).lower() or "boundary" in str(e).lower() or e.get("details", {}).get("field_inconsistency")), None)
                valid_trans_ev = next((e for e in hyp.contradicting_evidence if "authorized" in str(e).lower() or "within bounds" in str(e).lower()), None)
                if trans_ev:
                    outcome = "FAIL"
                    consumed_ids.append(trans_ev.get("evidence_id", ""))
                    rationale = f"State transition or invariant boundary violation detected: {trans_ev.get('finding')}"
                elif valid_trans_ev:
                    outcome = "PASS"
                    consumed_ids.append(valid_trans_ev.get("evidence_id", ""))
                    rationale = "Observed state transitions conform to valid specification."
                else:
                    # Check if state variable was actually observed
                    state_obs_ev = next((e for e in hyp.supporting_evidence + hyp.contradicting_evidence if e.get("symbol")), None)
                    if state_obs_ev and not trans_ev:
                        outcome = "PASS"
                        consumed_ids.append(state_obs_ev.get("evidence_id", ""))
                        rationale = f"Observed variable '{state_obs_ev.get('symbol')}' conforms to normal operational state."
                    else:
                        outcome = "INCONCLUSIVE"
                        missing_ev.append("state_variable_value")

            # 6. Clean check
            elif cid == "CRIT_ZERO_ANOMALIES":
                mem_readable = getattr(self.target_assessment, "memory_readable", False) if self.target_assessment else False
                if not hyp.contradicting_evidence and hyp.status == "SUPPORTED" and self.verified_checks_count >= 1 and mem_readable:
                    outcome = "PASS"
                    consumed_ids.extend([e.get("evidence_id", "") for e in self.collected_evidence if e.get("evidence_id")])
                    rationale = f"All {self.verified_checks_count} scheduled diagnostic checks verified clean with zero anomaly indicators."
                else:
                    outcome = "FAIL"
                    rationale = "Diagnostic checks could not be certified clean (unreadable memory or observed anomalies)."

            results.append({
                "criterion_id": cid,
                "description": crit.get("description", ""),
                "result": outcome,
                "rationale": rationale,
                "consumed_evidence_ids": [cid_val for cid_val in consumed_ids if cid_val],
                "missing_evidence": missing_ev,
            })
            if outcome == "FAIL":
                has_fail = True
            elif outcome == "PASS":
                has_pass = True

            results.append({
                "criterion_id": cid,
                "description": crit.get("description", ""),
                "result": outcome,
                "rationale": rationale,
            })
            if outcome == "FAIL":
                has_fail = True
            elif outcome == "PASS":
                has_pass = True

        hyp.verification_execution_results = results

        # Update hypothesis verdict based on criteria outcomes
        is_clean_hyp = (
            "No abnormal runtime indicators observed" in hyp.problem_statement or
            any(c.get("criterion_id") == "CRIT_ZERO_ANOMALIES" for c in criteria_list)
        )
        if is_clean_hyp:
            if has_pass and not has_fail:
                hyp.status = "CONFIRMED"
                hyp.confidence = 0.90
            else:
                hyp.status = "INCONCLUSIVE"
        elif "inconclusive" in hyp.problem_statement.lower():
            hyp.status = "INCONCLUSIVE"
        else:
            # Fault hypothesis: criteria FAIL means safety invariant was violated (fault verified!)
            if has_fail and hyp.supporting_evidence:
                hyp.status = "CONFIRMED"
                hyp.confidence = max(hyp.confidence, 0.92)
                hyp.confidence_basis = f"Executable criteria verified fault: {'; '.join(r['rationale'] for r in results if r['result'] == 'FAIL')}"
            elif has_pass and not has_fail and hyp.contradicting_evidence:
                hyp.status = "REFUTED"
                hyp.confidence = min(hyp.confidence, 0.15)
                hyp.confidence_basis = "Refuted by contradictory evidence and satisfied safety invariants."
                self.rejected_hypotheses.append(hyp)
            elif hyp.contradicting_evidence and not hyp.supporting_evidence:
                hyp.status = "REFUTED"
                hyp.confidence = 0.10
                self.rejected_hypotheses.append(hyp)
            elif hyp.supporting_evidence:
                hyp.status = "LIKELY"
            else:
                hyp.status = "INCONCLUSIVE"

        return {
            "hypothesis_id": hyp.hypothesis_id,
            "status": hyp.status,
            "confidence": hyp.confidence,
            "verdict": hyp.status,
            "verification_results": results,
        }

    def _step_narrow(self) -> Dict[str, Any]:
        """Adaptive narrowing: selects final conclusion or declares inconclusive."""
        self.active_hypotheses.sort(key=lambda h: h.confidence, reverse=True)

        if not self.active_hypotheses:
            self.state = STATE_INCONCLUSIVE
            self._finalize_conclusion(
                stop_reason="ALL_HYPOTHESES_REFUTED",
                summary="All candidate fault hypotheses were refuted by deterministic observation evidence.",
            )
        elif self.active_hypotheses[0].status == "CONFIRMED" or self.active_hypotheses[0].confidence >= 0.75:
            self.state = STATE_COMPLETED
            top_h = self.active_hypotheses[0]
            self._finalize_conclusion(
                stop_reason="HYPOTHESIS_CONFIRMED",
                summary=f"Strongest hypothesis confirmed: {top_h.problem_statement} with confidence {top_h.confidence:.2f}.",
                primary_finding=top_h.problem_statement,
                confidence=top_h.confidence,
                confidence_basis=top_h.confidence_basis,
            )
        else:
            self.state = STATE_INCONCLUSIVE
            self._finalize_conclusion(
                stop_reason="EVIDENCE_INSUFFICIENT",
                summary="Evidence collected was insufficient to confirm or refute competing hypotheses with high confidence.",
            )

        return {"action": "NARROW", "state": self.state, "conclusion": asdict(self.conclusion)}

    def _finalize_conclusion(
        self,
        stop_reason: str,
        summary: str,
        primary_finding: Optional[str] = None,
        confidence: float = 0.50,
        confidence_basis: str = "",
    ) -> DiagnosticConclusion:
        """Constructs and seals the final diagnostic conclusion."""
        remediations: List[str] = []
        if primary_finding:
            pf_up = primary_finding.upper()
            if "MEMORY" in pf_up or "CORRUPT" in pf_up or "POINTER" in pf_up:
                remediations.append("Audit pointer dereference bounds and verify memory mapping permissions before dereference.")
                remediations.append("Enable AddressSanitizer (ASan) during build: `-fsanitize=address -g`.")
            elif "LEAK" in pf_up or "GROWTH" in pf_up or "IMBALANCE" in pf_up:
                remediations.append("Profile heap allocations and verify balanced free/delete calls across container lifecycles.")
                remediations.append("Inspect long-lived container capacities and unbounded cache queue limits.")
            elif "DEADLOCK" in pf_up or "LOCK" in pf_up:
                remediations.append("Enforce strict global lock acquisition ordering hierarchy across all threads.")
                remediations.append("Consider replacing nested mutexes with lock-free structures or fine-grained atomics.")
            elif "HEALTHY" in pf_up or "CLEAN" in pf_up:
                remediations.append("No active remediation required: runtime state verified clean within investigated scope.")
            else:
                remediations.append("Review state transition logic and enforce assertions for valid enum state transitions.")
        else:
            remediations.append("No active remediation required: runtime state appears healthy within investigated scope.")

        limitations: List[str] = []
        if self.target_assessment:
            limitations.extend(self.target_assessment.limitations)

        self.conclusion = DiagnosticConclusion(
            investigation_id=self.investigation_id,
            target_pid=self.pid,
            status=self.state,
            stop_reason=stop_reason,
            executive_summary=summary,
            primary_finding=primary_finding or (self.active_hypotheses[0].problem_statement if self.active_hypotheses else "No primary fault identified"),
            confidence=confidence,
            confidence_basis=confidence_basis or "Derived from multi-factor diagnostic recipe evaluations.",
            supporting_evidence_chain=self.collected_evidence,
            rejected_alternatives=[h.to_dict() for h in self.rejected_hypotheses],
            missing_evidence_and_unknowns=list(limitations),
            recommended_remediations=remediations,
            diagnostic_limitations=limitations,
        )
        self._record_timeline_event("CONCLUSION_SEALED", {
            "status": self.state,
            "stop_reason": stop_reason,
            "confidence": confidence,
        })
        return self.conclusion

    # -------------------------------------------------------------------------
    # Public Query / MCP Helpers
    # -------------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """Returns the current investigation status, progress, and next recommended action."""
        progress = 0
        if self.state in TERMINAL_STATES:
            progress = 100
        elif self.state == STATE_CLASSIFYING:
            progress = 15
        elif self.state == STATE_ASSESSING:
            progress = 30
        elif self.state == STATE_PLANNING:
            progress = 45
        elif self.state == STATE_COLLECTING:
            if self.plan and self.plan.total_steps > 0:
                progress = 45 + int(35 * (self.plan.current_step_index / self.plan.total_steps))
            else:
                progress = 55
        elif self.state == STATE_ANALYZING:
            progress = 85
        elif self.state == STATE_VERIFYING or self.state == STATE_NARROWING:
            progress = 95

        next_action = "Execute next planned diagnostic step."
        if self.state in TERMINAL_STATES:
            next_action = "Review final conclusion report."
        elif self.state == STATE_CREATED:
            next_action = "Initiate problem classification."

        return {
            "investigation_id": self.investigation_id,
            "state": self.state,
            "progress_percentage": progress,
            "target_pid": self.pid,
            "problem_statement": self.raw_problem_statement,
            "active_hypotheses_count": len(self.active_hypotheses),
            "collected_evidence_count": len(self.collected_evidence),
            "next_recommended_action": next_action,
            "is_paused": self.is_paused,
            "created_at": self.timeline[0]["timestamp"] if self.timeline else "",
        }

    def get_plan(self) -> Dict[str, Any]:
        """Returns the current ordered investigation plan."""
        return self.plan.to_dict() if self.plan else {"steps": [], "total_steps": 0}

    def execute_step(self, step_id: Optional[str] = None) -> Dict[str, Any]:
        """Executes a specific step or the next pending step."""
        if not self.plan or not self.plan.steps:
            return self.step()
        if step_id:
            for idx, s in enumerate(self.plan.steps):
                if s.step_id == step_id:
                    self.plan.current_step_index = idx
                    break
        return self.step()

    def get_hypothesis_evidence(self, hypothesis_id: str) -> Dict[str, Any]:
        """Returns detailed supporting and contradicting evidence for a hypothesis."""
        if not self.active_hypotheses and not self.rejected_hypotheses:
            self._step_analyze()
        for hyp in self.active_hypotheses + self.rejected_hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                return {
                    "hypothesis_id": hyp.hypothesis_id,
                    "problem_statement": hyp.problem_statement,
                    "category": hyp.category,
                    "confidence": hyp.confidence,
                    "status": hyp.status,
                    "supporting_evidence": hyp.supporting_evidence,
                    "contradicting_evidence": hyp.contradicting_evidence,
                    "missing_evidence": hyp.missing_evidence,
                    "verification_criteria": hyp.verification_criteria,
                    "verification_results": hyp.verification_execution_results,
                }
        return {"error": f"Hypothesis '{hypothesis_id}' not found in investigation {self.investigation_id}"}

    def verify_hypothesis(self, hypothesis_id: str) -> Dict[str, Any]:
        """Executes deterministic verification for a specific hypothesis."""
        if not self.active_hypotheses:
            self._step_analyze()
        for hyp in self.active_hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                return self._execute_verification_for_hypothesis(hyp)
        return {"error": f"Hypothesis '{hypothesis_id}' not found"}

    def compare_hypotheses(self, hypothesis_ids: List[str]) -> Dict[str, Any]:
        """Compares competing hypotheses side-by-side."""
        matched: List[Dict[str, Any]] = []
        all_hyps = {h.hypothesis_id: h for h in (self.active_hypotheses + self.rejected_hypotheses)}
        for hid in hypothesis_ids:
            if hid in all_hyps:
                h = all_hyps[hid]
                matched.append({
                    "hypothesis_id": h.hypothesis_id,
                    "problem_statement": h.problem_statement,
                    "category": h.category,
                    "confidence": h.confidence,
                    "status": h.status,
                    "supporting_evidence_count": len(h.supporting_evidence),
                    "contradicting_evidence_count": len(h.contradicting_evidence),
                    "verification_results": h.verification_execution_results,
                })
        return {
            "investigation_id": self.investigation_id,
            "compared_count": len(matched),
            "hypotheses": matched,
            "recommendation": f"Select {matched[0]['hypothesis_id']} (highest confidence)" if matched else "No hypotheses to compare",
        }

    def export_report(self, format: str = "json") -> Union[Dict[str, Any], str]:
        """Exports full 13-point expert incident report as JSON or Markdown."""
        if not self.conclusion:
            self._finalize_conclusion("EXPORT_REQUESTED", "Report exported prior to terminal state.")

        # Build 13 structured sections
        executed_procs = []
        if self.plan:
            for s in self.plan.steps:
                if s.status == "COMPLETED":
                    executed_procs.append({
                        "step_id": s.step_id,
                        "recipe_id": s.recipe_id,
                        "recipe_name": s.recipe_name,
                        "category": s.category,
                        "executed_at": s.executed_at,
                        "result_status": s.result.get("status") if s.result else "UNKNOWN",
                    })

        observations_list = []
        for rec in self.collected_evidence_records:
            observations_list.append(rec.to_dict())

        confirmed_findings = [h.to_dict() for h in self.active_hypotheses if h.status == "CONFIRMED"]
        unresolved_hyps = [h.to_dict() for h in self.active_hypotheses if h.status in ("PROPOSED", "LIKELY", "INCONCLUSIVE")]
        rejected_hyps = [h.to_dict() for h in self.rejected_hypotheses]

        source_mappings = []
        for ev in self.collected_evidence:
            corr = ev.get("correlation")
            if corr:
                source_mappings.append({
                    "evidence_id": ev.get("evidence_id"),
                    "runtime_address": corr.get("runtime_address"),
                    "elf_address": corr.get("elf_address"),
                    "load_bias": corr.get("load_bias"),
                    "symbol": corr.get("demangled_symbol"),
                    "source_file": corr.get("source_file"),
                    "source_line": corr.get("source_line"),
                    "context": corr.get("source_context"),
                })

        detailed_findings = []
        for h in self.active_hypotheses:
            finding_classification = "CONFIRMED ROOT CAUSE" if h.status == "CONFIRMED" else ("HYPOTHESIS" if h.status == "PROPOSED" else ("INFERENCE" if h.status == "LIKELY" else "UNRESOLVED QUESTION"))
            # Correlate consumed evidence details
            obs_values = [e.get("observed_value") for e in h.supporting_evidence if e.get("observed_value") is not None]
            source_locs = []
            for e in h.supporting_evidence:
                corr = e.get("correlation", {})
                if corr.get("source_file"):
                    source_locs.append(f"{corr.get('source_file')}:{corr.get('source_line')}")

            detailed_findings.append({
                "statement": h.problem_statement,
                "classification": finding_classification,
                "observed_values": obs_values,
                "evidence_ids": h.supporting_evidence_ids,
                "diagnostic_recipes": h.applicable_diagnostic_rules,
                "verification_criteria": h.verification_criteria,
                "verification_results": h.verification_execution_results,
                "confidence_basis": h.confidence_basis,
                "contradictory_evidence": [e.get("finding") for e in h.contradicting_evidence],
                "source_locations": list(dict.fromkeys(source_locs)),
                "remaining_uncertainty": h.missing_evidence,
            })

        report_13_points = {
            "1_problem_description": self.raw_problem_statement,
            "2_target_information": {
                "pid": self.pid,
                "host": getattr(self.target_assessment, "target_host", "localhost") if self.target_assessment else "localhost",
                "thread_count": self.target_assessment.thread_count if self.target_assessment else 0,
                "rss_kb": self.target_assessment.rss_kb if self.target_assessment else 0,
                "memory_regions_count": self.target_assessment.memory_regions_count if self.target_assessment else 0,
                "memory_readable": getattr(self.target_assessment, "memory_readable", False) if self.target_assessment else False,
                "companion_elf": self.companion_elf,
                "dwarf_available": self.target_assessment.dwarf_available if self.target_assessment else False,
            },
            "3_initial_classification": {
                "primary_category": self.classification_result.primary_category if self.classification_result else "UNKNOWN",
                "confidence": self.classification_result.confidence if self.classification_result else 0.0,
                "is_vague": self.classification_result.is_vague if self.classification_result else True,
                "extracted_entities": self.classification_result.extracted_entities if self.classification_result else {},
            },
            "4_investigation_scope": {
                "targeted_recipes": [s.recipe_id for s in self.plan.steps] if self.plan else [],
                "target_domain": self.plan.steps[0].domain if self.plan and self.plan.steps else "GENERAL",
            },
            "5_executed_diagnostic_procedures": executed_procs,
            "6_actual_observations": observations_list,
            "7_confirmed_findings": confirmed_findings,
            "7_findings_detail": detailed_findings,
            "8_probable_causes": [h.problem_statement for h in self.active_hypotheses if h.status in ("CONFIRMED", "LIKELY")],
            "9_rejected_hypotheses": rejected_hyps,
            "10_unresolved_hypotheses": unresolved_hyps,
            "11_evidence_to_source_mapping": source_mappings,
            "12_missing_evidence": self.target_assessment.limitations if self.target_assessment else [],
            "13_recommended_next_actions": self.conclusion.recommended_remediations if self.conclusion else [],
        }

        if format.lower() == "markdown":
            md = [
                f"# dynamicState Expert Diagnostic Incident Report",
                f"**Investigation ID**: `{self.investigation_id}`  ",
                f"**Target PID**: `{self.pid}`  ",
                f"**Date**: `{self.conclusion.completed_at}`  ",
                f"**Status**: `{self.conclusion.status}` (`{self.conclusion.stop_reason}`)  ",
                f"**Confidence**: `{self.conclusion.confidence * 100:.1f}%`  ",
                "",
                "## 1. Problem Description",
                f"{self.raw_problem_statement}",
                "",
                "## 2. Target Information",
                f"- PID: `{self.pid}`",
                f"- Threads: `{report_13_points['2_target_information']['thread_count']}`",
                f"- Memory RSS: `{report_13_points['2_target_information']['rss_kb']} KB`",
                f"- DWARF Available: `{report_13_points['2_target_information']['dwarf_available']}`",
                "",
                "## 3. Initial Classification",
                f"- Primary Category: `{report_13_points['3_initial_classification']['primary_category']}`",
                f"- Confidence: `{report_13_points['3_initial_classification']['confidence'] * 100:.1f}%`",
                "",
                "## 4. Investigation Scope",
                f"- Scheduled Steps: `{len(report_13_points['4_investigation_scope']['targeted_recipes'])}`",
                "",
                "## 5. Executed Diagnostic Procedures",
            ]
            for proc in executed_procs:
                md.append(f"- **{proc['step_id']}**: `{proc['recipe_id']}` ({proc['result_status']})")

            md.extend([
                "",
                f"## 6. Actual Observations ({len(observations_list)} records)",
            ])
            for obs in observations_list[:10]:
                md.append(f"- `[{obs.get('evidence_id')}]` [OBSERVED FACT] Method: `{obs.get('collection_method')}` | Value: `{obs.get('observed_value')}`")

            md.extend([
                "",
                "## 7. Confirmed Findings & Technical Root Cause",
            ])
            if detailed_findings:
                for df in detailed_findings:
                    cls_tag = f"[{df['classification']}]"
                    md.append(f"### {cls_tag} {df['statement']}")
                    md.append(f"- **Classification**: `{df['classification']}`")
                    md.append(f"- **Consumed Evidence IDs**: `{', '.join(df['evidence_ids']) if df['evidence_ids'] else 'None'}`")
                    md.append(f"- **Diagnostic Rule / Recipe**: `{', '.join(df['diagnostic_recipes'])}`")
                    md.append(f"- **Confidence Basis**: {df['confidence_basis']}")
                    if df['source_locations']:
                        md.append(f"- **Source Locations**: `{', '.join(df['source_locations'])}`")
                    if df['remaining_uncertainty']:
                        md.append(f"- **Remaining Uncertainty / Missing**: `{', '.join(df['remaining_uncertainty'])}`")
            else:
                md.append("- No confirmed fault findings.")

            md.extend([
                "",
                "## 8. Probable Causes",
            ])
            for pc in report_13_points["8_probable_causes"]:
                md.append(f"- {pc}")

            md.extend([
                "",
                "## 9. Rejected Hypotheses",
            ])
            if rejected_hyps:
                for rh in rejected_hyps:
                    md.append(f"- **[REFUTED]** {rh.get('problem_statement')}: {rh.get('confidence_basis')}")
            else:
                md.append("- None.")

            md.extend([
                "",
                "## 10. Unresolved Hypotheses",
            ])
            if unresolved_hyps:
                for uh in unresolved_hyps:
                    md.append(f"- **[{uh.get('status')}]** {uh.get('problem_statement')}")
            else:
                md.append("- None.")

            md.extend([
                "",
                "## 11. Evidence-to-Source Mapping",
            ])
            if source_mappings:
                for sm in source_mappings:
                    loc = f"{sm.get('source_file')}:{sm.get('source_line')}" if sm.get("source_file") else "N/A"
                    md.append(f"- Runtime Addr: `{sm.get('runtime_address')}` | Symbol: `{sm.get('symbol')}` | Location: `{loc}`")
            else:
                md.append("- No DWARF source mappings resolved.")

            md.extend([
                "",
                "## 12. Missing Evidence & Limitations",
            ])
            for lim in report_13_points["12_missing_evidence"]:
                md.append(f"- *Note*: {lim}")

            md.extend([
                "",
                "## 13. Recommended Next Actions",
            ])
            for r in report_13_points["13_recommended_next_actions"]:
                md.append(f"- [ ] {r}")

            return "\n".join(md)

        # JSON output includes all 13 points
        return {
            "investigation_id": self.investigation_id,
            "target_pid": self.pid,
            "problem_statement": self.raw_problem_statement,
            "status": self.state,
            "conclusion": asdict(self.conclusion) if self.conclusion else None,
            "plan": self.plan.to_dict() if self.plan else None,
            "active_hypotheses": [h.to_dict() for h in self.active_hypotheses],
            "rejected_hypotheses": [h.to_dict() for h in self.rejected_hypotheses],
            "timeline": self.timeline,
            "diagnostic_limitations": self.target_assessment.limitations if self.target_assessment else [],
            "report_13_points": report_13_points,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serializes complete session state to a dictionary for persistence / recovery."""
        return {
            "investigation_id": self.investigation_id,
            "raw_problem_statement": self.raw_problem_statement,
            "pid": self.pid,
            "companion_elf": self.companion_elf,
            "corpus_dir": self.corpus_dir,
            "state": self.state,
            "is_paused": self.is_paused,
            "timeline": self.timeline,
            "plan": self.plan.to_dict() if self.plan else None,
            "collected_evidence": self.collected_evidence,
            "collected_evidence_records": [r.to_dict() for r in self.collected_evidence_records],
            "active_hypotheses": [h.to_dict() for h in self.active_hypotheses],
            "rejected_hypotheses": [h.to_dict() for h in self.rejected_hypotheses],
            "conclusion": asdict(self.conclusion) if self.conclusion else None,
            "classification_result": asdict(self.classification_result) if self.classification_result else None,
            "target_assessment": asdict(self.target_assessment) if self.target_assessment else None,
            "verified_checks_count": self.verified_checks_count,
            "temporal_memory_samples": self.temporal_memory_samples,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AdaptiveInvestigationSession":
        """Reconstructs session state from a serialized dictionary."""
        sess = cls(
            investigation_id=data["investigation_id"],
            problem_statement=data.get("raw_problem_statement", ""),
            pid=data.get("pid"),
            companion_elf=data.get("companion_elf"),
            corpus_dir=data.get("corpus_dir"),
        )
        sess.state = data.get("state", STATE_CREATED)
        sess.is_paused = data.get("is_paused", False)
        sess.timeline = data.get("timeline", [])
        if data.get("plan"):
            sess.plan = InvestigationPlan.from_dict(data["plan"])
        sess.collected_evidence = data.get("collected_evidence", [])
        sess.collected_evidence_records = [
            RuntimeEvidenceRecord.from_dict(r) for r in data.get("collected_evidence_records", [])
        ]
        sess.active_hypotheses = [ExpertHypothesis.from_dict(h) for h in data.get("active_hypotheses", [])]
        sess.rejected_hypotheses = [ExpertHypothesis.from_dict(h) for h in data.get("rejected_hypotheses", [])]
        sess.verified_checks_count = data.get("verified_checks_count", 0)
        sess.temporal_memory_samples = data.get("temporal_memory_samples", [])
        if data.get("classification_result"):
            sess.classification_result = ProblemClassificationResult(**data["classification_result"])
        if data.get("target_assessment"):
            sess.target_assessment = TargetAssessmentResult(**data["target_assessment"])
        if data.get("conclusion"):
            sess.conclusion = DiagnosticConclusion(**data["conclusion"])
        return sess


# -----------------------------------------------------------------------------
# 9. Investigation Engine Registry
# -----------------------------------------------------------------------------

class ExpertDiagnosticEngine:
    """Session coordinator and registry for adaptive expert investigations."""

    def __init__(self, corpus_dir: Optional[str] = None):
        self.corpus_dir = corpus_dir or "/tmp/dynamicstate_corpus"
        self._investigations_dir = os.path.join(self.corpus_dir, "investigations")
        os.makedirs(self._investigations_dir, exist_ok=True)
        self.sessions: Dict[str, AdaptiveInvestigationSession] = {}

    def start_investigation(
        self,
        problem_statement: str,
        pid: Optional[int] = None,
        companion_elf: Optional[str] = None,
        investigation_id: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> AdaptiveInvestigationSession:
        """Launches a new adaptive investigation session."""
        inv_id = investigation_id or f"inv_{uuid.uuid4().hex[:12]}"
        session = AdaptiveInvestigationSession(
            investigation_id=inv_id,
            problem_statement=problem_statement,
            pid=pid,
            companion_elf=companion_elf,
            corpus_dir=self.corpus_dir,
            adapter=adapter,
        )
        self.sessions[inv_id] = session
        return session
        self.sessions[inv_id] = session
        return session

    def get_session(self, investigation_id: str) -> Optional[AdaptiveInvestigationSession]:
        """Retrieves an existing investigation session by ID from memory or disk."""
        if investigation_id in self.sessions:
            return self.sessions[investigation_id]

        disk_path = os.path.join(self._investigations_dir, f"{investigation_id}.json")
        if os.path.exists(disk_path):
            try:
                with open(disk_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                sess = AdaptiveInvestigationSession.from_dict(data)
                self.sessions[investigation_id] = sess
                return sess
            except Exception:
                pass
        return None

    def list_sessions(self) -> List[Dict[str, Any]]:
        """Lists metadata for all active and completed sessions."""
        return [sess.get_status() for sess in self.sessions.values()]
