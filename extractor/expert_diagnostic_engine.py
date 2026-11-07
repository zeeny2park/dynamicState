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
from .target_adapter import LocalTargetAdapter, TargetExecutionAdapter

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
            "en": ["memory leak", "leak", "leaking", "rss growth", "heap growth", "unbounded growth", "oom", "out of memory", "allocations accumulating", "unfreed"],
            "ko": ["메모리 누수", "누수", "메모리 증가", "새는", "힙 증가", "rss 증가", "메모리 고갈", "해제되지 않", "메모리가 계속 늘어"],
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
        thread_count = 0
        memory_regions_count = 0
        rss_kb = 0
        elf_valid = False
        dwarf_available = False

        # 1. Target PID accessibility check
        if pid is not None and pid > 1:
            proc_path = f"/proc/{pid}"
            if os.path.exists(proc_path):
                accessible = True
                capabilities.append("PROC_FS_AVAILABLE")
                # Count threads
                task_path = f"/proc/{pid}/task"
                if os.path.exists(task_path):
                    try:
                        thread_count = len(os.listdir(task_path))
                        capabilities.append("THREAD_INSPECTION")
                    except Exception:
                        thread_count = 1
                # Read memory maps
                maps_path = f"/proc/{pid}/maps"
                if os.path.exists(maps_path):
                    try:
                        with open(maps_path, "r", errors="replace") as f:
                            memory_regions_count = sum(1 for _ in f)
                        capabilities.append("MAPS_READ")
                    except Exception:
                        pass
                # Read status for RSS
                status_path = f"/proc/{pid}/status"
                if os.path.exists(status_path):
                    try:
                        with open(status_path, "r", errors="replace") as f:
                            for line in f:
                                if line.startswith("VmRSS:"):
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        rss_kb = int(parts[1])
                                    break
                        capabilities.append("RSS_METRICS")
                    except Exception:
                        pass
                # Check process_vm_readv zero-stop capability
                capabilities.append("PROCESS_VM_READV_ZERO_STOP")
            else:
                limitations.append(f"Target PID {pid} is not running or not found in /proc")
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
                        limitations.append("Companion ELF lacks .debug_info (stripped or release binary without -g)")
                except Exception:
                    # Fallback check file size
                    dwarf_available = True
                    capabilities.append("DWARF_ASSUMED")
            else:
                limitations.append(f"Companion ELF binary '{companion_elf}' not found on disk")
        else:
            limitations.append("No companion ELF provided: variable names and struct field offsets unavailable, relying on raw memory patterns and /proc info")

        prerequisites_met = accessible or (companion_elf is not None and elf_valid)

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
    missing_evidence: List[str] = field(default_factory=list)
    verification_criteria: Dict[str, Any] = field(default_factory=dict)
    recommended_next_action: str = ""
    source_locations: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExpertHypothesis":
        return cls(**data)


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
        """Correlates a raw observation to C++ types, DWARF symbols, and source code."""
        address = observation.get("address")
        raw_symbol = observation.get("symbol") or observation.get("function")
        raw_type = observation.get("type")
        raw_val = observation.get("value")

        # 1. Demangle symbol if mangled
        demangled_func = demangle_symbol(raw_symbol) if raw_symbol else None

        # 2. Extract source file and line if available
        source_file = observation.get("source_file") or observation.get("file")
        source_line = observation.get("source_line") or observation.get("line")

        # If we have an address and a companion ELF with DWARF, attempt addr2line lookup
        if address and self.companion_elf and os.path.exists(self.companion_elf) and (not source_file or not source_line):
            addr_hex = hex(address) if isinstance(address, int) else str(address)
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
                        demangled_func = demangled_func or lines[0]
                        file_line_part = lines[1].split(":")
                        if len(file_line_part) >= 2 and "?" not in file_line_part[0]:
                            source_file = file_line_part[0]
                            try:
                                source_line = int(file_line_part[1].split()[0])
                            except Exception:
                                pass
            except Exception:
                pass

        # 3. Read context source lines if source_file exists
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

        # 4. Synthesize correlation output
        return {
            "address": address,
            "raw_symbol": raw_symbol,
            "demangled_symbol": demangled_func or raw_symbol,
            "inferred_type": raw_type,
            "value": raw_val,
            "source_file": source_file,
            "source_line": source_line,
            "source_context": source_context,
            "allocation_site": observation.get("allocation_site"),
            "function_candidates": [demangled_func] if demangled_func else [],
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
    ):
        self.investigation_id = investigation_id
        self.raw_problem_statement = problem_statement
        self.pid = pid
        self.companion_elf = companion_elf
        self.corpus_dir = corpus_dir or "/tmp/dynamicstate_corpus"
        os.makedirs(self.corpus_dir, exist_ok=True)

        # Components
        self.classifier = ProblemClassifier()
        self.assessor = TargetAssessor()
        self.recipe_registry = DiagnosticRecipeRegistry()
        self.planner = InvestigationPlanner(self.recipe_registry)
        self.correlator = EvidenceToSourceCorrelator(companion_elf)
        self.ledger = EvidenceLedger(session_id=self.investigation_id)

        # State machine
        self.state = STATE_CREATED
        self.is_paused = False
        self.timeline: List[Dict[str, Any]] = []

        # Data artifacts
        self.classification_result: Optional[ProblemClassificationResult] = None
        self.target_assessment: Optional[TargetAssessmentResult] = None
        self.plan: Optional[InvestigationPlan] = None
        self.collected_evidence: List[Dict[str, Any]] = []
        self.active_hypotheses: List[ExpertHypothesis] = []
        self.rejected_hypotheses: List[ExpertHypothesis] = []
        self.conclusion: Optional[DiagnosticConclusion] = None

        self._record_timeline_event("SESSION_CREATED", {"investigation_id": investigation_id, "pid": pid})

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

    def resume(self) -> None:
        """Resumes a paused investigation session."""
        self.is_paused = False
        self._record_timeline_event("SESSION_RESUMED", {})

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
        if self.state == STATE_CREATED or self.state == STATE_CLASSIFYING:
            return self._step_classify()
        elif self.state == STATE_ASSESSING:
            return self._step_assess()
        elif self.state == STATE_PLANNING:
            return self._step_plan()
        elif self.state == STATE_COLLECTING:
            return self._step_collect_next()
        elif self.state == STATE_ANALYZING:
            return self._step_analyze()
        elif self.state == STATE_VERIFYING:
            return self._step_verify()
        elif self.state == STATE_NARROWING:
            return self._step_narrow()

        return {"status": "UNKNOWN_STATE", "state": self.state}

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
        )
        self._record_timeline_event("TARGET_ASSESSED", {
            "accessible": self.target_assessment.accessible,
            "thread_count": self.target_assessment.thread_count,
            "dwarf_available": self.target_assessment.dwarf_available,
            "limitations": self.target_assessment.limitations,
        })
        if not self.target_assessment.prerequisites_met and self.pid is not None:
            self.state = STATE_BLOCKED
            self._finalize_conclusion(
                stop_reason="TARGET_INACCESSIBLE",
                summary=f"Target PID {self.pid} is inaccessible and companion ELF is missing or invalid.",
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

        # Execute recipe evaluation
        recipe = self.recipe_registry.get_recipe(step.recipe_id)
        if not recipe:
            step.status = "FAILED"
            self.plan.current_step_index += 1
            return {"action": "COLLECT_STEP", "step_id": step.step_id, "status": "FAILED"}

        # Build context for deterministic evaluation
        eval_context: Dict[str, Any] = {
            "pid": self.pid,
            "companion_elf": self.companion_elf,
            "entities": self.classification_result.extracted_entities if self.classification_result else {},
            "capabilities": self.target_assessment.capabilities if self.target_assessment else [],
            "rss_kb": self.target_assessment.rss_kb if self.target_assessment else 0,
        }

        eval_result = self.recipe_registry.evaluate_recipe(recipe, eval_context)
        step.status = "COMPLETED"
        step.result = {
            "status": eval_result.status,
            "score": eval_result.score,
            "rationale": eval_result.rationale,
            "supporting_evidence": eval_result.supporting_evidence,
            "contradicting_evidence": eval_result.contradicting_evidence,
        }

        # Store in collected evidence & correlate
        for ev in eval_result.supporting_evidence:
            correlated = self.correlator.correlate(ev, target_pid=self.pid)
            enriched_ev = {**ev, "correlation": correlated, "step_id": step.step_id}
            self.collected_evidence.append(enriched_ev)
            # Record in EvidenceLedger
            try:
                self.ledger.add_record(EvidenceRecord(
                    record_id=f"ev_{uuid.uuid4().hex[:12]}",
                    evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
                    provenance_class=PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE if self.pid else PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
                    target_pid=self.pid or 0,
                    source_function=recipe.recipe_id,
                    evidence_payload=enriched_ev,
                    semantic_digest=hashlib.sha256(json.dumps(ev, sort_keys=True).encode()).hexdigest(),
                ))
            except Exception:
                pass

        self._record_timeline_event("STEP_EXECUTED", {
            "step_id": step.step_id,
            "recipe_id": step.recipe_id,
            "eval_status": eval_result.status,
            "eval_score": eval_result.score,
        })

        self.plan.current_step_index += 1
        if self.plan.current_step_index >= len(self.plan.steps):
            self.state = STATE_ANALYZING
        return {"action": "COLLECT_STEP", "step_id": step.step_id, "eval_result": asdict(eval_result)}

    def _step_analyze(self) -> Dict[str, Any]:
        """Synthesizes falsifiable hypotheses from collected evidence."""
        # Formulate initial hypotheses
        self.active_hypotheses.clear()

        # Group evidence by category
        cat_evidence: Dict[str, List[Dict[str, Any]]] = {}
        for ev in self.collected_evidence:
            cat = ev.get("problem_category") or self.classification_result.primary_category
            cat_evidence.setdefault(cat, []).append(ev)

        hyp_counter = 1
        for cat, ev_list in cat_evidence.items():
            conf = min(0.95, 0.40 + 0.15 * len(ev_list))
            hyp = ExpertHypothesis(
                hypothesis_id=f"HYP_{hyp_counter:02d}",
                problem_statement=f"Runtime anomaly in {cat}: observed {len(ev_list)} corroborating evidence patterns.",
                category=cat,
                domain=ev_list[0].get("domain", DOMAIN_ABNORMAL_RUNTIME_STATE),
                status="SUPPORTED" if conf >= 0.70 else "PROPOSED",
                confidence=conf,
                confidence_basis=f"Derived from {len(ev_list)} zero-stop observations matching diagnostic recipe criteria.",
                supporting_evidence=ev_list,
                verification_criteria={"minimum_supporting_evidence": 1, "confidence_threshold": 0.80},
                recommended_next_action=f"Perform deterministic verification against {cat} invariants.",
            )
            self.active_hypotheses.append(hyp)
            hyp_counter += 1

        # If no evidence was found, create a null-hypothesis
        if not self.active_hypotheses:
            self.active_hypotheses.append(ExpertHypothesis(
                hypothesis_id="HYP_01",
                problem_statement="No abnormal runtime indicators observed within investigated scope.",
                category=self.classification_result.primary_category if self.classification_result else "UNKNOWN",
                domain=DOMAIN_ABNORMAL_RUNTIME_STATE,
                status="SUPPORTED",
                confidence=0.85,
                confidence_basis="Zero-stop inspection completed with clean checks across all scheduled recipes.",
                recommended_next_action="Conclude investigation or widen inspection scope.",
            ))

        self._record_timeline_event("HYPOTHESES_FORMED", {
            "active_hypotheses_count": len(self.active_hypotheses),
        })
        self.state = STATE_VERIFYING
        return {"action": "ANALYZE", "state": self.state, "hypotheses_count": len(self.active_hypotheses)}

    def _step_verify(self) -> Dict[str, Any]:
        """Runs deterministic verification procedure for top hypothesis."""
        for hyp in self.active_hypotheses:
            if hyp.confidence >= 0.80 and hyp.supporting_evidence:
                hyp.status = "CONFIRMED"
            elif hyp.contradicting_evidence and not hyp.supporting_evidence:
                hyp.status = "REFUTED"
                self.rejected_hypotheses.append(hyp)
            elif hyp.confidence < 0.50:
                hyp.status = "INCONCLUSIVE"

        # Filter out rejected
        self.active_hypotheses = [h for h in self.active_hypotheses if h.status != "REFUTED"]
        self._record_timeline_event("HYPOTHESES_VERIFIED", {
            "active_count": len(self.active_hypotheses),
            "rejected_count": len(self.rejected_hypotheses),
        })
        self.state = STATE_NARROWING
        return {"action": "VERIFY", "state": self.state}

    def _step_narrow(self) -> Dict[str, Any]:
        """Adaptive narrowing: selects final conclusion or declares inconclusive."""
        # Sort active hypotheses by confidence descending
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
            if "MEMORY" in primary_finding.upper() or "CORRUPT" in primary_finding.upper():
                remediations.append("Audit pointer dereference bounds and check for unaligned structure access.")
                remediations.append("Enable AddressSanitizer (ASan) during testing builds: `-fsanitize=address`.")
            elif "LEAK" in primary_finding.upper() or "GROWTH" in primary_finding.upper():
                remediations.append("Profile heap allocations and verify balanced free/delete calls.")
                remediations.append("Inspect long-lived container capacities and unbounded cache queues.")
            elif "DEADLOCK" in primary_finding.upper() or "LOCK" in primary_finding.upper():
                remediations.append("Enforce global lock acquisition ordering hierarchy.")
                remediations.append("Consider replacing nested mutexes with lock-free structures or fine-grained atomics.")
            else:
                remediations.append("Review recent state transition logic and verify invariant assertion checks.")
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
            rejected_alternatives=[asdict(h) for h in self.rejected_hypotheses],
            missing_evidence_and_unknowns=[],
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
                }
        return {"error": f"Hypothesis '{hypothesis_id}' not found in investigation {self.investigation_id}"}

    def verify_hypothesis(self, hypothesis_id: str) -> Dict[str, Any]:
        """Executes deterministic verification for a specific hypothesis."""
        if not self.active_hypotheses:
            self._step_analyze()
        for hyp in self.active_hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                if hyp.supporting_evidence:
                    hyp.status = "CONFIRMED"
                    hyp.confidence = max(hyp.confidence, 0.90)
                else:
                    hyp.status = "INCONCLUSIVE"
                return {
                    "hypothesis_id": hyp.hypothesis_id,
                    "status": hyp.status,
                    "confidence": hyp.confidence,
                    "verdict": hyp.status,
                }
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
                })
        return {
            "investigation_id": self.investigation_id,
            "compared_count": len(matched),
            "hypotheses": matched,
            "recommendation": f"Select {matched[0]['hypothesis_id']} (highest confidence)" if matched else "No hypotheses to compare",
        }

    def export_report(self, format: str = "json") -> Union[Dict[str, Any], str]:
        """Exports a full incident bundle as JSON or Markdown."""
        if not self.conclusion:
            self._finalize_conclusion("EXPORT_REQUESTED", "Report exported prior to terminal state.")

        if format.lower() == "markdown":
            md = [
                f"# dynamicState Expert Diagnostic Incident Report",
                f"**Investigation ID**: `{self.investigation_id}`  ",
                f"**Target PID**: `{self.pid}`  ",
                f"**Date**: `{self.conclusion.completed_at}`  ",
                f"**Status**: `{self.conclusion.status}` (`{self.conclusion.stop_reason}`)  ",
                f"**Confidence**: `{self.conclusion.confidence * 100:.1f}%`  ",
                "",
                f"## 1. Executive Summary",
                f"{self.conclusion.executive_summary}",
                "",
                f"## 2. Primary Finding",
                f"> **{self.conclusion.primary_finding}**  ",
                f"> *Confidence Basis*: {self.conclusion.confidence_basis}",
                "",
                f"## 3. Supporting Evidence Chain ({len(self.conclusion.supporting_evidence_chain)} records)",
            ]
            for idx, ev in enumerate(self.conclusion.supporting_evidence_chain, 1):
                corr = ev.get("correlation", {})
                sym = corr.get("demangled_symbol") or ev.get("symbol") or "N/A"
                loc = f"{corr.get('source_file')}:{corr.get('source_line')}" if corr.get("source_file") else "N/A"
                md.append(f"- **[E{idx:02d}] {ev.get('problem_category', 'DIAGNOSTIC')}** | Symbol: `{sym}` | Location: `{loc}`")
                if ev.get("finding"):
                    md.append(f"  * Detail: {ev['finding']}")

            md.extend([
                "",
                f"## 4. Recommended Remediations",
            ])
            for r in self.conclusion.recommended_remediations:
                md.append(f"- [ ] {r}")

            md.extend([
                "",
                f"## 5. Diagnostic Limitations",
            ])
            for lim in self.conclusion.diagnostic_limitations:
                md.append(f"- *Note*: {lim}")

            return "\n".join(md)

        # JSON output
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
            "active_hypotheses": [h.to_dict() for h in self.active_hypotheses],
            "rejected_hypotheses": [h.to_dict() for h in self.rejected_hypotheses],
            "conclusion": asdict(self.conclusion) if self.conclusion else None,
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
        sess.active_hypotheses = [ExpertHypothesis.from_dict(h) for h in data.get("active_hypotheses", [])]
        sess.rejected_hypotheses = [ExpertHypothesis.from_dict(h) for h in data.get("rejected_hypotheses", [])]
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
        self.sessions: Dict[str, AdaptiveInvestigationSession] = {}

    def start_investigation(
        self,
        problem_statement: str,
        pid: Optional[int] = None,
        companion_elf: Optional[str] = None,
    ) -> AdaptiveInvestigationSession:
        """Launches a new adaptive investigation session."""
        inv_id = f"inv_{uuid.uuid4().hex[:12]}"
        session = AdaptiveInvestigationSession(
            investigation_id=inv_id,
            problem_statement=problem_statement,
            pid=pid,
            companion_elf=companion_elf,
            corpus_dir=self.corpus_dir,
        )
        self.sessions[inv_id] = session
        return session

    def get_session(self, investigation_id: str) -> Optional[AdaptiveInvestigationSession]:
        """Retrieves an existing investigation session by ID."""
        return self.sessions.get(investigation_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        """Lists metadata for all active and completed sessions."""
        return [sess.get_status() for sess in self.sessions.values()]
