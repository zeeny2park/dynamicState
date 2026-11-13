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

from dataclasses import dataclass, field, fields
from .dataclass_dict import asdict  # same result as dataclasses.asdict, much faster on large observations
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
import re
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import uuid

from .diagnostic_recipes import (
    recipe_requires_lock_owner,
    BASELINE_RECIPE_IDS,
    CAPABILITY_DESCRIPTIONS,
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
    RECIPE_STATUS_NOT_APPLICABLE,
    EVAL_STATUS_NOT_APPLICABLE,
    DiagnosticRecipe,
    DiagnosticRecipeRegistry,
    RecipeEvaluationResult,
)
from .diagnostic_rule_model import (
    VERDICT_CONFIRMED,
    VERDICT_LIKELY,
    VERDICT_SUPPORTED,
    VERDICT_REFUTED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_APPLICABLE,
    DiagnosticRule,
    RuleApplicabilityResult,
)
from .temporal_observation_window import (
    ObservationWindow,
    MemorySample,
    MemoryBehavior,
    MemoryAnalysisResult,
)
from .competing_hypotheses import (
    CompetingHypothesis,
    CompetingHypothesisManager,
    HypothesisComparisonResult,
)
from .cpp_structural_discovery import (
    CppStructuralDiscovery,
    CppRelationshipCandidate,
    ExpertOverrideConstraint,
)
from .invariant_framework import (
    InvariantDefinition,
    InvariantType,
    InvariantSource,
    InvariantEvaluator,
    InvariantEvaluationResult,
)
from .concurrency_graph import (
    WaitForGraph,
    ConcurrencyState,
)
from .allocator_inspector import (
    AllocatorType,
    AllocatorInspector,
    detect_allocator,
    FreeValidationOutcome,
    GlibcPtMallocInspector,
    JemallocInspector,
    TcmallocInspector,
    CustomAllocatorInspector,
    UnknownAllocatorInspector,
)
from .evidence_adapter import (
    EvidenceAdapter,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
)
from .observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
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
from .target_adapter import LocalTargetAdapter, RemoteSshTargetAdapter, TargetExecutionAdapter
from .watch_session import read_process_memory_slice
from .diagnostic_methodology import (
    CheckStatus,
    DiagnosticCheck,
    DiagnosticMethodology,
    MethodologySelector,
)
from .diagnostic_report import (
    CLASSIFICATION_ANOMALY,
    CLASSIFICATION_CONFIRMED_ROOT_CAUSE,
    CLASSIFICATION_OBSERVED_SYMPTOM,
    CLASSIFICATION_PROBABLE_CAUSE,
    CompetingHypothesesSection,
    DetailedInspectionResultsSection,
    DiagnosticReport,
    DiagnosticStrategySection,
    EvidenceAndProvenanceSection,
    EvidenceIndexEntry,
    ExecutiveSummarySection,
    FinalConclusionsSection,
    FindingRecord,
    FindingsSection,
    LimitationsSection,
    TargetContextSection,
)
from .diagnostic_verdict_aggregator import (
    DiagnosticVerdictAggregator,
    AggregatedVerdict,
    VERDICT_CONFIRMED_FAULT,
    VERDICT_PROBABLE_FAULT,
    VERDICT_HEALTHY,
    VERDICT_INCONCLUSIVE,
    VERDICT_ABORTED,
)
from .healthy_verdict import (
    HEALTHY_RULE_ID,
    evaluate as evaluate_healthy,
    long_wait_scope_items,
    not_healthy_scope,
    summary_sentence as healthy_summary_sentence,
)
from .modules import ModuleAddressResolver
from .debug_image import inspect_elf


class DurableCommitOutcome(str, Enum):
    NOT_COMMITTED = "NOT_COMMITTED"
    COMMITTED = "COMMITTED"
    COMMIT_UNKNOWN = "COMMIT_UNKNOWN"


class InvestigationPersistenceError(RuntimeError):
    """Raised when investigation state persistence fails."""
    def __init__(
        self,
        message: str,
        outcome: DurableCommitOutcome = DurableCommitOutcome.NOT_COMMITTED,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.outcome = outcome
        self.cause = cause

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
STATE_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"

TERMINAL_STATES = {STATE_COMPLETED, STATE_INCONCLUSIVE, STATE_BLOCKED, STATE_FAILED, STATE_BUDGET_EXHAUSTED}


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
    # Stage 2 (symptom_interpretation): the symptom class behind primary_category, whether the symptom was
    # understood specifically (False: LOW confidence, the broad plan was used) and the full interpretation.
    symptom_class: str = ""
    understood: bool = True
    confidence_level: str = "HIGH"
    interpretation: Optional[Dict[str, Any]] = None


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
            "en": ["memory leak", "leak", "leaking", "rss growth", "heap growth", "unbounded growth", "oom", "out of memory", "allocations accumulating", "unfreed", "allocation and free imbalance", "allocation imbalance", "alloc imbalance", "free imbalance", "memory usage is growing", "memory usage growing", "growing memory", "memory growth"],
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
            "en": ["deadlock", "lock inversion", "hang", "blocked thread", "circular wait", "mutex stuck", "waiting for lock", "deadlocked", "freeze", "freezes", "freezing", "occasionally freezes", "stalls", "stalled", "unresponsive"],
            "ko": ["데드락", "교착 상태", "락 역전", "스레드 블록", "락 대기", "응답 없음", "멈춤", "멈췄", "뮤텍스 대기", "간헐적 멈춤", "프리징"],
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
            "en": ["process instability", "frequent crash", "intermittent restart", "unstable process", "flapping", "flaky process", "crashing repeatedly", "crashes after running", "crashes after", "running for several hours", "application crashes"],
            "ko": ["프로세스 불안정", "잦은 크래시", "간헐적 종료", "재부팅 반복", "재부팅", "불안정한 프로세스", "불안정", "자주 죽", "장시간 실행 후 크래시"],
        },
        CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY: {
            "en": ["state inconsistency", "invariant violated", "corrupted internal state", "mismatched state", "buffer mismatch", "inconsistent state"],
            "ko": ["기능적 상태 불일치", "불변식 위반", "내부 상태 불일치", "버퍼 상태 모순", "정합성 깨짐", "일관성 훼손"],
        },
    }

    def classify(self, query: str, fields: Any = None) -> ProblemClassificationResult:
        """Classify a symptom (free text and/or structured fields) into a symptom class and plan categories.

        Delegates the interpretation to :func:`extractor.symptom_interpretation.interpret_symptom` (normalisation,
        bilingual vocabulary per class, precedence, explicit confidence).  CATEGORY_KEYWORDS above is the legacy
        keyword table; it is no longer used for classification.
        """
        from .symptom_interpretation import interpret_symptom, parse_symptom_fields, related_identifiers
        raw_query = query or ""
        parsed = parse_symptom_fields(fields)
        interp = interpret_symptom(raw_query, parsed)
        extracted_entities = self._extract_entities(raw_query)
        if parsed and parsed.related_objects:
            variables, functions = related_identifiers(parsed.related_objects)
            for key, vals in (("variables", variables), ("functions", functions)):
                for v in vals:
                    if v not in extracted_entities[key]:
                        extracted_entities[key].append(v)
            extracted_entities["related_objects"] = list(parsed.related_objects)

        if interp.broad_plan:
            # Broad multi-domain screening: asked for (health check / no text) or the fallback of LOW confidence.
            normalized_scores = [
                (CATEGORY_PROCESS_INSTABILITY, 0.50),
                (CATEGORY_DEADLOCK_INDICATORS, 0.45),
                (CATEGORY_MEMORY_LEAK, 0.40),
                (CATEGORY_MEMORY_CORRUPTION, 0.35),
            ]
            confidence = 0.45 if interp.understood else 0.0
            screening_strategy = (
                "BROAD_MULTI_DOMAIN_SCREENING: Multi-domain assessment across "
                "Memory Integrity (null/guard probes), Memory Growth (RSS/heap delta), "
                "Abnormal State (variable boundaries), and Concurrency (thread blocking & deadlock check)."
            )
        else:
            normalized_scores = list(interp.candidate_categories)
            confidence = interp.confidence
            screening_strategy = None

        return ProblemClassificationResult(
            raw_query=raw_query,
            normalized_query=raw_query.strip().lower(),
            primary_category=interp.primary_category,
            candidate_categories=normalized_scores,
            confidence=confidence,
            extracted_entities=extracted_entities,
            is_vague=interp.broad_plan,
            screening_strategy=screening_strategy,
            symptom_class=interp.symptom_class,
            understood=interp.understood,
            confidence_level=interp.confidence_level,
            interpretation=interp.to_dict(),
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
    allocator_type: str = "UNKNOWN"
    allocator_confidence: str = "UNKNOWN"
    allocator_basis: str = ""
    allocator_inspector: Optional[Any] = None
    build_id: Optional[str] = None
    process_identity: Optional[str] = None
    executable_identity: Optional[str] = None
    build_id_check: Optional[Dict[str, Any]] = None  # {status MATCHED|MISMATCHED|UNKNOWN, process_build_id, debug_build_id}
    target_abi: Optional[Dict[str, Any]] = None  # TargetABI.to_dict() read through the adapter at diagnosis time

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "accessible": self.accessible,
            "thread_count": self.thread_count,
            "memory_regions_count": self.memory_regions_count,
            "rss_kb": self.rss_kb,
            "companion_elf_path": self.companion_elf_path,
            "companion_elf_valid": self.companion_elf_valid,
            "dwarf_available": self.dwarf_available,
            "capabilities": self.capabilities,
            "limitations": self.limitations,
            "prerequisites_met": self.prerequisites_met,
            "target_host": self.target_host,
            "memory_readable": self.memory_readable,
            "mode": self.mode,
            "allocator_type": self.allocator_type,
            "allocator_confidence": self.allocator_confidence,
            "allocator_basis": self.allocator_basis,
            "build_id": self.build_id,
            "process_identity": self.process_identity,
            "executable_identity": self.executable_identity,
            "build_id_check": self.build_id_check,
            "target_abi": self.target_abi,
        }


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
        maps: List[Dict[str, Any]] = []

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

                # Read memory maps (retry briefly if freshly spawned process is still in ld.so startup)
                maps: List[Dict[str, Any]] = []
                try:
                    maps = target_adapter.get_proc_maps(pid)
                    if not target_adapter.is_remote() and not any("libc" in (m.get("pathname") or m.get("name", "")) for m in maps):
                        for _ in range(5):
                            time.sleep(0.01)
                            maps = target_adapter.get_proc_maps(pid)
                            if any("libc" in (m.get("pathname") or m.get("name", "")) for m in maps):
                                break
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

        # 3. Allocator detection
        allocator_abi = None
        if pid is not None and pid > 1 and accessible:
            from .target_abi import detect_target_abi
            allocator_abi = detect_target_abi(target_adapter, pid, probe_version=False)
        allocator_det = detect_allocator(maps=maps, symbols=None, target_abi=allocator_abi)
        if allocator_det and allocator_det.allocator_type != AllocatorType.UNKNOWN:
            capabilities.append(f"ALLOCATOR_{allocator_det.allocator_type.value.upper()}")
            capabilities.append(f"ALLOCATOR_CONFIDENCE_{allocator_det.confidence.upper()}")
        else:
            basis_str = allocator_det.basis if allocator_det else "not detected"
            limitations.append(f"Allocator is UNKNOWN ({basis_str}); heap chunk inspection will be restricted")

        # Live PID must be accessible to satisfy prerequisites for live mode; offline mode only requires valid ELF/snapshot
        if pid is not None and pid > 0:
            prerequisites_met = accessible
        else:
            prerequisites_met = bool(companion_elf is not None and elf_valid)

        # Extract verified target identity attributes without fabrication
        proc_identity = None
        executable_identity = None
        build_id = None
        if pid is not None and pid > 1 and accessible:
            try:
                proc_info = target_adapter.get_process_identity(pid)
                proc_identity = proc_info.get("process_identity")
                executable_identity = proc_info.get("executable_identity") or proc_info.get("executable")
                build_id = proc_info.get("build_id")
            except Exception:
                pass

        process_build_id = build_id
        build_id_check: Optional[Dict[str, Any]] = None
        if companion_elf and os.path.exists(companion_elf):
            try:
                from .target_adapter import inspect_elf
                companion_info = inspect_elf(companion_elf)
                build_id_check = {"status": "UNKNOWN", "process_build_id": process_build_id,
                                  "debug_build_id": companion_info.build_id or None}
                if companion_info.build_id and process_build_id:
                    same = str(process_build_id).strip().lower() == str(companion_info.build_id).strip().lower()
                    build_id_check["status"] = "MATCHED" if same else "MISMATCHED"
                if companion_info.build_id:
                    if build_id and str(build_id).strip().lower() != str(companion_info.build_id).strip().lower():
                        limitations.append(
                            f"Build ID mismatch: process ({build_id}) != companion ELF ({companion_info.build_id})"
                        )
                        dwarf_available = False
                        capabilities = [c for c in capabilities if c != "DWARF_DEBUG_INFO"]
                        build_id = None
                    elif not build_id:
                        build_id = companion_info.build_id
                if not executable_identity:
                    executable_identity = companion_elf
            except Exception:
                pass

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
            allocator_type=allocator_det.allocator_type.value if allocator_det else "UNKNOWN",
            allocator_confidence=allocator_det.confidence if allocator_det else "UNKNOWN",
            allocator_basis=allocator_det.basis if allocator_det else "",
            allocator_inspector=allocator_det.inspector if allocator_det else None,
            build_id=build_id,
            process_identity=proc_identity,
            executable_identity=executable_identity,
            build_id_check=build_id_check,
            target_abi=allocator_abi.to_dict() if allocator_abi is not None else None,
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

    def score_and_build_step(
        self,
        recipe: DiagnosticRecipe,
        rel_weight: float,
        step_id: str,
        priority: int,
        target_assessment: Optional[TargetAssessmentResult] = None,
        rationale_override: Optional[str] = None,
    ) -> InvestigationStep:
        """Computes multi-factor score and constructs a valid InvestigationStep."""
        diag_val = 0.85 if len(recipe.verification_procedure) >= 2 else 0.70
        info_gain = 0.80
        avail = 0.90
        caps = target_assessment.capabilities if target_assessment else []
        if "DWARF_DEBUG_INFO" not in caps:
            if "DWARF" in recipe.output_structure or "vtable" in recipe.recipe_id.lower():
                avail = 0.50
        cost_score = 0.95
        safety_score = 1.00
        combined_score = round(
            0.30 * rel_weight +
            0.25 * diag_val +
            0.20 * info_gain +
            0.15 * avail +
            0.05 * cost_score +
            0.05 * safety_score,
            3
        )
        rationale = rationale_override or (
            f"Evaluates {recipe.problem_category} in domain {recipe.domain} "
            f"with multi-factor score {combined_score:.2f} (relevance={rel_weight:.2f}, "
            f"availability={avail:.2f})."
        )
        return InvestigationStep(
            step_id=step_id,
            recipe_id=recipe.recipe_id,
            recipe_name=recipe.name,
            category=recipe.problem_category,
            domain=recipe.domain,
            rationale=rationale,
            priority=priority,
            cost_score=cost_score,
            safety_score=safety_score,
            expected_info_gain=info_gain,
            multi_factor_score=combined_score,
        )

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
            ]
            for r_id in domain_reps:
                r = self.recipe_registry.get_plannable_recipe(r_id)
                if r:
                    candidate_recipes.append((r, 0.75))
        else:
            # Map candidate categories to matching recipes
            for cat, weight in classification.candidate_categories:
                recs = self.recipe_registry.get_recipes_for_category(cat, plannable_only=True)
                for r in recs:
                    if not any(cr[0].recipe_id == r.recipe_id for cr in candidate_recipes):
                        candidate_recipes.append((r, weight))

        # If no recipes found, fallback to generic screening
        if not candidate_recipes:
            for r in self.recipe_registry.list_recipes(plannable_only=True)[:4]:
                candidate_recipes.append((r, 0.5))

        # Baseline checks always run; the symptom only orders them (relevance) and adds recipes around them.
        for r_id in BASELINE_RECIPE_IDS:
            if not any(cr[0].recipe_id == r_id for cr in candidate_recipes):
                r = self.recipe_registry.get_recipe(r_id)
                if r:
                    candidate_recipes.append((r, 0.4))

        # Multi-factor scoring for each candidate recipe
        # Weights: relevance (0.30), diagnostic value (0.25), info gain (0.20),
        #          availability (0.15), cost (0.05), safety (0.05)
        step_id_counter = 1
        for recipe, rel_weight in candidate_recipes:
            steps.append(self.score_and_build_step(
                recipe=recipe,
                rel_weight=rel_weight,
                step_id=f"STEP_{step_id_counter:02d}",
                priority=step_id_counter,
                target_assessment=target_assessment,
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
            f"and zero-stop safety. Baseline checks always planned: {', '.join(BASELINE_RECIPE_IDS)}."
        )
        if not getattr(classification, "understood", True):
            plan_rationale = (
                "Symptom not understood specifically (low classification confidence): broad multi-domain plan "
                "used instead of a narrow one. " + plan_rationale
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

    def __init__(self, companion_elf: Optional[str] = None, adapter: Optional[Any] = None):
        self.companion_elf = companion_elf
        self.adapter = adapter   # a remote adapter supplies /proc/<pid>/maps (a local file would be another host's)

    def correlate(
        self,
        observation: Dict[str, Any],
        target_pid: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Correlates a raw observation to C++ types, DWARF symbols, and source code,
        accounting for ASLR load bias using PT_LOAD, validating Build IDs, and
        returning unresolved results instead of incorrect source mappings.
        """
        address = observation.get("address") if observation.get("address") is not None else (
            observation.get("target_address") if observation.get("target_address") is not None else observation.get("faulting_address")
        )
        if isinstance(address, str) and address.startswith("0x"):
            try:
                address = int(address, 16)
            except Exception:
                pass

        raw_symbol = observation.get("symbol") or observation.get("function") or observation.get("pointer_name")
        raw_type = observation.get("type") or observation.get("type_name")
        raw_val = observation.get("value") if observation.get("value") is not None else observation.get("observed_value")

        # 1. Demangle symbol if mangled
        demangled_func = demangle_symbol(raw_symbol) if raw_symbol else None

        # 2. Account for ASLR and module load bias using PT_LOAD and Build ID validation
        load_bias = 0
        load_bias_status = "UNRESOLVED"
        build_id_status = "NOT_AVAILABLE"
        elf_addr = address
        target_build_id = observation.get("build_id")

        if self.companion_elf and os.path.exists(self.companion_elf):
            try:
                elf_info = inspect_elf(self.companion_elf)
                elf_type = getattr(elf_info, "elf_type", None)
                elf_build_id = getattr(elf_info, "build_id", None)

                # Validate Build ID equality if target build id is provided
                if target_build_id and elf_build_id:
                    if target_build_id != elf_build_id:
                        build_id_status = "MISMATCH"
                    else:
                        build_id_status = "VERIFIED"

                if build_id_status != "MISMATCH":
                    if elf_type == "ET_EXEC":
                        load_bias = 0
                        load_bias_status = "RESOLVED"
                    elif target_pid and target_pid > 0:
                        maps_path = f"/proc/{target_pid}/maps"
                        remote = self.adapter is not None and self.adapter.is_remote()
                        if remote or os.path.exists(maps_path):
                            elf_base = os.path.basename(self.companion_elf)
                            mappings = []
                            if remote:
                                for m in self.adapter.get_proc_maps(target_pid) or []:
                                    if elf_base in str(m.get("pathname") or ""):
                                        mappings.append({
                                            "start": m["start_int"], "end": m["end_int"],
                                            "permissions": m["permissions"], "offset": m["offset_int"],
                                            "pathname": m["pathname"],
                                        })
                            else:
                                with open(maps_path, "r", errors="replace") as f:
                                    for line in f:
                                        parts = line.split()
                                        if len(parts) >= 6 and elf_base in parts[5]:
                                            addr_range = parts[0].split("-")
                                            mappings.append({
                                                "start": int(addr_range[0], 16),
                                                "end": int(addr_range[1], 16),
                                                "permissions": parts[1],
                                                "offset": int(parts[2], 16),
                                                "pathname": parts[5],
                                            })
                            if mappings and elf_info:
                                try:
                                    load_bias = ModuleAddressResolver.calculate_load_bias(mappings, elf_info)
                                    load_bias_status = "RESOLVED"
                                except Exception:
                                    first_pt = elf_info.pt_loads[0] if elf_info.pt_loads else {}
                                    p_vaddr = first_pt.get("p_vaddr", 0)
                                    load_bias = mappings[0]["start"] - p_vaddr
                                    load_bias_status = "RESOLVED"
            except Exception:
                pass

        # 3. Extract source file and line if available
        source_file = observation.get("source_file") or observation.get("file")
        source_line = observation.get("source_line") or observation.get("line")

        # Compute relative ELF file address for addr2line
        if address and isinstance(address, int):
            if load_bias_status == "RESOLVED":
                elf_addr = address - load_bias
                if elf_addr < 0:
                    load_bias_status = "UNRESOLVED"
                    elf_addr = None
            else:
                elf_addr = None

        # If we have an address and a companion ELF with DWARF, attempt addr2line lookup
        if elf_addr and isinstance(elf_addr, int) and load_bias_status == "RESOLVED" and build_id_status != "MISMATCH" and self.companion_elf and os.path.exists(self.companion_elf) and (not source_file or not source_line):
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
            "load_bias": f"0x{load_bias:x}" if load_bias_status == "RESOLVED" else f"0x{load_bias:x}",
            "load_bias_status": load_bias_status,
            "build_id_status": build_id_status,
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
            "correlated": bool(source_file and source_line),
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
    overall_verdict: Optional[str] = None


# States in which a session without any executed check still has a truthful report: it says why nothing ran.
_REPORTABLE_WITHOUT_CHECKS = {STATE_BLOCKED, STATE_FAILED, STATE_BUDGET_EXHAUSTED, STATE_INCONCLUSIVE}


# run_to_completion without an explicit max_steps: at least DEFAULT_MIN_STEP_CAP steps, and never fewer than the
# plan's own steps plus STEP_MARGIN_BEYOND_PLAN.
DEFAULT_MIN_STEP_CAP = 30
STEP_MARGIN_BEYOND_PLAN = 10


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
        expert_overrides: Optional[List[Any]] = None,
        manual_invariants: Optional[List[Any]] = None,
        observation_interval: Optional[float] = None,
        observation_duration: Optional[float] = None,
        target_recipe: Optional[str] = None,
        target_expressions: Optional[List[str]] = None,
        recipe_thresholds: Optional[Dict[str, Any]] = None,
        budget_tracker: Optional[ObservationBudgetTracker] = None,
        budget_limits: Optional[ObservationBudgetLimits] = None,
        symptom_fields: Any = None,
    ):
        from .symptom_interpretation import parse_symptom_fields
        self.investigation_id = investigation_id
        self.raw_problem_statement = problem_statement
        self.symptom_fields = parse_symptom_fields(symptom_fields)   # structured symptom input (stage 2), or None
        self.pid = pid
        self.companion_elf = companion_elf
        self.corpus_dir = corpus_dir or "/tmp/dynamicstate_corpus"
        self._investigations_dir = os.path.join(self.corpus_dir, "investigations")
        os.makedirs(self._investigations_dir, exist_ok=True)
        self.adapter = adapter or LocalTargetAdapter()
        self.expert_overrides = expert_overrides or []
        self.manual_invariants = manual_invariants or []
        self.observation_interval = observation_interval or 0.05
        self.observation_duration = observation_duration or 1.0
        self.target_recipe = target_recipe
        self.target_expressions = list(target_expressions or [])
        self.recipe_thresholds = dict(recipe_thresholds or {})

        # Budget Tracker
        if budget_tracker is not None:
            self.budget_tracker = budget_tracker
        elif budget_limits is not None:
            self.budget_tracker = ObservationBudgetTracker(limits=budget_limits)
        else:
            self.budget_tracker = ObservationBudgetTracker(limits=ObservationBudgetLimits())

        # Components
        self.classifier = ProblemClassifier()
        self.assessor = TargetAssessor()
        self.recipe_registry = DiagnosticRecipeRegistry()
        self.planner = InvestigationPlanner(self.recipe_registry)
        self.correlator = EvidenceToSourceCorrelator(companion_elf, self.adapter)
        self.ledger = EvidenceLedger(session_id=self.investigation_id)
        self.evidence_adapter = EvidenceAdapter()
        self.evidence_provider = RuntimeEvidenceProvider(
            adapter=self.adapter,
            corpus_dir=self.corpus_dir,
            budget_tracker=self.budget_tracker,
        )
        # IMP-010: thread time-series sampling is configurable through the recipe thresholds
        self.evidence_provider.thread_sampling_overrides = {
            k: v for k, v in self.recipe_thresholds.items()
            if k in ("thread_sample_count", "thread_sample_interval_sec", "runaway_cpu_share")
        }
        # One thread sample series per run, shared by the thread recipes (the baseline runs two of them)
        self.evidence_provider.thread_series_cache = {}
        # IMP-008: memory is observed >= 3 times per run at the session's interval / window (cheap /proc samples
        # share the thread-sampling window; heap walks only when the trend or the run asks about memory).
        from .leak_attribution import MemoryObservationConfig
        self.evidence_provider.memory_observation = MemoryObservationConfig.from_session(
            self.observation_interval, self.observation_duration, self.recipe_thresholds, target_recipe=self.target_recipe)
        self.temporal_memory_samples: List[Dict[str, Any]] = []
        self.observation_window = ObservationWindow(
            target_pid=pid or 0,
            target_identity=str(self.adapter.target_host()),
            default_interval=self.observation_interval,
        )
        self.competing_hypotheses: List[CompetingHypothesis] = []
        self.observation_selection_log: List[Dict[str, Any]] = []  # discriminating-selector decisions (replanning)
        self.invariant_evaluator = InvariantEvaluator()
        self.allocator_inspector: Optional[AllocatorInspector] = None
        self.structural_discovery = CppStructuralDiscovery()
        self.concurrency_graph = WaitForGraph()

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
        self.methodology: Optional[DiagnosticMethodology] = None
        self.checks: List[DiagnosticCheck] = []

        self._record_timeline_event("SESSION_CREATED", {"investigation_id": investigation_id, "pid": pid})
        self._save_to_disk()

    def _save_to_disk(self) -> DurableCommitOutcome:
        """Persists authoritative investigation state atomically to disk.
        
        Durability and Trust Boundaries:
        1. Atomic File Replacement: Relies on POSIX rename semantics via os.replace().
        2. Pre-commit Durability: Writes to temporary file with mode 0600, explicit chmod verification,
           and fsync() before replacement.
        3. Durable Commit Point: os.replace(tmp_path, target_path) atomically replaces the target file.
           Prior to replace, outcome is NOT_COMMITTED.
        4. Post-replacement Durability: Calls os.fsync() on parent directory. If a failure occurs
           following replacement during directory fsync, outcome is COMMIT_UNKNOWN.
        5. Fail-Closed Boundaries: Rejects symlink directories and targets.
        """
        target_path = os.path.join(self._investigations_dir, f"{self.investigation_id}.json")
        tmp_path = os.path.join(self._investigations_dir, f".tmp_{self.investigation_id}_{uuid.uuid4().hex[:8]}")
        outcome = DurableCommitOutcome.NOT_COMMITTED

        try:
            # 1. Symlink and trust-boundary check
            if os.path.islink(self._investigations_dir):
                raise InvestigationPersistenceError(
                    f"Refusing to persist to symlink directory: {self._investigations_dir}",
                    outcome=DurableCommitOutcome.NOT_COMMITTED,
                )
            if os.path.lexists(target_path) and os.path.islink(target_path):
                raise InvestigationPersistenceError(
                    f"Refusing to overwrite symlink target: {target_path}",
                    outcome=DurableCommitOutcome.NOT_COMMITTED,
                )

            os.makedirs(self._investigations_dir, mode=0o700, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            fd = os.open(tmp_path, flags, 0o600)
            try:
                def _serialize_fallback(o):
                    if hasattr(o, "to_dict"):
                        return o.to_dict()
                    if hasattr(o, "value"):
                        return o.value
                    return str(o)

                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    # json.dump() always runs the pure-Python encoder and indent= disables the C encoder:
                    # on a many-thread target (tens of MB per save, one save per step) that was ~80% of a diagnosis.
                    f.write(json.dumps(self.to_dict(), default=_serialize_fallback))
                    f.flush()
                    # Apply and verify chmod 0600 - DO NOT SWALLOW
                    os.chmod(tmp_path, 0o600)
                    st = os.stat(tmp_path)
                    if (st.st_mode & 0o777) != 0o600:
                        raise InvestigationPersistenceError(
                            f"Permissions verification failed on {tmp_path}: mode {oct(st.st_mode & 0o777)} != 0600",
                            outcome=DurableCommitOutcome.NOT_COMMITTED,
                        )
                    os.fsync(f.fileno())
            except BaseException as pre_commit_err:
                try:
                    os.close(fd)
                except OSError:
                    pass
                if isinstance(pre_commit_err, InvestigationPersistenceError):
                    raise
                raise InvestigationPersistenceError(
                    f"Pre-commit operations failed for '{self.investigation_id}': {pre_commit_err}",
                    outcome=DurableCommitOutcome.NOT_COMMITTED,
                    cause=pre_commit_err,
                ) from pre_commit_err

            # 2. Durable Commit Point: Atomic rename
            try:
                os.replace(tmp_path, target_path)
            except Exception as replace_err:
                raise InvestigationPersistenceError(
                    f"Atomic replacement failed for {target_path}: {replace_err}",
                    outcome=DurableCommitOutcome.NOT_COMMITTED,
                    cause=replace_err,
                ) from replace_err

            # Once replaced, the state is committed on disk
            outcome = DurableCommitOutcome.COMMITTED

            # 3. Post-replacement parent directory fsync
            try:
                dir_flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    dir_flags |= os.O_DIRECTORY
                dir_fd = os.open(self._investigations_dir, dir_flags)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except Exception as dir_err:
                outcome = DurableCommitOutcome.COMMIT_UNKNOWN
                raise InvestigationPersistenceError(
                    f"Parent directory fsync failed after replacement: {dir_err}",
                    outcome=DurableCommitOutcome.COMMIT_UNKNOWN,
                    cause=dir_err,
                ) from dir_err

            return DurableCommitOutcome.COMMITTED
        except InvestigationPersistenceError:
            if "tmp_path" in locals() and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise
        except Exception as e:
            if "tmp_path" in locals() and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise InvestigationPersistenceError(
                f"Authoritative persistence failure for investigation '{self.investigation_id}': {e}",
                outcome=outcome,
                cause=e,
            ) from e

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

    def run_to_completion(self, max_steps: Optional[int] = None) -> DiagnosticConclusion:
        """Runs the investigation state machine iteratively until a terminal state is reached.

        ``max_steps``: an explicit number is a hard cap (the run ends INCONCLUSIVE / STEP_BUDGET_REACHED when it is
        hit).  None (the default) sizes the cap from the plan, so a plan is never cut short by a constant chosen
        when there were fewer baseline recipes.
        """
        steps_executed = 0

        def limit() -> int:
            if max_steps is not None:
                return int(max_steps)
            # Auto: the guard against a state machine that never terminates.  The plan grows with every registered
            # baseline recipe (recipe_plugins); allow its steps plus a margin for classify / assess / plan /
            # replan / conclude.
            planned = int(getattr(self.plan, "total_steps", 0) or 0) if self.plan is not None else 0
            return max(DEFAULT_MIN_STEP_CAP, planned + STEP_MARGIN_BEYOND_PLAN)

        while self.state not in TERMINAL_STATES and steps_executed < limit():
            if self.is_paused:
                break
            self.step()
            steps_executed += 1

        if self.state not in TERMINAL_STATES and steps_executed >= limit():
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
        self.classification_result = self.classifier.classify(self.raw_problem_statement, self.symptom_fields)
        if self.target_expressions:
            for exp in self.target_expressions:
                if exp not in self.classification_result.extracted_entities.setdefault("variables", []):
                    self.classification_result.extracted_entities["variables"].append(exp)
                if exp not in self.classification_result.extracted_entities.setdefault("pointers", []):
                    self.classification_result.extracted_entities["pointers"].append(exp)
        # Generate initial competing hypotheses bound to session ledger and target identity
        self.competing_hypotheses = CompetingHypothesisManager.generate_competing_hypotheses_for_symptom(
            self.classification_result.primary_category,
            {
                "pid": self.pid,
                "target_pid": self.pid,
                "investigation_id": self.investigation_id,
                "ledger": self.ledger,
                "entities": self.classification_result.extracted_entities,
            },
        )
        self._record_timeline_event("PROBLEM_CLASSIFIED", {
            "primary_category": self.classification_result.primary_category,
            "confidence": self.classification_result.confidence,
            "is_vague": self.classification_result.is_vague,
            "symptom_class": self.classification_result.symptom_class,
            "understood": self.classification_result.understood,
            "confidence_level": self.classification_result.confidence_level,
            "extracted_entities": self.classification_result.extracted_entities,
            "competing_hypotheses_count": len(self.competing_hypotheses),
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

        if self.target_assessment and self.target_assessment.allocator_inspector:
            self.allocator_inspector = self.target_assessment.allocator_inspector

        # Select first-class diagnostic methodology
        self.methodology = MethodologySelector.select_methodology(
            category=self.classification_result.primary_category if self.classification_result else "UNKNOWN",
            problem_statement=self.raw_problem_statement,
            target_capabilities=self.target_assessment.capabilities if self.target_assessment else [],
            context={"pid": self.pid, "companion_elf": self.companion_elf},
        )

        self.state = STATE_PLANNING
        return {"action": "ASSESS", "state": self.state, "capabilities": self.target_assessment.capabilities}

    def _step_plan(self) -> Dict[str, Any]:
        if not self.classification_result or not self.target_assessment:
            self.state = STATE_FAILED
            return {"action": "PLAN", "state": self.state, "error": "Missing prerequisites for planning"}

        if self.target_recipe:
            r_meta = self.recipe_registry.get_recipe(self.target_recipe)
            if r_meta:
                primary_step = InvestigationStep(
                    step_id=f"step_{r_meta.recipe_id.lower()}_01",
                    recipe_id=r_meta.recipe_id,
                    recipe_name=r_meta.name,
                    category=r_meta.problem_category,
                    domain=r_meta.domain,
                    rationale=f"Targeted execution of diagnostic recipe {r_meta.name}",
                    priority=1,
                    cost_score=0.9,
                    safety_score=1.0,
                    expected_info_gain=0.9,
                    multi_factor_score=0.95,
                )
                self.plan = InvestigationPlan(
                    steps=[primary_step],
                    total_steps=1,
                    current_step_index=0,
                    plan_rationale=f"Targeted execution of diagnostic recipe {r_meta.recipe_id}",
                )

        if not self.plan:
            self.plan = self.planner.create_plan(
                classification=self.classification_result,
                target_assessment=self.target_assessment,
            )

        # Incorporate Expert Overrides into plan (Case P)
        if self.expert_overrides:
            for ov in reversed(self.expert_overrides):
                ov_vars = getattr(ov, "related_variables", []) or ([getattr(ov, "variable_expression")] if getattr(ov, "variable_expression", None) else [])
                ov_recipe = "RECIPE_INCONSISTENT_RELATED_VARIABLES" if len(ov_vars) >= 2 else "RECIPE_UNEXPECTED_VARIABLE_CHANGES"
                r_meta = self.recipe_registry.get_recipe(ov_recipe)
                if r_meta:
                    override_step = InvestigationStep(
                        step_id=f"step_expert_{len(self.plan.steps)+1:02d}",
                        recipe_id=ov_recipe,
                        recipe_name=f"[Expert Override] {r_meta.name}",
                        category=getattr(ov, "problem_category", None) or r_meta.problem_category,
                        domain=r_meta.domain,
                        rationale=f"Expert override prioritization: targeting {ov_vars}",
                        priority=1,
                        cost_score=0.95,
                        safety_score=1.0,
                        expected_info_gain=0.85,
                        multi_factor_score=0.80,
                    )
                    self.plan.steps.insert(0, override_step)
            self.plan.total_steps = len(self.plan.steps)

        self._record_timeline_event("PLAN_GENERATED", {
            "total_steps": self.plan.total_steps,
            "rationale": self.plan.plan_rationale,
            "has_expert_overrides": bool(self.expert_overrides),
        })
        self.state = STATE_COLLECTING
        return {"action": "PLAN", "state": self.state, "plan": self.plan.to_dict()}

    def _step_start_collection(self) -> Dict[str, Any]:
        return self._step_collect_next()

    def _record_authoritative_evidence_in_ledger(
        self,
        ev_id: str,
        recipe_id: str,
        observation_text: str,
        prov_class: str,
        enriched_ev: Dict[str, Any],
    ) -> str:
        """Records an authoritative or unverified EvidenceRecord into self.ledger via canonical EvidenceAdapter."""
        try:
            eff_pid = int(self.pid) if (self.pid is not None and self.pid > 0) else None
            t_ident: Dict[str, Any] = {}
            if eff_pid:
                t_ident["pid"] = eff_pid

            # Preserve real process_identity without fabrication
            proc_id = (
                getattr(self.target_assessment, "process_identity", None)
                or enriched_ev.get("process_identity")
                or (enriched_ev.get("target_identity") or {}).get("process_identity")
                or (self.adapter.get_process_identity(eff_pid).get("process_identity") if eff_pid else None)
            )
            if proc_id:
                t_ident["process_identity"] = proc_id

            # Preserve real executable_identity without fabrication
            exe_id = (
                getattr(self.target_assessment, "executable_identity", None)
                or enriched_ev.get("executable_identity")
                or (enriched_ev.get("target_identity") or {}).get("executable_identity")
                or self.companion_elf
                or (self.adapter.get_process_identity(eff_pid).get("executable_identity") if eff_pid else None)
            )
            if exe_id:
                t_ident["executable_identity"] = exe_id

            # Preserve real build_id without fabrication (never fabricate fallback)
            bid = (
                getattr(self.target_assessment, "build_id", None)
                or enriched_ev.get("build_id")
                or (enriched_ev.get("target_identity") or {}).get("build_id")
                or (self.adapter.get_process_identity(eff_pid).get("build_id") if eff_pid else None)
            )
            if bid:
                t_ident["build_id"] = bid

            # Strict trust boundary:
            # LiveCaptureReceipt must originate authentically from trusted capture backend.
            # Never manufacture receipts in this recording method.
            rcpt_raw = (
                enriched_ev.get("live_capture_receipt")
                or (enriched_ev.get("provenance") or {}).get("live_capture_receipt")
            )
            if prov_class == "LIVE_RUNTIME_CAPTURE":
                if rcpt_raw is None:
                    # Missing receipt: fail-closed downgrade to untrusted
                    prov_class = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
                else:
                    from .capture_backend import LiveCaptureReceipt
                    try:
                        rcpt_obj = rcpt_raw if isinstance(rcpt_raw, LiveCaptureReceipt) else LiveCaptureReceipt.from_dict(rcpt_raw)
                        # Reject if target identity is incomplete
                        if eff_pid is None or not t_ident.get("process_identity") or not t_ident.get("executable_identity"):
                            prov_class = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
                            rcpt_raw = None
                        else:
                            ok, reason = rcpt_obj.verify(
                                expected_session_id=self.ledger.session_id,
                                expected_pid=eff_pid,
                                expected_process_identity=t_ident.get("process_identity"),
                                expected_executable_identity=t_ident.get("executable_identity"),
                                expected_build_id=t_ident.get("build_id"),
                                require_production_authority=True,
                            )
                            if not ok:
                                prov_class = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
                                rcpt_raw = None
                    except Exception:
                        prov_class = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
                        rcpt_raw = None

            tool_result = dict(enriched_ev)
            tool_result["evidence_id"] = ev_id
            if "finding" not in tool_result or not tool_result["finding"]:
                tool_result["finding"] = observation_text
            tool_result["recipe_id"] = recipe_id
            tool_result["provenance_class"] = prov_class
            if rcpt_raw is not None and prov_class == "LIVE_RUNTIME_CAPTURE":
                tool_result["live_capture_receipt"] = rcpt_raw.to_dict() if hasattr(rcpt_raw, "to_dict") else rcpt_raw
            else:
                tool_result.pop("live_capture_receipt", None)
                if "provenance" in tool_result and isinstance(tool_result["provenance"], dict):
                    tool_result["provenance"].pop("live_capture_receipt", None)

            # Preserve nature: Never turn an inference or hypothesis into an observation fact
            eff_nature = enriched_ev.get("nature")
            if not eff_nature:
                fc = str(enriched_ev.get("finding_classification") or "").upper()
                if fc in ("INFERENCE", "DERIVED") or enriched_ev.get("is_inference"):
                    eff_nature = NATURE_INFERENCE
                elif fc in ("HYPOTHESIS", "SPECULATION") or enriched_ev.get("is_hypothesis"):
                    eff_nature = NATURE_HYPOTHESIS
                else:
                    eff_nature = NATURE_OBSERVATION

            # Canonical adaptation through EvidenceAdapter
            rec_obj = self.evidence_adapter.adapt_generic_tool_output(
                tool_name=recipe_id,
                tool_result=tool_result,
                evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
                nature=eff_nature,
                target_identity=t_ident,
                session_id=self.ledger.session_id,
                ledger=self.ledger,
                epoch=getattr(self.plan, "current_step_index", 0) if self.plan else 0,
                evidence_id=ev_id,
                observation=observation_text,
            )

            # Canonical registration into EvidenceLedger via EvidenceAdapter (fail-closed, no private collection mutation)
            added = self.evidence_adapter.record_into_ledger(rec_obj, self.ledger, raise_on_error=True)
            if not added:
                sem_dig = (rec_obj.details or {}).get("semantic_digest")
                dup = self.ledger.find_by_semantic_digest(sem_dig) if sem_dig else None
                if dup is None and self.ledger.has(ev_id):
                    dup = self.ledger.get_record(ev_id)
                if dup is not None:
                    return f"DUPLICATE: {dup.evidence_id}"
                return "FAILED: Record was not admitted by ledger"

            return "RECORDED"
        except Exception as le:
            return f"FAILED: {type(le).__name__}: {le}"

    def _halt_on_budget(self) -> str:
        """End the collection because the observation budget ran out.

        What the checks that DID run found is kept: when one of them supported a problem, the hypotheses are formed
        from the evidence already collected (``_step_analyze`` groups that evidence; it reads nothing from the
        target) before the conclusion is sealed.  Otherwise a check that had already found the problem (e.g. lock
        contention, a spinning thread) was dropped whenever a loaded host made the run slower than the budget, and
        the verdict said "no problem finding was produced".  The findings stay probable (the verify / narrow steps
        that could confirm them did not run) and the run is still never HEALTHY: budget_exhausted blocks it."""
        self.state = STATE_BUDGET_EXHAUSTED
        reason = self.budget_tracker.exhaustion_reason or "Observation resource budget exhausted."
        if any(isinstance(e, dict) and e.get("status") == "SUPPORTED" for e in self.collected_evidence):
            try:
                self._step_analyze()
            except Exception as exc:  # noqa: BLE001 - never let the synthesis hide the budget stop
                self._record_timeline_event("ANALYZE_AFTER_BUDGET_FAILED", {"error": f"{type(exc).__name__}: {exc}"})
            self.state = STATE_BUDGET_EXHAUSTED
        self._finalize_conclusion(
            stop_reason="BUDGET_EXHAUSTED",
            summary=f"Investigation halted: {reason}",
        )
        return reason

    def _step_collect_next(self) -> Dict[str, Any]:
        if self.budget_tracker and not self.budget_tracker.can_continue():
            reason = self._halt_on_budget()
            return {"action": "BUDGET_EXHAUSTED", "state": self.state, "reason": reason}

        if not self.plan:
            self.state = STATE_ANALYZING
            return {"action": "COLLECT_COMPLETE", "state": self.state}

        # Skip any steps marked SKIPPED or already executed in this session (Part D: avoid repeating identical checks)
        already_exec_recipes = {c.recipe_id for c in self.checks}
        while self.plan.current_step_index < len(self.plan.steps):
            cand_step = self.plan.steps[self.plan.current_step_index]
            if cand_step.status == "SKIPPED":
                self.plan.current_step_index += 1
                continue
            if cand_step.recipe_id in already_exec_recipes and not cand_step.step_id.startswith("step_override"):
                cand_step.status = "SKIPPED"
                self.plan.current_step_index += 1
                continue
            break

        if self.budget_tracker and not self.budget_tracker.can_continue():
            self._halt_on_budget()
            return {"action": "BUDGET_EXHAUSTED", "state": self.state}

        if self.plan.current_step_index >= len(self.plan.steps):
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

        # Track first-class DiagnosticCheck
        check_id = f"CHK_{step.recipe_id}_{len(self.checks) + 1:03d}"
        diagnostic_check = DiagnosticCheck(
            check_id=check_id,
            methodology_id=self.methodology.methodology_id if self.methodology else "METH_GENERAL",
            recipe_id=recipe.recipe_id,
            recipe_version=getattr(recipe, "version", "2.1.0"),
            name=recipe.name,
            description=recipe.name,
            technical_rationale=recipe.domain,
            preconditions=list(getattr(recipe, "required_prerequisites", [])),
            applicability_criteria={"required_capabilities": list(getattr(recipe, "applicable_target_capabilities", []))},
            decision_criteria=dict(getattr(recipe, "thresholds_and_conditions", {})),
            expected_evidence=list(getattr(recipe, "required_evidence", [])),
            inspected_entity=f"Target PID {self.pid} ({recipe.domain})",
        )
        diagnostic_check.start()

        # Record real temporal memory sample for session persistence (Section 4)
        if self.pid and self.pid > 0:
            try:
                p_st = self.adapter.get_process_status(self.pid)
                sample_rss = int(p_st.get("VmRSS", 0)) if "VmRSS" in p_st else None
                sample_vsz = int(p_st.get("VmSize", 0)) if "VmSize" in p_st else None
                step_idx = self.plan.current_step_index if self.plan else 0
                existing_step_sample = next((s for s in self.temporal_memory_samples if s.get("step_index") == step_idx), None)
                if existing_step_sample is None:
                    self.temporal_memory_samples.append({
                        "monotonic_ns": time.monotonic_ns(),
                        "timestamp": time.time(),
                        "rss_kb": sample_rss,
                        "vsize_kb": sample_vsz,
                        "step_index": step_idx,
                        "recipe_id": recipe.recipe_id,
                    })
            except Exception:
                pass

        # Open transaction on self.adapter for live process if supported
        step_tx = None
        if self.pid and self.pid > 0 and hasattr(self.adapter, "begin_capture_transaction"):
            try:
                step_tx = self.adapter.begin_capture_transaction(
                    session_id=self.ledger.session_id,
                    pid=int(self.pid),
                    operation_type="diagnostic",
                    snapshot_binding=f"snap_{self.investigation_id}_{step.step_id}",
                )
            except Exception:
                step_tx = None

        # Perform actual live runtime evidence acquisition via RuntimeEvidenceProvider
        _t0_collect = time.monotonic()
        try:
            cur_epoch = (self.plan.current_step_index + 1) if self.plan else 1
            obs_data, ev_records = self.evidence_provider.collect_for_recipe(
                recipe=recipe,
                pid=self.pid,
                companion_elf=self.companion_elf,
                target_assessment=self.target_assessment,
                classification=self.classification_result,
                session_id=self.investigation_id,
                epoch_id=cur_epoch,
            )
        finally:
            step_rcpt = None
            if step_tx is not None:
                try:
                    committed_tx = self.adapter.commit_capture_transaction(step_tx)
                    if committed_tx.physical_bytes_read > 0:
                        bid = getattr(self.target_assessment, "build_id", None)
                        step_rcpt = self.adapter.issue_live_receipt_for_session(
                            session_id=self.ledger.session_id,
                            pid=int(self.pid),
                            snapshot_binding=committed_tx.snapshot_binding,
                            companion_build_id=bid,
                            transaction=committed_tx,
                        )
                except Exception as tx_err:
                    try:
                        self.adapter.rollback_capture_transaction(step_tx, str(tx_err))
                    except Exception:
                        pass
                    step_rcpt = None

        _collect_dur_sec = round(max(0.0001, time.monotonic() - _t0_collect), 6)
        for _er in ev_records:
            if isinstance(_er.raw_details, dict) and "duration_sec" not in _er.raw_details:
                _er.raw_details["duration_sec"] = _collect_dur_sec
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
            "allocator_inspector": self.allocator_inspector,
            "allocator": self.allocator_inspector,
            "structural_discovery": self.structural_discovery,
            "invariant_evaluator": self.invariant_evaluator,
            "concurrency_graph": self.concurrency_graph,
            "wait_for_graph": self.concurrency_graph,
            "observation_window": self.observation_window,
            "window": self.observation_window,
            **self.recipe_thresholds,
            **obs_data,
        }

        # Deterministic recipe evaluation against real acquired observations
        eval_result = self.recipe_registry.evaluate_recipe(recipe, eval_context)
        # The evaluated rules are done with live objects; what is recorded in checks / reports must be plain data
        # (an object repr carries a memory address and differs between a session and its reloaded copy).
        for _k, _v in list(obs_data.items()):
            if isinstance(_v, ObservationWindow):
                obs_data[_k] = {"observation_window_samples": _v.sample_count()}
        consumed_step_ev_ids: List[str] = []

        eff_step_prov = PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE if step_rcpt is not None else (
            PROVENANCE_CLASS_IMPORTED_UNVERIFIED if self.pid else PROVENANCE_CLASS_SYNTHETIC_FIXTURE
        )
        rcpt_dict_payload = step_rcpt.to_dict() if step_rcpt is not None else None

        # Enrich and correlate evidence records (Section 7: 1:1 finding-to-evidence relationship)
        for i, fact in enumerate(eval_result.supporting_facts):
            obs_actual_val = obs_data.get("observed_value") if obs_data.get("observed_value") is not None else (
                obs_data.get("value") if obs_data.get("value") is not None else (
                    obs_data.get("current_rss_kb") if obs_data.get("current_rss_kb") is not None else (
                        obs_data.get("pointer_value") if obs_data.get("pointer_value") is not None else obs_data
                    )
                )
            )

            if i < len(ev_records):
                matching_rec = ev_records[i]
                ev_id = matching_rec.evidence_id
                prov_class = eff_step_prov
            else:
                ev_id = f"ev_{uuid.uuid4().hex[:12]}"
                prov_class = eff_step_prov
                matching_rec = RuntimeEvidenceRecord(
                    evidence_id=ev_id,
                    collection_method=recipe.recipe_id,
                    target_pid=self.pid,
                    observed_value=obs_actual_val,
                    raw_observation=obs_data,
                    normalized_observation=obs_actual_val,
                    provenance_class=prov_class,
                )
                self.collected_evidence_records.append(matching_rec)

            consumed_step_ev_ids.append(ev_id)
            ev_payload = {
                "evidence_id": ev_id,
                # The observed rule decides the category (e.g. a runaway thread is PROCESS_INSTABILITY, not a
                # deadlock); recipes that do not say fall back to their primary category.
                "problem_category": eval_result.details.get("finding_category") or recipe.problem_category,
                "recipe_id": recipe.recipe_id,
                "domain": recipe.domain,
                "finding": fact,
                "finding_classification": "OBSERVED_FACT",
                "status": "SUPPORTED",
                "details": eval_result.details,
                "address": obs_data.get("address") or obs_data.get("faulting_address"),
                "symbol": obs_data.get("pointer_name") or obs_data.get("variable_name"),
                "observed_value": obs_actual_val,
                "raw_observation": obs_data,
                "normalized_observation": obs_actual_val,
                "provenance_class": prov_class,
                **({"live_capture_receipt": rcpt_dict_payload} if rcpt_dict_payload else {}),
            }
            correlated = self.correlator.correlate(ev_payload, target_pid=self.pid)
            enriched_ev = {**ev_payload, "correlation": correlated, "step_id": step.step_id}

            ledger_status = self._record_authoritative_evidence_in_ledger(
                ev_id=ev_id,
                recipe_id=recipe.recipe_id,
                observation_text=str(fact),
                prov_class=prov_class,
                enriched_ev=enriched_ev,
            )
            enriched_ev["ledger_status"] = ledger_status
            self.collected_evidence.append(enriched_ev)

        for j, fact in enumerate(eval_result.contradicting_facts):
            contra_ev_id = f"ev_contra_{uuid.uuid4().hex[:10]}"
            consumed_step_ev_ids.append(contra_ev_id)
            obs_contra_val = obs_data.get("observed_value") if obs_data.get("observed_value") is not None else (
                obs_data.get("value") if obs_data.get("value") is not None else None
            )
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
                "observed_value": obs_contra_val,
                "raw_observation": obs_data,
                "normalized_observation": obs_contra_val,
                "provenance_class": eff_step_prov,
                **({"live_capture_receipt": rcpt_dict_payload} if rcpt_dict_payload else {}),
            }
            correlated = self.correlator.correlate(ev_payload, target_pid=self.pid)
            enriched_ev = {**ev_payload, "correlation": correlated, "step_id": step.step_id}
            enriched_ev["ledger_status"] = self._record_authoritative_evidence_in_ledger(
                ev_id=contra_ev_id,
                recipe_id=recipe.recipe_id,
                observation_text=str(fact),
                prov_class=enriched_ev["provenance_class"],
                enriched_ev=enriched_ev,
            )
            self.collected_evidence.append(enriched_ev)

        if not eval_result.supporting_facts and not eval_result.contradicting_facts:
            base_ev_id = f"ev_obs_{uuid.uuid4().hex[:10]}"
            consumed_step_ev_ids.append(base_ev_id)
            obs_base_val = obs_data.get("observed_value") if obs_data.get("observed_value") is not None else (
                obs_data.get("value") if obs_data.get("value") is not None else (
                    obs_data.get("current_rss_kb") if obs_data.get("current_rss_kb") is not None else obs_data
                )
            )
            ev_payload = {
                "evidence_id": base_ev_id,
                "problem_category": recipe.problem_category,
                "recipe_id": recipe.recipe_id,
                "domain": recipe.domain,
                "finding_classification": "OBSERVED_FACT",
                "status": eval_result.status,
                "details": eval_result.details,
                "observed_value": obs_base_val,
                "raw_observation": obs_data,
                "normalized_observation": obs_base_val,
                "provenance_class": eff_step_prov,
                **({"live_capture_receipt": rcpt_dict_payload} if rcpt_dict_payload else {}),
            }
            correlated = self.correlator.correlate(ev_payload, target_pid=self.pid)
            enriched_ev = {**ev_payload, "correlation": correlated, "step_id": step.step_id}
            enriched_ev["ledger_status"] = self._record_authoritative_evidence_in_ledger(
                ev_id=base_ev_id,
                recipe_id=recipe.recipe_id,
                observation_text=f"{recipe.recipe_id}:{eval_result.status}",
                prov_class=enriched_ev["provenance_class"],
                enriched_ev=enriched_ev,
            )
            self.collected_evidence.append(enriched_ev)

        # Record in ObservationWindow
        if self.pid and self.pid > 0:
            now_mono = time.monotonic()
            now_wall = time.time()
            sample_rss_val = int(p_st.get("VmRSS", 0)) if "p_st" in locals() else (obs_data.get("current_rss_kb") or 0)
            sample_vsz_val = int(p_st.get("VmSize", 0)) if "p_st" in locals() else 0
            sample = MemorySample(
                epoch_id=self.observation_window.sample_count(),
                monotonic_timestamp=now_mono,
                rss_kb=sample_rss_val,
                wall_clock_timestamp=now_wall,
                timestamp=now_mono,
                vsize_kb=sample_vsz_val,
                heap_vma_kb=obs_data.get("heap_kb"),
                container_sizes={obs_data.get("container_name"): obs_data.get("active_chunk_count")} if obs_data.get("container_name") else {},
                alloc_counter=obs_data.get("alloc_count"),
                free_counter=obs_data.get("free_count"),
            )
            self.observation_window.record_sample(sample)

        # Update competing hypotheses with observed facts and authoritative ledger context
        primary_ev_id = consumed_step_ev_ids[0] if consumed_step_ev_ids else None
        _ch_ctx = {"ledger": self.ledger, "investigation_id": self.investigation_id, "target_pid": self.pid}
        for ch in self.competing_hypotheses:
            ch.ledger = self.ledger
            if recipe.recipe_id in ch.applicable_diagnostic_rules or recipe.problem_category == ch.category:
                for fact in eval_result.supporting_facts:
                    ch.add_supporting_observation(fact, evidence_id=primary_ev_id, target_context=_ch_ctx)
                for fact in eval_result.contradicting_facts:
                    ch.add_contradicting_observation(fact, evidence_id=primary_ev_id, target_context=_ch_ctx)

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
        # Determine explicit CheckStatus (IMP-001: only count verified clean PASS checks)
        if eval_result.status == RECIPE_STATUS_SUPPORTED:
            chk_status = CheckStatus.FAIL  # Problem invariant was violated / fault observed
        elif eval_result.status == RECIPE_STATUS_CONTRADICTED:
            chk_status = CheckStatus.PASS  # Invariant satisfied / clean
            self.verified_checks_count += 1
        elif eval_result.status == RECIPE_STATUS_NOT_APPLICABLE:
            chk_status = CheckStatus.NOT_APPLICABLE
        else:
            chk_status = CheckStatus.INCONCLUSIVE

        supp_ids = [e["evidence_id"] for e in self.collected_evidence if e.get("step_id") == step.step_id and e.get("status") == "SUPPORTED"]
        contra_ids = [e["evidence_id"] for e in self.collected_evidence if e.get("step_id") == step.step_id and e.get("status") == "CONTRADICTED"]

        diagnostic_check.complete(
            status=chk_status,
            actual_observations=obs_data,
            technical_interpretation="; ".join(str(f) for f in (eval_result.supporting_facts or eval_result.contradicting_facts or []) if f is not None) or eval_result.details.get("reason", "Check executed"),
            supporting_evidence_ids=supp_ids,
            contradicting_evidence_ids=contra_ids,
            limitations=eval_result.details.get("limitations", []),
            missing_evidence=eval_result.details.get("missing_evidence", []),
        )
        self.checks.append(diagnostic_check)
        if self.methodology:
            self.methodology.add_check(diagnostic_check)

        self._record_timeline_event("STEP_EXECUTED", {
            "step_id": step.step_id,
            "recipe_id": step.recipe_id,
            "eval_status": eval_result.status,
            "confidence": eval_result.confidence,
            "consumed_evidence_ids": consumed_step_ev_ids,
        })

        # ---------------------------------------------------------------------
        # Adaptive Feedback Loop & Dynamic Replanning (Section 10 & Case O)
        # ---------------------------------------------------------------------
        remaining_steps = self.plan.steps[self.plan.current_step_index + 1:]
        if eval_result.status == RECIPE_STATUS_SUPPORTED:
            # If RSS growth was observed, dynamically schedule heap growth and object accumulation
            dynamic_followups: List[InvestigationStep] = []
            if "MEMORY_GROWTH" in recipe.recipe_id or "GROWTH" in recipe.recipe_id:
                followup_ids = ["RECIPE_HEAP_GROWTH", "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION"]
                for fid in reversed(followup_ids):
                    if (
                        fid != recipe.recipe_id
                        and not any(s.recipe_id == fid for s in self.plan.steps)
                        and not any(s.recipe_id == fid for s in remaining_steps)
                    ):
                        f_rec = self.recipe_registry.get_recipe(fid)
                        if f_rec:
                            new_step = self.planner.score_and_build_step(
                                recipe=f_rec,
                                rel_weight=0.95,
                                step_id=f"step_{len(self.plan.steps) + len(remaining_steps) + 1:02d}",
                                priority=self.plan.current_step_index + 2,
                                target_assessment=self.target_assessment,
                                rationale_override=f"Dynamic follow-up: isolated from confirmed {recipe.recipe_id}",
                            )
                            remaining_steps.insert(0, new_step)
                            dynamic_followups.append(new_step)

            # Prioritize relevant follow-up steps for this category
            related_steps = [s for s in remaining_steps if s.category == recipe.problem_category]
            unrelated_steps = [s for s in remaining_steps if s.category != recipe.problem_category]
            self.plan.steps = self.plan.steps[:self.plan.current_step_index + 1] + related_steps + unrelated_steps
            self.plan.total_steps = len(self.plan.steps)

            # Early stop condition: if definitive fault confirmed with high confidence (>= 0.90) and no contradiction
            if eval_result.confidence >= 0.90 and not eval_result.contradicting_facts:
                for s in remaining_steps:
                    # Baseline checks are never skipped: a process can have two problems and the report must be
                    # able to say the other cheap checks were clean (or not).
                    if s.category != recipe.problem_category and s.recipe_id not in BASELINE_RECIPE_IDS:
                        s.status = "SKIPPED"
                # IMP-004: dynamically scheduled growth follow-ups must still execute; otherwise keep the
                # original early stop.  Baseline checks that have not run yet also keep the loop going.
                # (IMP-008: also the follow-ups scheduled by an EARLIER growth step - a supported first follow-up
                # must not cut off the second one.)
                if (not any(s.status == "PENDING" for s in dynamic_followups)
                        and not any(s.status == "PENDING" and str(s.rationale or "").startswith("Dynamic follow-up")
                                    for s in remaining_steps)
                        and not any(s.status == "PENDING" and s.recipe_id in BASELINE_RECIPE_IDS
                                    for s in remaining_steps)):
                    if self.budget_tracker and obs_data.get("bytes_read"):
                        # IMP-009: the bytes this step measured count even when it ends the investigation early
                        self.budget_tracker.record_read(bytes_read=int(obs_data["bytes_read"]), stop_ms=0.0,
                                                        profile_id=step.recipe_id)
                    self.state = STATE_ANALYZING
                    self.plan.current_step_index += 1
                    return {"action": "COLLECT_STEP", "step_id": step.step_id, "eval_result": asdict(eval_result), "adaptive_action": "EARLY_ANOMALY_CONFIRMED"}

        elif eval_result.status == RECIPE_STATUS_CONTRADICTED:
            # Case O: Contradictory evidence introduced: update competing hypotheses via authoritative boundary
            for ch in self.competing_hypotheses:
                if recipe.recipe_id in ch.applicable_diagnostic_rules:
                    ch.add_contradicting_observation(
                        f"{recipe.recipe_id}: contradicted by runtime observation",
                        evidence_id=primary_ev_id,
                        target_context=_ch_ctx,
                    )

            # Re-rank competing hypotheses to find next discriminating recipe
            comp_res = CompetingHypothesisManager.compare(self.competing_hypotheses)
            # IMP-017: the discriminating-observation selector (ported from the retired adaptive engine) picks
            # the cheapest budget-feasible recipe whose declared observations test the most unresolved
            # hypotheses; the comparison's own recommendation is the fallback.
            from .observation_selector import select_discriminating_recipe
            _cand_ids = sorted({r for ch in self.competing_hypotheses for r in (ch.applicable_diagnostic_rules or [])})
            _cands = [rc for rc in (self.recipe_registry.get_plannable_recipe(r) for r in _cand_ids) if rc is not None]
            _done = {s.recipe_id for s in self.plan.steps[:self.plan.current_step_index + 1]}
            sel_rid, sel_log, sel_why = select_discriminating_recipe(
                self.competing_hypotheses, _cands, budget_tracker=self.budget_tracker, executed_recipe_ids=_done)
            self.observation_selection_log.append({"after_recipe": recipe.recipe_id, "selected": sel_rid,
                                                   "fallback": comp_res.recommended_discriminating_recipe,
                                                   "rationale": sel_why, "candidates": sel_log})
            if sel_rid:
                comp_res.recommended_discriminating_recipe = sel_rid
                comp_res.discrimination_rationale = sel_why
            if comp_res.recommended_discriminating_recipe:
                next_rec_id = comp_res.recommended_discriminating_recipe
                already_executed = any(s.recipe_id == next_rec_id for s in self.plan.steps[:self.plan.current_step_index + 1])
                already_in = any(s.recipe_id == next_rec_id for s in remaining_steps)
                if not already_executed and not already_in:
                    f_rec = self.recipe_registry.get_plannable_recipe(next_rec_id)
                    if f_rec:
                        discrim_step = self.planner.score_and_build_step(
                            recipe=f_rec,
                            rel_weight=0.90,
                            step_id=f"step_discrim_{len(self.plan.steps)+1:02d}",
                            priority=1,
                            target_assessment=self.target_assessment,
                            rationale_override=f"Information-gain discriminating step: {comp_res.discrimination_rationale}",
                        )
                        remaining_steps.insert(0, discrim_step)
                        self.plan.steps = self.plan.steps[:self.plan.current_step_index + 1] + remaining_steps
                        self.plan.total_steps = len(self.plan.steps)
                elif already_in:
                    target_s = next(s for s in remaining_steps if s.recipe_id == next_rec_id)
                    remaining_steps.remove(target_s)
                    target_s.priority = 1
                    target_s.step_id = f"step_discrim_{target_s.step_id}"
                    target_s.rationale = f"Information-gain discriminating step prioritized: {comp_res.discrimination_rationale}"
                    remaining_steps.insert(0, target_s)
                    self.plan.steps = self.plan.steps[:self.plan.current_step_index + 1] + remaining_steps
            else:
                for s in remaining_steps:
                    if s.category == recipe.problem_category and s.recipe_id not in BASELINE_RECIPE_IDS:
                        s.status = "SKIPPED"

        # Deduct actual consumed resources into budget_tracker
        if self.budget_tracker:
            bytes_in_step = sum(
                len(_er.observed_value) if isinstance(_er.observed_value, (bytes, bytearray))
                else (len(str(_er.observed_value)) if _er.observed_value is not None else 0)
                for _er in ev_records
            )
            measured_bytes = int(obs_data.get("bytes_read") or obs_data.get("bytes_captured") or bytes_in_step)
            t_stop = float(obs_data.get("target_stop_ms", 0.0))
            self.budget_tracker.record_sample(profile_id=step.recipe_id)
            self.budget_tracker.record_read(
                bytes_read=measured_bytes,
                latency_us=float(_collect_dur_sec * 1_000_000.0),
                stop_ms=t_stop,
                is_failure=False,
                profile_id=step.recipe_id,
            )

        self.plan.current_step_index += 1

        if self.budget_tracker and not self.budget_tracker.can_continue():
            reason = self._halt_on_budget()
            return {"action": "BUDGET_EXHAUSTED", "step_id": step.step_id, "state": self.state, "reason": reason}

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

            # IMP-008: a rule may name what it observed (e.g. the growing owner path and rate) for the finding text
            summaries = list(dict.fromkeys(str(e.get("details", {}).get("finding_summary")) for e in supp_ev
                                           if e.get("details", {}).get("finding_summary")))
            hyp = ExpertHypothesis(
                hypothesis_id=f"HYP_{hyp_counter:02d}",
                problem_statement=f"Runtime anomaly in {cat}: observed {len(supp_ev)} corroborating indicators."
                                  + ("".join(" " + x for x in summaries[:2])),
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
        has_any_supp = any(bool(h.supporting_evidence) for h in self.active_hypotheses)
        if not any(h.status == "SUPPORTED" for h in self.active_hypotheses) and not has_any_supp:
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
        # IMP-009: stable heap metadata damage attributed to a named block (uncapped) is the memory-integrity proof;
        # the pointer / poison-word criteria (written for a single probed pointer) do not apply to it.
        heap_proof = next((e for e in hyp.supporting_evidence if e.get("status") == "SUPPORTED"
                           and e.get("details", {}).get("corruption_confirmed")
                           and e.get("details", {}).get("certainty_cap") != "PROBABLE"), None)
        for crit in criteria_list:
            cid = crit.get("criterion_id", "")
            outcome = "INCONCLUSIVE"
            rationale = "No observation evidence available to verify criterion."
            consumed_ids: List[str] = []
            missing_ev: List[str] = []

            if heap_proof is not None and cid in ("CRIT_POINTER_VALID_VMA", "CRIT_NO_POISON_PATTERN"):
                if cid == "CRIT_NO_POISON_PATTERN":
                    outcome = "FAIL"
                    consumed_ids.append(heap_proof.get("evidence_id", ""))
                    rationale = f"Stable heap metadata damage observed: {heap_proof.get('finding')}"
                else:
                    rationale = "Not applicable: the damage is proven by heap metadata, not by one probed pointer."
            # 1. Pointer & VMA check
            elif cid == "CRIT_POINTER_VALID_VMA":
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
            # Verification rule: CONFIRMED requires verified primary supporting observations with zero unrefuted counter-indicators
            has_primary_supp = bool(hyp.supporting_evidence and any(e.get("status") == "SUPPORTED" for e in hyp.supporting_evidence))
            has_unrefuted_contra = bool(hyp.contradicting_evidence and any(e.get("status") == "CONTRADICTED" for e in hyp.contradicting_evidence))

            # IMP-008: a rule can cap what its observation proves (e.g. unbounded growth of a still-referenced
            # container: the growth is measured, but leak vs intended accumulation is not decidable from memory)
            capped = [e for e in hyp.supporting_evidence if e.get("details", {}).get("certainty_cap") == "PROBABLE"]
            uncapped = [e for e in hyp.supporting_evidence if e.get("status") == "SUPPORTED"
                        and e.get("details", {}).get("certainty_cap") != "PROBABLE"
                        and (e.get("details", {}).get("leak_confirmed")
                             or e.get("details", {}).get("corruption_confirmed"))]
            if has_fail and has_primary_supp and not has_pass and capped and not uncapped:
                hyp.status = "LIKELY"
                hyp.confidence = min(max(hyp.confidence, 0.70), 0.85)
                hyp.confidence_basis = ("Observed fault criteria met, but the evidence caps the conclusion at probable: "
                                        + "; ".join(dict.fromkeys(str(e["details"].get("certainty_cap_reason", ""))
                                                                  for e in capped)))
            elif has_fail and has_primary_supp and not has_pass:
                hyp.status = "CONFIRMED"
                hyp.confidence = max(hyp.confidence, 0.92)
                hyp.confidence_basis = f"Executable criteria verified fault: {'; '.join(r['rationale'] for r in results if r['result'] == 'FAIL')}"
            elif has_fail and has_primary_supp and has_pass:
                hyp.status = "LIKELY"
                hyp.confidence = min(max(hyp.confidence, 0.70), 0.80)
                hyp.confidence_basis = "Fault criteria triggered, but conflicting counter-evidence exists. Not confirmed."
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
        elif self.active_hypotheses[0].status == "CONFIRMED":
            self.state = STATE_COMPLETED
            top_h = self.active_hypotheses[0]
            self._finalize_conclusion(
                stop_reason="HYPOTHESIS_CONFIRMED",
                summary=f"Strongest hypothesis confirmed: {top_h.problem_statement} with confidence {top_h.confidence:.2f}.",
                primary_finding=top_h.problem_statement,
                confidence=top_h.confidence,
                confidence_basis=top_h.confidence_basis,
            )
        elif self.active_hypotheses[0].confidence >= 0.70 or self.active_hypotheses[0].status == "LIKELY":
            self.state = STATE_COMPLETED
            top_h = self.active_hypotheses[0]
            self._finalize_conclusion(
                stop_reason="HYPOTHESIS_LIKELY",
                summary=f"Likely hypothesis identified: {top_h.problem_statement} with confidence {top_h.confidence:.2f}.",
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

    def _build_all_planned_and_executed_checks(self) -> List[DiagnosticCheck]:
        """Returns unified check list combining executed checks with SKIPPED and NOT_EXECUTED planned steps."""
        all_checks = list(self.checks)
        executed_recipe_ids = {c.recipe_id for c in all_checks}
        if self.plan:
            for s in self.plan.steps:
                if s.recipe_id not in executed_recipe_ids:
                    is_skipped = (s.status == "SKIPPED")
                    chk = DiagnosticCheck(
                        check_id=f"CHK_{s.recipe_id}_{'SKIPPED' if is_skipped else 'UNEXEC'}",
                        methodology_id=self.methodology.methodology_id if self.methodology else "METH_GENERAL",
                        recipe_id=s.recipe_id,
                        recipe_version="2.1.8",
                        name=s.recipe_name,
                        description=f"Planned check {s.recipe_name}",
                        technical_rationale=s.domain,
                        status=getattr(CheckStatus, "SKIPPED", CheckStatus.NOT_EXECUTED) if is_skipped else CheckStatus.NOT_EXECUTED,
                        inspected_entity=f"Target PID {self.pid} ({s.domain})",
                        technical_interpretation=(
                            "Check was skipped after earlier discriminating step resolved scope."
                            if is_skipped
                            else "Check was not executed before investigation concluded."
                        ),
                        is_required=not is_skipped,
                    )
                    all_checks.append(chk)
        return all_checks

    def _finalize_conclusion(
        self,
        stop_reason: str,
        summary: str,
        primary_finding: Optional[str] = None,
        confidence: float = 0.50,
        confidence_basis: str = "",
    ) -> DiagnosticConclusion:
        """Constructs and seals the final diagnostic conclusion using centralized verdict aggregation."""
        limitations: List[str] = []
        if self.target_assessment:
            limitations.extend(self.target_assessment.limitations)
        for rec in self.collected_evidence_records:
            if rec.collection_status == COLLECTION_STATUS_FAILED and rec.limitations:
                for lim in rec.limitations:
                    if lim not in limitations:
                        limitations.append(lim)

        all_checks = self._build_all_planned_and_executed_checks()
        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=self.state,
            stop_reason=stop_reason,
            checks=all_checks,
            active_hypotheses=self.active_hypotheses,
            rejected_hypotheses=self.rejected_hypotheses,
            limitations=limitations,
            target_assessment=self.target_assessment,
            evidence_records=self.collected_evidence_records,
        )

        remediations: List[str] = []
        if (
            agg.overall_result in (VERDICT_INCONCLUSIVE, VERDICT_ABORTED)
            or self.state in (STATE_INCONCLUSIVE, STATE_BLOCKED, STATE_FAILED, STATE_BUDGET_EXHAUSTED)
        ):
            remediations.append(
                "Investigation inconclusive due to insufficient evidence or collection failures; "
                "verify target permissions, debug symbols, and process accessibility before re-running."
            )
        elif primary_finding:
            pf_up = primary_finding.upper()
            if "INCONCLUSIVE" in pf_up:
                remediations.append(
                    "Investigation inconclusive due to insufficient evidence or collection failures; "
                    "verify target permissions, debug symbols, and process accessibility before re-running."
                )
            elif "MEMORY" in pf_up or "CORRUPT" in pf_up or "POINTER" in pf_up:
                remediations.append("Audit pointer dereference bounds and verify memory mapping permissions before dereference.")
                remediations.append("Enable AddressSanitizer (ASan) during build: `-fsanitize=address -g`.")
            elif "LEAK" in pf_up or "GROWTH" in pf_up or "IMBALANCE" in pf_up:
                remediations.append("Profile heap allocations and verify balanced free/delete calls across container lifecycles.")
                remediations.append("Inspect long-lived container capacities and unbounded cache queue limits.")
            elif "DEADLOCK" in pf_up or "LOCK" in pf_up:
                remediations.append("Enforce strict global lock acquisition ordering hierarchy across all threads.")
                remediations.append("Consider replacing nested mutexes with lock-free structures or fine-grained atomics.")
            elif "HEALTHY" in pf_up or "CLEAN" in pf_up or "NO ABNORMAL" in pf_up:
                remediations.append("No active remediation required: runtime state verified clean within investigated scope.")
            else:
                remediations.append("Review state transition logic and enforce assertions for valid enum state transitions.")
        elif agg.overall_result == VERDICT_HEALTHY:
            remediations.append("No active remediation required: runtime state verified clean within investigated scope.")
        else:
            remediations.append(
                "Diagnostic inspection did not confirm a specific fault; review collected evidence and limitations."
            )

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
            overall_verdict=agg.overall_result,
        )
        self._record_timeline_event("CONCLUSION_SEALED", {
            "status": self.state,
            "stop_reason": stop_reason,
            "confidence": confidence,
            "overall_verdict": agg.overall_result,
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
            "checks_count": len(self.checks),
            "methodology_id": self.methodology.methodology_id if self.methodology else None,
            "methodology_name": self.methodology.name if self.methodology else None,
            "next_recommended_action": next_action,
            "is_paused": self.is_paused,
            "created_at": self.timeline[0]["timestamp"] if self.timeline else "",
            "overall_verdict": self.conclusion.overall_verdict if self.conclusion else None,
            "budget": self.budget_tracker.to_dict() if self.budget_tracker else None,
        }

    def get_methodology(self) -> Dict[str, Any]:
        """Returns the structured diagnostic methodology."""
        return self.methodology.to_dict() if self.methodology else {}

    def get_checks(self) -> List[Dict[str, Any]]:
        """Returns the list of executed and evaluated diagnostic checks."""
        return [c.to_dict() for c in self.checks]

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
                    "supporting_evidence_ids": hyp.supporting_evidence_ids,
                    "contradicting_evidence_ids": hyp.contradicting_evidence_ids,
                    "missing_evidence": hyp.missing_evidence,
                    "verification_criteria": hyp.verification_criteria,
                    "verification_results": hyp.verification_execution_results,
                }
        for ch in self.competing_hypotheses:
            if ch.hypothesis_id == hypothesis_id:
                ch.evaluate_verdict(ledger=self.ledger)
                return {
                    "hypothesis_id": ch.hypothesis_id,
                    "problem_statement": ch.title or ch.confidence_basis,
                    "category": ch.category,
                    "confidence": ch.confidence,
                    "status": ch.status,
                    "supporting_evidence": ch.supporting_observations,
                    "contradicting_evidence": ch.contradicting_observations,
                    "supporting_evidence_ids": ch.supporting_evidence_ids,
                    "contradicting_evidence_ids": ch.contradicting_evidence_ids,
                    "missing_evidence": ch.missing_evidence,
                    "decision_trace": ch.decision_trace,
                }
        return {"error": f"Hypothesis '{hypothesis_id}' not found in investigation {self.investigation_id}"}

    def verify_hypothesis(self, hypothesis_id: str) -> Dict[str, Any]:
        """Executes deterministic verification for a specific hypothesis across active, rejected, and competing hypotheses."""
        if not self.active_hypotheses:
            self._step_analyze()
        for hyp in self.active_hypotheses + self.rejected_hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                res = self._execute_verification_for_hypothesis(hyp)
                res["supporting_evidence_ids"] = list(hyp.supporting_evidence_ids)
                res["contradicting_evidence_ids"] = list(hyp.contradicting_evidence_ids)
                res["missing_evidence"] = list(hyp.missing_evidence)
                return res
        for ch in self.competing_hypotheses:
            if ch.hypothesis_id == hypothesis_id:
                verdict_status = ch.evaluate_verdict(ledger=self.ledger)
                return {
                    "hypothesis_id": ch.hypothesis_id,
                    "status": verdict_status,
                    "verdict": verdict_status,
                    "confidence": ch.confidence,
                    "supporting_evidence_ids": list(ch.supporting_evidence_ids),
                    "contradicting_evidence_ids": list(ch.contradicting_evidence_ids),
                    "unverified_evidence_ids": list(ch.unverified_evidence_ids),
                    "rejected_evidence_reasons": dict(ch.rejected_evidence_reasons),
                    "independent_root_sources": sorted(ch.get_independent_root_sources(ledger=self.ledger)),
                    "decision_trace": dict(ch.decision_trace),
                    "verification_results": list(ch.verification_results),
                }
        return {"error": f"Hypothesis '{hypothesis_id}' not found"}

    def compare_hypotheses(self, hypothesis_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Compares competing hypotheses side-by-side with explicit discrimination metrics."""
        all_hyps = {h.hypothesis_id: h for h in (self.active_hypotheses + self.rejected_hypotheses)}

        if hypothesis_ids and any(hid in all_hyps for hid in hypothesis_ids):
            matched: List[Dict[str, Any]] = []
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
            matched.sort(
                key=lambda x: (
                    100 if x["status"] == "CONFIRMED" else (70 if x["status"] == "LIKELY" else (50 if x["status"] == "SUPPORTED" else 10)),
                    x["confidence"],
                    x["supporting_evidence_count"] - 2 * x["contradicting_evidence_count"],
                ),
                reverse=True,
            )
            return {
                "investigation_id": self.investigation_id,
                "compared_count": len(matched),
                "hypotheses": matched,
                "recommendation": f"Select {matched[0]['hypothesis_id']} (highest confidence)" if matched else "No hypotheses to compare",
            }

        if self.competing_hypotheses:
            target_set = self.competing_hypotheses
            if hypothesis_ids:
                filtered = [h for h in self.competing_hypotheses if h.hypothesis_id in hypothesis_ids]
                if filtered:
                    target_set = filtered
            comp_res = CompetingHypothesisManager.compare(target_set, ledger=self.ledger)
            return {
                "investigation_id": self.investigation_id,
                "compared_count": len(target_set),
                "leading_hypothesis_id": comp_res.leading_hypothesis_id,
                "hypotheses": comp_res.ranked_hypotheses,
                "discrimination_rationale": comp_res.discrimination_rationale,
                "eliminated_alternatives": comp_res.eliminated_alternatives,
                "unresolved_uncertainties": comp_res.unresolved_uncertainties,
                "recommended_discriminating_recipe": comp_res.recommended_discriminating_recipe,
                "recommendation": f"Select {comp_res.leading_hypothesis_id} ({comp_res.ranked_hypotheses[0]['title']})" if comp_res.ranked_hypotheses else "No hypotheses to compare",
            }

        matched = []
        ids_to_check = hypothesis_ids or list(all_hyps.keys())
        for hid in ids_to_check:
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

        matched.sort(
            key=lambda x: (
                100 if x["status"] == "CONFIRMED" else (70 if x["status"] == "LIKELY" else (50 if x["status"] == "SUPPORTED" else 10)),
                x["confidence"],
                x["supporting_evidence_count"] - 2 * x["contradicting_evidence_count"],
            ),
            reverse=True,
        )

        rationale = (
            f"Leading candidate '{matched[0]['hypothesis_id']}' (status={matched[0]['status']}, conf={matched[0]['confidence']}) "
            f"has {matched[0]['supporting_evidence_count']} supporting facts vs {matched[0]['contradicting_evidence_count']} contradictions."
            if matched else "No hypotheses to compare"
        )

        return {
            "investigation_id": self.investigation_id,
            "compared_count": len(matched),
            "hypotheses": matched,
            "discrimination_rationale": rationale,
            "recommendation": f"Select {matched[0]['hypothesis_id']} ({matched[0]['problem_statement']})" if matched else "No hypotheses to compare",
        }

    def report_blocked_reason(self) -> Optional[str]:
        """Why no report may be produced for this session (planned-only), or None."""
        if not self.executed_check_count() and self.state not in _REPORTABLE_WITHOUT_CHECKS:
            return (f"investigation {self.investigation_id} is in state {self.state} and no check has been executed; "
                    "this report is PLANNED_ONLY and is not a diagnosis (run the investigation first)")
        return None

    def executed_check_count(self) -> int:
        return sum(1 for c in self.checks if c.status not in (CheckStatus.NOT_EXECUTED, CheckStatus.SKIPPED))

    def build_diagnostic_report(self) -> DiagnosticReport:
        """Assembles unified, master DiagnosticReport adhering to Phase 2.1.8 schema (Part E1 & E2).

        IMP-006: a report may be built at any time (unexecuted recipes appear as NOT_EXECUTED, never PASS).
        When no check was ever executed (planned-only) and the session did not end in a state that explains why
        nothing ran, the report is marked ``report_completeness: PLANNED_ONLY`` with overall_result INCONCLUSIVE
        and a limitation line; the one-call ``diagnose()`` never returns a verdict for such a session."""
        planned_only = self.report_blocked_reason()      # before finalising: that changes the state
        if not self.conclusion:
            self._finalize_conclusion("EXPORT_REQUESTED", "Diagnostic report requested prior to terminal state.")

        all_checks = self._build_all_planned_and_executed_checks()

        # Count check statuses
        total_chks = len(all_checks)
        passed_chks = sum(1 for c in all_checks if c.status == CheckStatus.PASS)
        failed_chks = sum(1 for c in all_checks if c.status == CheckStatus.FAIL)
        inconcl_chks = sum(1 for c in all_checks if c.status == CheckStatus.INCONCLUSIVE)
        na_chks = sum(1 for c in all_checks if c.status == CheckStatus.NOT_APPLICABLE)
        not_exec_chks = sum(1 for c in all_checks if c.status == CheckStatus.NOT_EXECUTED)
        err_chks = sum(1 for c in all_checks if c.status == CheckStatus.ERROR)
        skipped_chks = sum(1 for c in all_checks if c.status == getattr(CheckStatus, "SKIPPED", "SKIPPED"))
        unsupp_chks = sum(1 for c in all_checks if c.status == getattr(CheckStatus, "UNSUPPORTED", "UNSUPPORTED"))

        # Centralized Verdict Aggregation Policy (Single Source of Truth)
        agg_verdict = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=self.state,
            stop_reason=self.conclusion.stop_reason if self.conclusion else None,
            checks=all_checks,
            active_hypotheses=self.active_hypotheses,
            rejected_hypotheses=self.rejected_hypotheses,
            limitations=[lim for lim in (self.target_assessment.limitations if self.target_assessment else [])],
            target_assessment=self.target_assessment,
            evidence_records=self.collected_evidence_records,
        )
        if self.conclusion:
            self.conclusion.overall_verdict = agg_verdict.overall_result

        sec_a = ExecutiveSummarySection(
            target_identity=f"PID {self.pid} ({self.companion_elf or 'live process'})",
            investigation_id=self.investigation_id,
            overall_result=agg_verdict.overall_result,
            most_important_findings=agg_verdict.confirmed_problems or agg_verdict.probable_problems or [agg_verdict.verdict_rationale],
            confirmed_problems=agg_verdict.confirmed_problems,
            probable_problems=agg_verdict.probable_problems,
            critical_risks=agg_verdict.critical_risks,
            unresolved_questions=agg_verdict.unresolved_questions,
            recommended_next_actions=agg_verdict.recommended_next_actions,
            verdict_rationale=agg_verdict.verdict_rationale,
            contributing_factors=agg_verdict.contributing_factors,
            limiting_factors=agg_verdict.limiting_factors,
            determining_checks=agg_verdict.determining_checks,
            determining_hypotheses=agg_verdict.determining_hypotheses,
            decision_rule_id=agg_verdict.decision_rule_id,
            problem_statement=self.raw_problem_statement,
        )

        # Section B: Target Context
        det_start = self.timeline[0]["timestamp"] if self.timeline else datetime.now(timezone.utc).isoformat()
        det_end = (
            self.conclusion.completed_at
            if (self.conclusion and getattr(self.conclusion, "completed_at", None))
            else (self.timeline[-1]["timestamp"] if self.timeline else det_start)
        )
        measured_stop_ms = 0.0
        if self.budget_tracker and hasattr(self.budget_tracker, "metrics"):
            measured_stop_ms = float(getattr(self.budget_tracker.metrics, "target_stop_duration_ms", 0.0) or 0.0)
        if measured_stop_ms == 0.0:
            for rec in self.collected_evidence_records:
                if isinstance(rec.raw_details, dict):
                    measured_stop_ms += float(rec.raw_details.get("target_stop_ms") or rec.raw_details.get("stop_duration_ms") or 0.0)
        actual_collection_mode = getattr(self, "collection_mode", None) or (
            "STOPPED_LIVE_RUNTIME" if measured_stop_ms > 0.0 else "ZERO_STOP_LIVE_RUNTIME"
        )
        sec_b = TargetContextSection(
            target_process_name=os.path.basename(self.companion_elf) if self.companion_elf else f"process_{self.pid}",
            pid=self.pid,
            process_start_identity=f"proc_{self.pid}_{self.investigation_id}" if self.pid else None,
            binary_path=self.companion_elf,
            build_id=getattr(self.target_assessment, "build_id", None) if self.target_assessment else None,
            companion_elf=self.companion_elf,
            build_id_check=getattr(self.target_assessment, "build_id_check", None) if self.target_assessment else None,
            target_abi=getattr(self.target_assessment, "target_abi", None) if self.target_assessment else None,
            target_capabilities=self.target_assessment.capabilities if self.target_assessment else [],
            collection_mode=actual_collection_mode,
            target_stop_duration_ms=round(measured_stop_ms, 3),
            observation_interval_sec=self.observation_interval,
            observation_duration_sec=self.observation_duration,
            investigation_start_time=det_start,
            investigation_end_time=det_end,
            collection_failures=[rec.limitations[0] for rec in self.collected_evidence_records if rec.collection_status == COLLECTION_STATUS_FAILED and rec.limitations],
            environmental_limitations=self.target_assessment.limitations if self.target_assessment else [],
        )

        # Section C: Diagnostic Strategy
        executed_recipes = [c.recipe_id for c in self.checks]
        all_planned = [s.recipe_id for s in self.plan.steps] if self.plan else []
        prim_cat = self.classification_result.primary_category if self.classification_result else "UNKNOWN"
        excluded_recipes = []
        for rid in self.recipe_registry.list_recipe_ids():
            if rid not in all_planned:
                r_obj = self.recipe_registry.get_recipe(rid)
                r_dom = getattr(r_obj, "domain", "GENERAL") if r_obj else "GENERAL"
                r_cats = getattr(r_obj, "applicable_problem_categories", []) if r_obj else []
                _missing_caps = self.recipe_registry.missing_capabilities(rid)
                excluded_recipes.append({
                    "recipe_id": rid,
                    **({"unsupported_capability": _missing_caps[0]} if _missing_caps else {}),
                    "reason_excluded": (
                        f"Not supported in this mode: needs {', '.join(_missing_caps)}" if _missing_caps else
                        f"Excluded by adaptive planner: recipe domain '{r_dom}' (categories {r_cats}) "
                        f"did not match primary symptom classification '{prim_cat}'"
                    ),
                })

        sec_c = DiagnosticStrategySection(
            initial_classification=prim_cat,
            classification_confidence=self.classification_result.confidence if self.classification_result else 0.0,
            methodology_name=self.methodology.name if self.methodology else "General Diagnostic Methodology",
            methodology_selection_reason=self.methodology.selection_reason if self.methodology else "General investigation",
            recipes_executed=list(dict.fromkeys(executed_recipes)),
            recipes_excluded=excluded_recipes,
            scope_narrowing_sequence=[
                f"Narrowed to {len(self.active_hypotheses)} active candidate hypotheses based on live evidence",
                f"Evaluated {len(all_checks)} diagnostic checks against target address space",
            ],
            key_observations_driving_decisions=[e.get("finding") for e in self.collected_evidence if e.get("finding")],
            information_gain_prioritization=[h.problem_statement for h in self.active_hypotheses],
        )

        # Section D: Detailed Inspection Results
        req_checks = [c for c in all_checks if getattr(c, "is_required", getattr(c, "required", True))]
        req_passed = sum(1 for c in req_checks if c.status == CheckStatus.PASS)
        missing_cov = [c.check_id for c in req_checks if c.status != CheckStatus.PASS]

        sec_d = DetailedInspectionResultsSection(
            checks_total=total_chks,
            checks_passed=passed_chks,
            checks_failed=failed_chks,
            checks_inconclusive=inconcl_chks,
            checks_not_applicable=na_chks,
            checks_not_executed=not_exec_chks,
            checks_error=err_chks,
            checks_skipped=skipped_chks,
            checks_unsupported=unsupp_chks,
            required_checks_count=len(req_checks),
            required_checks_passed=req_passed,
            missing_coverage=missing_cov,
            checks=[c.to_dict() for c in all_checks],
        )

        # Section E: Findings & Root Cause Analysis (with explicit 5-level epistemic classification)
        findings_sec = FindingsSection()
        for idx, h in enumerate(self.active_hypotheses):
            f_id = f"FND_{idx+1:03d}"
            if h.status == "CONFIRMED" and h.category not in ("HEALTHY", "HEALTHY_PROCESS"):
                findings_sec.confirmed_root_causes.append(FindingRecord(
                    finding_id=f_id,
                    severity="CRITICAL" if any(k in h.problem_statement.upper() for k in ("CORRUPTION", "FREE", "DEADLOCK")) else "HIGH",
                    classification=CLASSIFICATION_CONFIRMED_ROOT_CAUSE,
                    problem_description=h.problem_statement,
                    affected_entity=h.category,
                    observed_behavior=h.confidence_basis,
                    technical_explanation=f"Deterministic criteria confirmed fault: {h.confidence_basis}",
                    supporting_evidence_ids=h.supporting_evidence_ids,
                    contradicting_evidence_ids=[e.get("evidence_id") for e in h.contradicting_evidence if e.get("evidence_id")],
                    applicable_diagnostic_rules=h.applicable_diagnostic_rules,
                    confidence_basis=h.confidence_basis,
                    verification_status="CONFIRMED",
                    epistemic_level="confirmed_root_cause",
                ))
            elif h.status in ("LIKELY", "PROPOSED", "SUPPORTED") and h.category not in ("HEALTHY", "HEALTHY_PROCESS"):
                # IMP-009: a rule may mark its observation as a warning (e.g. stack nearly exhausted) or as INFO,
                # a degradation that is not a fault (e.g. heap retention; see diagnose: DEGRADED)
                sev = [e.get("details", {}).get("finding_severity") for e in h.supporting_evidence
                       if e.get("status") == "SUPPORTED"]
                findings_sec.probable_causes.append(FindingRecord(
                    finding_id=f_id,
                    severity=sev[0] if sev and sev[0] in ("WARNING", "INFO") and len(set(sev)) == 1 else "MEDIUM",
                    classification=CLASSIFICATION_PROBABLE_CAUSE,
                    problem_description=h.problem_statement,
                    affected_entity=h.category,
                    observed_behavior=h.confidence_basis,
                    technical_explanation="Evidence supports hypothesis but conclusive invariant failure or primary observation remains unverified.",
                    supporting_evidence_ids=h.supporting_evidence_ids,
                    contradicting_evidence_ids=[e.get("evidence_id") for e in h.contradicting_evidence if e.get("evidence_id")],
                    applicable_diagnostic_rules=h.applicable_diagnostic_rules,
                    confidence_basis=h.confidence_basis,
                    verification_status="SUSPECTED",
                    epistemic_level="probable_cause",
                ))

        for ev in self.collected_evidence:
            if ev.get("finding"):
                findings_sec.observed_symptoms.append(FindingRecord(
                    finding_id=f"SYM_{ev.get('evidence_id')}",
                    severity="LOW",
                    classification=CLASSIFICATION_OBSERVED_SYMPTOM,
                    problem_description=ev.get("finding", ""),
                    affected_entity=ev.get("symbol") or str(ev.get("address")),
                    observed_behavior=str(ev.get("observed_value")),
                    supporting_evidence_ids=[ev.get("evidence_id", "")],
                    verification_status="OBSERVED",
                    epistemic_level="observation",
                ))

        # Section F: Competing Hypotheses & Authority Decisions
        all_hyps = self.active_hypotheses + self.rejected_hypotheses
        comp_dicts = []
        prim_rules_eval = []
        rej_ev_map: Dict[str, str] = {}
        indep_roots_union: Set[str] = set()
        dep_graph_union: Dict[str, List[str]] = {}
        missing_ident_recs: List[str] = []
        mismatched_ident_recs: List[str] = []

        for ch in self.competing_hypotheses:
            ch.evaluate_verdict(ledger=self.ledger)
            comp_dicts.append(ch.to_dict())
            if ch.primary_rule_audit:
                prim_rules_eval.append(dict(ch.primary_rule_audit))
            rej_ev_map.update(ch.rejected_evidence_reasons)
            indep_roots_union.update(ch.get_independent_root_sources(ledger=self.ledger))
            for k_dep, v_dep in ch.evidence_dependencies.items():
                dep_graph_union[k_dep] = list(v_dep)
            for eid_k, id_rec in ch.identity_validation_records.items():
                if id_rec.get("status") == "MISSING_IDENTITY":
                    missing_ident_recs.append(f"{eid_k}: {id_rec.get('reason')}")
                elif id_rec.get("status") == "IDENTITY_MISMATCH":
                    mismatched_ident_recs.append(f"{eid_k}: {id_rec.get('reason')}")

        sec_f = CompetingHypothesesSection(
            leading_hypothesis_id=self.active_hypotheses[0].hypothesis_id if self.active_hypotheses else (
                self.competing_hypotheses[0].hypothesis_id if self.competing_hypotheses else None
            ),
            hypotheses=[h.to_dict() for h in all_hyps] if all_hyps else comp_dicts,
            ranking_rationale="Ranked by verification status, confidence score, and net supporting vs counter-evidence without double-counting.",
            eliminated_alternatives=[
                {"hypothesis_id": rh.hypothesis_id, "rationale": rh.confidence_basis}
                for rh in self.rejected_hypotheses
            ] + [
                {"hypothesis_id": ch.hypothesis_id, "rationale": "; ".join(ch.contradicting_observations)}
                for ch in self.competing_hypotheses if ch.status == "REFUTED"
            ],
            missing_evidence_preventing_conclusions=[m for h in self.active_hypotheses for m in h.missing_evidence] + [
                m for ch in self.competing_hypotheses for m in ch.missing_evidence
            ],
            double_counting_protections_applied=True,
            competing_candidates=comp_dicts,
            primary_evidence_rules_evaluated=prim_rules_eval,
            rejected_evidence=rej_ev_map,
        )

        # Section G: Evidence & Provenance Index
        ev_entries = []
        for rec in self.collected_evidence_records:
            corr = next((e.get("correlation") for e in self.collected_evidence if e.get("evidence_id") == rec.evidence_id), None)
            assoc_checks = [c.check_id for c in self.checks if rec.evidence_id in c.supporting_evidence_ids or rec.evidence_id in c.contradicting_evidence_ids]
            assoc_hyps = [h.hypothesis_id for h in all_hyps if rec.evidence_id in h.supporting_evidence_ids or rec.evidence_id in h.contradicting_evidence_ids]
            rec_dur = 0.001
            if isinstance(rec.raw_details, dict) and isinstance(rec.raw_details.get("duration_sec"), (int, float)):
                rec_dur = float(rec.raw_details["duration_sec"])
            l_rec = self.ledger.get_record(rec.evidence_id) if (self.ledger and hasattr(self.ledger, "get_record")) else None
            p_ids = list(getattr(l_rec, "parent_evidence_ids", [])) if l_rec else list(dep_graph_union.get(rec.evidence_id, []))
            if not indep_roots_union and l_rec and not p_ids and rec.provenance_class in ("LIVE_RUNTIME_CAPTURE", "CONTROLLED_RUNTIME_REPRODUCTION"):
                indep_roots_union.add(rec.evidence_id)

            ev_entries.append(EvidenceIndexEntry(
                evidence_id=rec.evidence_id,
                collection_method=rec.collection_method,
                target_pid=rec.target_pid,
                timestamp=rec.collection_timestamp,
                duration_sec=rec_dur,
                provenance_class=rec.provenance_class,
                raw_observation=rec.raw_observation if rec.raw_observation is not None else rec.observed_value,
                normalized_observation=rec.normalized_observation if rec.normalized_observation is not None else rec.observed_value,
                correlated_source=corr,
                associated_checks=assoc_checks,
                associated_hypotheses=assoc_hyps,
                parent_evidence_ids=p_ids,
                epistemic_level="derived_evidence" if p_ids else "observation",
                authority_status="UNVERIFIED" if rec.evidence_id in rej_ev_map else (
                    "VERIFIED" if rec.provenance_class in ("LIVE_RUNTIME_CAPTURE", "CONTROLLED_RUNTIME_REPRODUCTION") else "UNVERIFIED"
                ),
            ))
        sec_g = EvidenceAndProvenanceSection(
            evidence_count=len(ev_entries),
            evidence_records=ev_entries,
            independent_root_sources=sorted(indep_roots_union),
            dependency_graph=dep_graph_union,
            rejected_or_unverified_evidence=rej_ev_map,
        )

        # Section H: Limitations & Unverified Areas
        sec_h = LimitationsSection(
            unexecuted_checks=[c.name for c in all_checks if c.status == CheckStatus.NOT_EXECUTED],
            unsupported_capabilities=[cap for cap in (self.methodology.required_target_capabilities if self.methodology else []) if cap not in (self.target_assessment.capabilities if self.target_assessment else [])],
            collection_failures=[rec.limitations[0] for rec in self.collected_evidence_records if rec.collection_status == COLLECTION_STATUS_FAILED and rec.limitations],
            missing_symbols_or_dwarf=["DWARF debug information missing from companion ELF"] if (self.target_assessment and not self.target_assessment.dwarf_available) else [],
            incomplete_temporal_observations=self.observation_window.limitations if hasattr(self.observation_window, "limitations") else [],
            incomplete_lock_graphs=["Lock graph incomplete due to unresolvable mutex owners"] if (hasattr(self.concurrency_graph, "unresolved_edges") and self.concurrency_graph.unresolved_edges) else [],
            unavailable_allocator_metadata=["Allocator metadata unavailable"] if (self.allocator_inspector and self.allocator_inspector.allocator_type == AllocatorType.UNKNOWN) else [],
            confidence_limiting_factors=agg_verdict.limiting_factors,
            missing_identity_records=missing_ident_recs,
            mismatched_identity_records=mismatched_ident_recs,
        )

        # Section I: Final Conclusions & Recommendations (Single Source of Truth: overall_conclusion == agg_verdict.overall_result)
        sec_i = FinalConclusionsSection(
            overall_conclusion=agg_verdict.overall_result,
            confirmed_problems=agg_verdict.confirmed_problems,
            probable_problems=agg_verdict.probable_problems,
            ruled_out_hypotheses=sec_f.eliminated_alternatives,
            remaining_uncertainties=agg_verdict.unresolved_questions or agg_verdict.limiting_factors,
            recommended_next_diagnostic_steps=agg_verdict.recommended_next_actions,
            expected_information_value=["Definitive verification of unresolved invariants" if agg_verdict.unresolved_questions else "Confirmation of clean execution"],
            safe_remediation_suggestions=self.conclusion.recommended_remediations if (self.conclusion and self.conclusion.recommended_remediations) else agg_verdict.recommended_next_actions,
            verdict_rationale=agg_verdict.verdict_rationale,
            decision_trace=agg_verdict.decision_trace,
        )

        if planned_only:
            sec_a.overall_result = "INCONCLUSIVE"
            sec_a.limiting_factors = list(sec_a.limiting_factors or []) + [planned_only]
            sec_h.unexecuted_checks = list(sec_h.unexecuted_checks or []) + [planned_only]
        return DiagnosticReport(
            report_completeness="PLANNED_ONLY" if planned_only else "COMPLETE",
            report_id=f"rep_{self.investigation_id}",
            investigation_id=self.investigation_id,
            generated_at=det_end,
            section_a_executive_summary=sec_a,
            section_b_target_context=sec_b,
            section_c_diagnostic_strategy=sec_c,
            section_d_detailed_inspection_results=sec_d,
            section_e_findings_and_root_cause=findings_sec,
            section_f_competing_hypotheses=sec_f,
            section_g_evidence_and_provenance=sec_g,
            section_h_limitations_and_unverified=sec_h,
            section_i_final_conclusions=sec_i,
        )

    def export_report(self, format: str = "json") -> Union[Dict[str, Any], str]:
        """Exports master diagnostic report as JSON, Markdown, or HTML."""
        fmt = format.lower()
        report = self.build_diagnostic_report()
        if fmt == "html":
            return report.to_html()
        elif fmt == "markdown" or fmt == "md":
            return report.to_markdown()
        elif fmt == "json_str":
            return report.to_json()

        res = report.to_dict()
        res["report_13_points"] = {
            "1_problem_description": self.raw_problem_statement,
            "2_target_information": res.get("section_b_target_context", {}),
            "3_initial_classification": res.get("section_c_diagnostic_strategy", {}),
            "4_investigation_scope": {"targeted_recipes": [s.recipe_id for s in self.plan.steps] if self.plan else []},
            "5_executed_diagnostic_procedures": [c for c in res.get("section_d_detailed_inspection_results", {}).get("checks", []) if c.get("status") not in ("NOT_EXECUTED", "SKIPPED")],
            "6_actual_observations": [r.to_dict() for r in self.collected_evidence_records],
            "7_confirmed_findings": [h.to_dict() for h in self.active_hypotheses if h.status == "CONFIRMED"],
            "7_findings_detail": res.get("section_e_findings_and_root_cause", {}),
            "8_probable_causes": [h.problem_statement for h in self.active_hypotheses if h.status in ("CONFIRMED", "LIKELY")],
            "9_rejected_hypotheses": [h.to_dict() for h in self.rejected_hypotheses],
            "10_unresolved_hypotheses": [h.to_dict() for h in self.active_hypotheses if h.status in ("PROPOSED", "LIKELY", "INCONCLUSIVE")],
            "11_evidence_to_source_mapping": [corr for corr in [ev.get("correlation") for ev in self.collected_evidence] if corr],
            "12_missing_evidence": self.target_assessment.limitations if self.target_assessment else [],
            "13_recommended_next_actions": self.conclusion.recommended_remediations if self.conclusion else [],
        }
        res["investigation_id"] = self.investigation_id
        res["target_pid"] = self.pid
        res["problem_statement"] = self.raw_problem_statement
        res["status"] = self.state
        res["conclusion"] = asdict(self.conclusion) if self.conclusion else None
        res["plan"] = self.plan.to_dict() if self.plan else None
        res["active_hypotheses"] = [h.to_dict() for h in self.active_hypotheses]
        res["rejected_hypotheses"] = [h.to_dict() for h in self.rejected_hypotheses]
        res["timeline"] = self.timeline
        res["diagnostic_limitations"] = self.target_assessment.limitations if self.target_assessment else []
        return res

    def to_dict(self) -> Dict[str, Any]:
        """Serializes complete session state to a dictionary for persistence / recovery (Part F)."""
        return {
            "schema_version": "2.1.8",
            "investigation_id": self.investigation_id,
            "raw_problem_statement": self.raw_problem_statement,
            "symptom_fields": self.symptom_fields.to_dict() if self.symptom_fields else None,
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
            "target_assessment": self.target_assessment.to_dict() if self.target_assessment else None,
            "verified_checks_count": self.verified_checks_count,
            "temporal_memory_samples": self.temporal_memory_samples,
            "ledger": self.ledger.to_dict() if self.ledger else None,
            "methodology": self.methodology.to_dict() if self.methodology else None,
            "checks": [c.to_dict() for c in self.checks],
            "competing_hypotheses": [h.to_dict() for h in self.competing_hypotheses],
        }

    def reconcile_durability(self) -> Dict[str, Any]:
        """Reconciles durability state after an unknown commit outcome or crash (Part F)."""
        target_path = os.path.join(self._investigations_dir, f"{self.investigation_id}.json")
        if os.path.islink(self._investigations_dir) or (os.path.lexists(target_path) and os.path.islink(target_path)):
            return {
                "investigation_id": self.investigation_id,
                "reconciled": False,
                "outcome": DurableCommitOutcome.NOT_COMMITTED.value,
                "details": "Symlink detected on investigation directory or target file",
            }
        if not os.path.exists(target_path):
            return {
                "investigation_id": self.investigation_id,
                "reconciled": False,
                "outcome": DurableCommitOutcome.NOT_COMMITTED.value,
                "details": f"Target file does not exist on disk: {target_path}",
            }
        try:
            st = os.stat(target_path)
            if (st.st_mode & 0o777) != 0o600:
                os.chmod(target_path, 0o600)
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("investigation_id") != self.investigation_id:
                return {
                    "investigation_id": self.investigation_id,
                    "reconciled": False,
                    "outcome": DurableCommitOutcome.NOT_COMMITTED.value,
                    "details": "Mismatched investigation_id in persisted file",
                }
            dir_fd = os.open(self._investigations_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            return {
                "investigation_id": self.investigation_id,
                "reconciled": True,
                "outcome": DurableCommitOutcome.COMMITTED.value,
                "details": "Persisted state verified and directory fsync completed",
            }
        except Exception as e:
            return {
                "investigation_id": self.investigation_id,
                "reconciled": False,
                "outcome": DurableCommitOutcome.COMMIT_UNKNOWN.value,
                "details": f"Reconciliation failed: {e}",
            }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AdaptiveInvestigationSession":
        """Reconstructs session state from a serialized dictionary with schema migration and authority re-validation (Part A5 & F)."""
        if not isinstance(data, dict) or not data.get("investigation_id"):
            raise ValueError("Invalid or corrupted session dictionary: missing investigation_id")

        sess = cls(
            investigation_id=str(data["investigation_id"]),
            problem_statement=str(data.get("raw_problem_statement") or data.get("problem_statement") or ""),
            pid=data.get("pid"),
            companion_elf=data.get("companion_elf"),
            corpus_dir=data.get("corpus_dir"),
            symptom_fields=data.get("symptom_fields"),
        )
        sess.state = data.get("state", STATE_CREATED)
        sess.is_paused = bool(data.get("is_paused", False))
        sess.timeline = list(data.get("timeline", []))
        if data.get("plan") and isinstance(data["plan"], dict):
            sess.plan = InvestigationPlan.from_dict(data["plan"])
        sess.collected_evidence = list(data.get("collected_evidence", []))
        sess.collected_evidence_records = [
            RuntimeEvidenceRecord.from_dict(r) for r in data.get("collected_evidence_records", [])
            if isinstance(r, dict)
        ]
        if data.get("ledger") and isinstance(data["ledger"], dict):
            sess.ledger = EvidenceLedger.from_dict(data["ledger"])
        sess.active_hypotheses = [
            ExpertHypothesis.from_dict(h) for h in data.get("active_hypotheses", [])
            if isinstance(h, dict)
        ]
        sess.rejected_hypotheses = [
            ExpertHypothesis.from_dict(h) for h in data.get("rejected_hypotheses", [])
            if isinstance(h, dict)
        ]
        sess.verified_checks_count = int(data.get("verified_checks_count", 0))
        sess.temporal_memory_samples = list(data.get("temporal_memory_samples", []))
        if data.get("classification_result") and isinstance(data["classification_result"], dict):
            valid_cr = {f.name for f in fields(ProblemClassificationResult)}
            cr_in = dict(data["classification_result"])
            cr_defaults = {
                "raw_query": sess.raw_problem_statement,
                "normalized_query": sess.raw_problem_statement.lower(),
                "primary_category": "UNKNOWN",
                "candidate_categories": [],
                "confidence": 0.5,
                "extracted_entities": {},
                "is_vague": False,
            }
            cr_defaults.update({k: v for k, v in cr_in.items() if k in valid_cr})
            sess.classification_result = ProblemClassificationResult(**cr_defaults)
        if data.get("target_assessment") and isinstance(data["target_assessment"], dict):
            valid_ta = {f.name for f in fields(TargetAssessmentResult)}
            ta_in = dict(data["target_assessment"])
            ta_defaults = {
                "pid": sess.pid,
                "accessible": False,
                "thread_count": 0,
                "memory_regions_count": 0,
                "rss_kb": 0,
                "companion_elf_path": sess.companion_elf,
                "companion_elf_valid": False,
                "dwarf_available": False,
                "capabilities": [],
                "limitations": [],
                "prerequisites_met": False,
            }
            ta_defaults.update({k: v for k, v in ta_in.items() if k in valid_ta})
            sess.target_assessment = TargetAssessmentResult(**ta_defaults)
        if data.get("conclusion") and isinstance(data["conclusion"], dict):
            valid_dc = {f.name for f in fields(DiagnosticConclusion)}
            dc_in = dict(data["conclusion"])
            dc_defaults = {
                "investigation_id": sess.investigation_id,
                "target_pid": sess.pid,
                "status": sess.state,
                "stop_reason": "UNKNOWN",
                "executive_summary": "",
                "primary_finding": "",
                "confidence": 0.0,
                "confidence_basis": "",
                "supporting_evidence_chain": [],
                "rejected_alternatives": [],
                "missing_evidence_and_unknowns": [],
                "recommended_remediations": [],
                "diagnostic_limitations": [],
            }
            dc_defaults.update({k: v for k, v in dc_in.items() if k in valid_dc})
            sess.conclusion = DiagnosticConclusion(**dc_defaults)
        if data.get("methodology") and isinstance(data["methodology"], dict):
            sess.methodology = DiagnosticMethodology.from_dict(data["methodology"])
        if data.get("checks") and isinstance(data["checks"], list):
            sess.checks = [DiagnosticCheck.from_dict(c) for c in data["checks"] if isinstance(c, dict)]
        if data.get("competing_hypotheses") and isinstance(data["competing_hypotheses"], list):
            sess.competing_hypotheses = [
                CompetingHypothesis.from_dict(h, ledger=sess.ledger)
                for h in data["competing_hypotheses"]
                if isinstance(h, dict)
            ]
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
        expert_overrides: Optional[List[Any]] = None,
        manual_invariants: Optional[List[Any]] = None,
        observation_interval: Optional[float] = None,
        observation_duration: Optional[float] = None,
        target_recipe: Optional[str] = None,
        target_expressions: Optional[List[str]] = None,
        recipe_thresholds: Optional[Dict[str, Any]] = None,
        budget_tracker: Optional[ObservationBudgetTracker] = None,
        budget_limits: Optional[ObservationBudgetLimits] = None,
        symptom_fields: Any = None,
    ) -> AdaptiveInvestigationSession:
        """Launches a new adaptive investigation session (symptom_fields: optional structured symptom input)."""
        inv_id = investigation_id or f"inv_{uuid.uuid4().hex[:12]}"
        session = AdaptiveInvestigationSession(
            investigation_id=inv_id,
            problem_statement=problem_statement,
            pid=pid,
            companion_elf=companion_elf,
            corpus_dir=self.corpus_dir,
            adapter=adapter,
            expert_overrides=expert_overrides,
            manual_invariants=manual_invariants,
            observation_interval=observation_interval,
            observation_duration=observation_duration,
            target_recipe=target_recipe,
            target_expressions=target_expressions,
            recipe_thresholds=recipe_thresholds,
            budget_tracker=budget_tracker,
            budget_limits=budget_limits,
            symptom_fields=symptom_fields,
        )
        self.sessions[inv_id] = session
        return session

    def run_recipe(
        self,
        recipe_id: str,
        pid: Optional[int] = None,
        companion_elf: Optional[str] = None,
        expressions: Optional[List[str]] = None,
        thresholds: Optional[Dict[str, Any]] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
        budget: Optional[ObservationBudgetTracker] = None,
        budget_limits: Optional[ObservationBudgetLimits] = None,
    ) -> Dict[str, Any]:
        """Runs a targeted deterministic diagnostic recipe from the registry with budget enforcement."""
        from .diagnostic_recipes import DiagnosticRecipeRegistry
        recipe = DiagnosticRecipeRegistry.get_recipe(recipe_id)
        if not recipe:
            norm = recipe_id.strip().upper()
            if not norm.startswith("RECIPE_"):
                recipe = DiagnosticRecipeRegistry.get_recipe(f"RECIPE_{norm}")
            if not recipe:
                for rid in DiagnosticRecipeRegistry.list_recipe_ids():
                    if rid.upper() == norm or rid.replace("RECIPE_", "").upper() == norm:
                        recipe = DiagnosticRecipeRegistry.get_recipe(rid)
                        break
        if not recipe:
            raise ValueError(f"Recipe '{recipe_id}' not found in DiagnosticRecipeRegistry")

        session = self.start_investigation(
            problem_statement=f"Targeted execution of diagnostic recipe {recipe.recipe_id}: {recipe.name}",
            pid=pid,
            companion_elf=companion_elf,
            adapter=adapter,
            target_recipe=recipe.recipe_id,
            target_expressions=expressions,
            recipe_thresholds=thresholds,
            budget_tracker=budget,
            budget_limits=budget_limits,
        )

        conclusion = session.run_to_completion()
        check = next((c for c in session.checks if c.recipe_id == recipe.recipe_id), None)
        records = session.ledger.get_records()

        res = {
            "investigation_id": session.investigation_id,
            "recipe_id": recipe.recipe_id,
            "recipe_name": recipe.name,
            "domain": recipe.domain,
            "category": recipe.problem_category,
            "status": session.state if session.state == STATE_BUDGET_EXHAUSTED else (getattr(check, "status", session.state)),
            "outcome": getattr(check, "outcome", session.state),
            "state": session.state,
            "stop_reason": getattr(conclusion, "stop_reason", None) or (session.state if session.state == STATE_BUDGET_EXHAUSTED else None),
            "confidence": conclusion.confidence if conclusion else "medium",
            "findings": [
                asdict(f) if hasattr(f, "__dataclass_fields__") else f
                for f in (conclusion.findings if conclusion and hasattr(conclusion, "findings") else [])
            ],
            "checks": [c.to_dict() if hasattr(c, "to_dict") else asdict(c) for c in session.checks],
            "evidence_records": [r.to_dict() for r in records],
            "evidence_count": len(records),
            "limitations": conclusion.diagnostic_limitations if conclusion and hasattr(conclusion, "diagnostic_limitations") else [],
            "budget": session.budget_tracker.to_dict() if session.budget_tracker else None,
            "budget_metrics": asdict(session.budget_tracker.metrics) if (session.budget_tracker and hasattr(session.budget_tracker, "metrics")) else None,
            "conclusion": conclusion.to_dict() if hasattr(conclusion, "to_dict") else (asdict(conclusion) if conclusion else None),
        }
        return res
        self.sessions[inv_id] = session
        return session

    def get_session(self, investigation_id: str) -> Optional[AdaptiveInvestigationSession]:
        """Retrieves an existing investigation session by ID from memory or disk."""
        if investigation_id in self.sessions:
            return self.sessions[investigation_id]

        disk_path = os.path.join(self._investigations_dir, f"{investigation_id}.json")
        if os.path.islink(disk_path):
            raise InvestigationPersistenceError(
                f"Refusing to load from symlink: {disk_path}",
                outcome=DurableCommitOutcome.NOT_COMMITTED,
            )
        if os.path.exists(disk_path):
            try:
                with open(disk_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                sess = AdaptiveInvestigationSession.from_dict(data)
                self.sessions[investigation_id] = sess
                return sess
            except InvestigationPersistenceError:
                raise
            except Exception as e:
                raise InvestigationPersistenceError(
                    f"Corrupted investigation session state on disk for '{investigation_id}': {e}",
                    outcome=DurableCommitOutcome.NOT_COMMITTED,
                    cause=e,
                ) from e
        return None

    def recover_session(self, investigation_id: str) -> Optional[AdaptiveInvestigationSession]:
        """Recovers an investigation session from disk and reconciles durability state."""
        sess = self.get_session(investigation_id)
        if sess:
            sess.reconcile_durability()
        return sess

    def list_sessions(self) -> List[Dict[str, Any]]:
        """Lists metadata for all active and completed sessions."""
        return [sess.get_status() for sess in self.sessions.values()]


# =============================================================================
# IMP-006 (thin version): single `diagnose` entry point
# =============================================================================
# One call: classify -> assess -> plan -> execute (run_to_completion) -> conclude -> report.
# It composes ExpertDiagnosticEngine.start_investigation / run_to_completion /
# build_diagnostic_report; it adds no engine and no verdict logic.  The verdict is the
# DiagnosticVerdictAggregator's (HEALTHY, INCONCLUSIVE, ...), copied unchanged.
#
# DiagnoseResult schema (all keys always present, JSON-serialisable via ``to_dict``):
#   schema_version   str   "1"
#   verdict          str   aggregator vocabulary: CONFIRMED_FAULT | PROBABLE_FAULT | FAULT | DEGRADED |
#                          HEALTHY | INCONCLUSIVE | ABORTED.  INCONCLUSIVE whenever the diagnosis could
#                          not run to completion (bad PID, missing debug image, stage exception, ...).
#   confidence       float 0..1 (engine's conclusion confidence; 0.0 when nothing ran)
#   confidence_basis str
#   summary          str   one or two plain sentences
#   findings         list  {category, severity, status, description, subjects, subject_details,
#                           recipe_ids, evidence_ids}.  category = the engine's problem identifier
#                          (e.g. DEADLOCK_INDICATORS, MEMORY_LEAK); subjects = flat list of the
#                          concrete names the evidence exposed (lock names, thread ids, function names,
#                          variable names, "file:line"); [] when the evidence exposed none.
#                          subject_details = same names as {kind, name}.
#   checks_run       list  {check_id, recipe_id, name, status, duration_s, limitations}; executed only
#   not_covered      list  {kind, item, reason}; everything that could not be examined (check statuses
#                          INCONCLUSIVE/ERROR/NOT_APPLICABLE/UNSUPPORTED/NOT_EXECUTED, engine limitations,
#                          features unsupported on the target ABI, budget exhaustion, missing debug image,
#                          pre-flight / stage failures).
#   collection_impact {capture_mode, measured_stop_ms, zero_stop (bool), bytes_read, wall_clock_ms,
#                          samples_collected, budget_exhausted}.  diagnose never requests a stop mode.
#   report_path      str|None  JSON report written to <corpus>/reports/<investigation_id>.report.json
#   report           dict|None only with include_report=True
#   investigation_id str|None
#   target           {pid, process_name, abi (target_abi.TargetABI.to_dict() or None), debug_image}
#   state            str   final session lifecycle state (or "NOT_RUN")
#   stop_reason      str|None
#   duration_s       float wall time of the call
#   healthy_scope    dict  the HEALTHY rule (extractor.healthy_verdict, docs/HEALTHY_VERDICT.md) applied to this run:
#                          {rule, healthy (bool), checked [{recipe_id, what, what_ko, result}],
#                           not_checked [{kind, item, label, label_ko, reason}] (scope limits of a HEALTHY verdict),
#                           blocking [{kind, item, reason}] (why the run is NOT healthy; empty when HEALTHY)}.
#                          verdict == HEALTHY  <=>  healthy_scope.healthy.
#   symptom_interpretation dict  how the symptom was read (extractor.symptom_interpretation): {symptom_class,
#                          source (text|structured|default), understood (False: LOW confidence, the broad plan
#                          was used and the report says so), confidence_level (HIGH|LOW), confidence, reason
#                          (clear|no_match|weak_evidence|conflicting_classes), primary_category, broad_plan,
#                          scores, competing_class, text_class, fields}; {} when the run ended before classification.
DIAGNOSE_SCHEMA_VERSION = "1"
DIAGNOSE_DEFAULT_SYMPTOM = "general health check"

_SUBJECT_SKIP_KEYS = {"threads", "callstacks_info", "locks", "observation_window", "thread_summary",
                      "thread_sampling", "long_wait_threads",
                      # IMP-008: per-walk totals and growth NOT attributed to an owner carry no subject names
                      "heap_walks", "held_growth", "memory_trend"}
# IMP-010: thread findings of the time-series sampler (rows are dicts of {tid, name, function, ...})
_SUBJECT_THREAD_ROW_KEYS = ("runaway_threads", "zombie_threads", "d_state_threads", "stalled_lock_waits")
_SUBJECT_KEY_KIND = {
    "lock_name": "lock",
    "fd_target": "resource",  # IMP-018: what a leaking file descriptor refers to (socket / pipe / path)
    "tid": "thread", "waiter_tid": "thread", "owner_tid": "thread", "held_by_tid": "thread",
    "waiter_name": "thread_name", "owner_name": "thread_name", "held_by_thread_name": "thread_name",
    "thread_name": "thread_name",
    "function_name": "function",
    "source_location": "source_location",
    "variable": "variable", "variable_name": "variable", "symbol": "variable",
    "expression": "variable", "source_variable": "variable",
    # IMP-008 leak attribution: the owning variable / its normalised growth path; for unreachable growth the
    # thread whose arena holds the blocks (evidence-based, see leak_attribution.arena_threads)
    "variable_path": "variable",
    "allocating_thread_name": "thread_name", "allocating_thread_tid": "thread",
    # use-after-free (recipe_plugins/use_after_free): the freed chunk a dangling pointer refers to / was written
    "freed_chunk": "heap_chunk",
}


@dataclass
class DiagnoseResult:
    """Stable result of :func:`diagnose`; see the schema comment above."""
    verdict: str = "INCONCLUSIVE"
    confidence: float = 0.0
    confidence_basis: str = ""
    summary: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    checks_run: List[Dict[str, Any]] = field(default_factory=list)
    not_covered: List[Dict[str, Any]] = field(default_factory=list)
    collection_impact: Dict[str, Any] = field(default_factory=dict)
    report_path: Optional[str] = None
    report: Optional[Dict[str, Any]] = None
    investigation_id: Optional[str] = None
    target: Dict[str, Any] = field(default_factory=dict)
    state: str = "NOT_RUN"
    stop_reason: Optional[str] = None
    duration_s: float = 0.0
    schema_version: str = DIAGNOSE_SCHEMA_VERSION
    healthy_scope: Dict[str, Any] = field(default_factory=dict)
    symptom_interpretation: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return json.loads(json.dumps(asdict(self), default=str))


def _collect_subjects(obj: Any, out: List[Tuple[str, str]], depth: int = 0) -> None:
    if depth > 8:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _SUBJECT_SKIP_KEYS:
                continue
            if k in _SUBJECT_THREAD_ROW_KEYS and isinstance(v, list):
                for row in v:
                    if not isinstance(row, dict):
                        continue
                    for rk, kind_ in (("tid", "thread"), ("name", "thread_name"), ("function", "function"),
                                      ("top_source_location", "source_location"), ("lock", "lock")):
                        rv = row.get(rk)
                        if isinstance(rv, (str, int)) and not isinstance(rv, bool) and str(rv) != "":
                            out.append((kind_, str(rv)))
                continue
            kind = _SUBJECT_KEY_KIND.get(k)
            if kind and isinstance(v, (str, int)) and not isinstance(v, bool) and str(v) != "":
                out.append((kind, str(v)))
            elif isinstance(v, (dict, list)):
                _collect_subjects(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _collect_subjects(v, out, depth + 1)


def _finding_subjects(session: "AdaptiveInvestigationSession", rule_ids: List[str]) -> List[Dict[str, str]]:
    pairs: List[Tuple[str, str]] = []
    wanted = set(rule_ids or [])
    for chk in session.checks:
        if chk.recipe_id in wanted and chk.status == CheckStatus.FAIL:
            _collect_subjects(chk.actual_observations, pairs)
            for rec in session.collected_evidence_records:
                if rec.evidence_id in chk.supporting_evidence_ids and rec.source_variable:
                    pairs.append(("variable", str(rec.source_variable)))
    seen, details = set(), []
    for kind, name in pairs:
        if (kind, name) not in seen:
            seen.add((kind, name))
            details.append({"kind": kind, "name": name})
    return details


def _preflight_target(pid: Any, adapter: Any) -> Tuple[Optional[str], Optional[str]]:
    """Returns (process_name, failure_reason).  Never raises."""
    try:
        if isinstance(pid, bool) or int(pid) != pid or int(pid) <= 0:
            return None, f"invalid PID {pid!r}"
        pid = int(pid)
    except (TypeError, ValueError):
        return None, f"invalid PID {pid!r}"
    if isinstance(adapter, LocalTargetAdapter):
        if not os.path.isdir(f"/proc/{pid}"):
            return None, f"process {pid} does not exist"
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as fh:
                name = fh.read().strip()
        except OSError as exc:
            return None, f"process {pid} is not readable or has exited: {exc}"
        try:
            with open(f"/proc/{pid}/mem", "rb"):
                pass
        except OSError as exc:
            return name, f"process {pid} memory is not readable by this user: {exc}"
        return name, None
    try:
        raw = adapter.read_target_file(pid, f"/proc/{pid}/comm", 256)
    except Exception as exc:  # noqa: BLE001
        return None, f"cannot reach target process {pid}: {exc}"
    if not raw:
        return None, f"process {pid} does not exist or is not readable on the target host"
    return raw.decode("utf-8", errors="replace").strip(), None


def _diagnose_check_row(c: Any) -> Dict[str, Any]:
    return {
        "check_id": c.check_id, "recipe_id": c.recipe_id, "name": c.name, "status": str(c.status),
        "duration_s": round(float(getattr(c, "duration_seconds", 0.0) or 0.0), 4),
        "limitations": list(c.limitations or []),
    }


@dataclass
class TargetSpec:
    """Where the target process runs.  The field names are those of ``connect`` / the MCP and web remote
    parameters (``remote_host``, ``ssh_user``, ``ssh_port``, ``ssh_key``, ``ssh_proxy_jump``,
    ``auto_deploy_collector``); ``host`` / ``user`` / ``port`` / ``identity`` are accepted as aliases.
    ``command_runner`` / ``stream_opener`` are injection seams (tests run the "remote" side locally) and are
    never part of the serialised description.  Credentials (key material, key path) never appear in a result."""
    remote_host: Optional[str] = None
    ssh_user: Optional[str] = None
    ssh_port: int = 22
    ssh_key: Optional[str] = None
    ssh_proxy_jump: Optional[str] = None
    auto_deploy_collector: bool = False
    collector_path: Optional[str] = None
    timeout_s: Optional[float] = None
    command_runner: Any = None
    stream_opener: Any = None

    @classmethod
    def from_value(cls, value: Any) -> "TargetSpec":
        if isinstance(value, cls):
            return value
        if not isinstance(value, dict):
            raise ValueError("target must be a TargetSpec or a dict of connection parameters")
        aliases = {"host": "remote_host", "user": "ssh_user", "port": "ssh_port", "identity": "ssh_key",
                   "ssh_key_file": "ssh_key", "key_file": "ssh_key", "proxy_jump": "ssh_proxy_jump"}
        kw: Dict[str, Any] = {}
        for k, v in value.items():
            k = aliases.get(k, k)
            if k not in cls.__dataclass_fields__:
                raise ValueError(f"unknown target parameter '{k}'")
            kw[k] = v
        spec = cls(**kw)
        for f in ("remote_host", "ssh_user", "ssh_key", "ssh_proxy_jump", "collector_path"):
            v = getattr(spec, f)
            setattr(spec, f, v.strip() if isinstance(v, str) and v.strip() else None)
        try:
            spec.ssh_port = int(spec.ssh_port if spec.ssh_port is not None else 22)
        except (TypeError, ValueError):
            raise ValueError("ssh_port must be an integer")
        if not (1 <= spec.ssh_port <= 65535):
            raise ValueError("ssh_port must be in 1..65535")
        spec.auto_deploy_collector = bool(spec.auto_deploy_collector)
        return spec

    def build_adapter(self) -> TargetExecutionAdapter:
        if not self.remote_host:
            raise ValueError("target.remote_host is required for a remote target")
        kw: Dict[str, Any] = {}
        if self.command_runner is not None:
            kw["command_runner"] = self.command_runner
        if self.stream_opener is not None:
            kw["stream_opener"] = self.stream_opener
        if self.timeout_s:
            kw["timeout_sec"] = float(self.timeout_s)
        return RemoteSshTargetAdapter(
            host=self.remote_host, user=self.ssh_user, port=self.ssh_port, key_file=self.ssh_key,
            proxy_jump=self.ssh_proxy_jump, collector_path=self.collector_path, **kw)

    def describe(self) -> Dict[str, Any]:
        """Transport info for the result: host / user / port / jump host; never a key or a key path."""
        return {"transport": "ssh", "host": self.remote_host, "user": self.ssh_user, "port": self.ssh_port,
                "proxy_jump": self.ssh_proxy_jump, "auto_deploy_collector": self.auto_deploy_collector}


def _new_diagnose_result(pid: Any, debug_image: Optional[str]) -> DiagnoseResult:
    res = DiagnoseResult()
    res.collection_impact = {
        "capture_mode": "NOT_RUN", "measured_stop_ms": 0.0, "zero_stop": True, "bytes_read": 0,
        "wall_clock_ms": 0.0, "samples_collected": 0, "budget_exhausted": False,
    }
    res.target = {"pid": pid, "process_name": None, "abi": None, "debug_image": debug_image}
    return res


def diagnose(
    pid: int,
    debug_image: Optional[str] = None,
    symptom: Optional[str] = None,
    *,
    adapter: Optional[TargetExecutionAdapter] = None,
    target: Optional[Any] = None,
    corpus_dir: Optional[str] = None,
    time_limit_s: Optional[float] = None,
    max_steps: Optional[int] = None,
    include_report: bool = False,
    engine: Optional["ExpertDiagnosticEngine"] = None,
    symptom_fields: Any = None,
) -> DiagnoseResult:
    """Diagnose live process ``pid`` end to end in one call and return a :class:`DiagnoseResult`.

    debug_image: ELF with DWARF on THIS host.  Local target: default is the target's own executable
        (/proc/PID/exe).  Remote target: REQUIRED (the matching unstripped ELF); without it the result is
        INCONCLUSIVE with ``missing_debug_image`` in ``not_covered`` (the target's own /proc/PID/exe is
        normally stripped and is not fetched).  A path that does not exist yields an INCONCLUSIVE result.
    symptom: natural-language symptom; default "general health check" (the planner then runs its broad
        recipe set).  adapter: ready target adapter (default local).  time_limit_s: wall-clock observation
        budget (default: 20 s local, 120 s for a remote target, where every read is an SSH round trip).  max_steps: explicit state-machine step cap (default: sized from the plan).
    symptom_fields: optional structured symptom input (``extractor.symptom_interpretation.SymptomFields`` or a dict
        with symptom_kind, symptom_frequency, symptom_duration, affected_area, related_objects).  A given
        symptom_kind decides the investigation plan; the free text ``symptom`` alone behaves as before.  Invalid
        values give an INCONCLUSIVE result with ``invalid_symptom_fields`` in ``not_covered``.
    target: remote target as a :class:`TargetSpec` or dict (``remote_host``, ``ssh_user``, ``ssh_port``,
        ``ssh_key``, ``ssh_proxy_jump``, ``auto_deploy_collector``, ``collector_path``); builds an SSH
        adapter that is closed again when the call ends.  An unreachable host or failed SSH is INCONCLUSIVE
        with ``target_unreachable`` in ``not_covered``.  ``result.target`` carries host/transport, never
        credentials.

    Target-side problems never raise: they produce verdict INCONCLUSIVE with the cause in
    ``not_covered``.  A result is only produced after the session executed to a terminal state; a
    session that only planned yields INCONCLUSIVE and no report.
    """
    t0 = time.monotonic()
    spec: Optional[TargetSpec] = None
    own_adapter: Optional[TargetExecutionAdapter] = None
    pre_nc: List[Dict[str, Any]] = []
    extra_target: Dict[str, Any] = {}

    def _early(kind: str, item: str, reason: str, summary: str) -> DiagnoseResult:
        r = _new_diagnose_result(pid, debug_image)
        r.target.update(extra_target)
        r.not_covered.extend(pre_nc)
        r.not_covered.append({"kind": kind, "item": item, "reason": reason})
        r.summary = summary
        r.healthy_scope = not_healthy_scope(r.not_covered, summary)
        r.duration_s = round(time.monotonic() - t0, 3)
        return r

    try:
        from .symptom_interpretation import SymptomFieldError, parse_symptom_fields
        try:
            symptom_fields = parse_symptom_fields(symptom_fields)
        except SymptomFieldError as exc:
            return _early("invalid_symptom_fields", "symptom fields", str(exc),
                          f"The structured symptom input is invalid: {exc}. No conclusion was reached.")
        if target is not None:
            try:
                spec = TargetSpec.from_value(target)
                extra_target.update(spec.describe())
                if adapter is None:
                    adapter = own_adapter = spec.build_adapter()
            except ValueError as exc:
                return _early("invalid_target", "target", str(exc),
                              f"The remote target description is invalid: {exc}. No conclusion was reached.")
        remote = False
        try:
            remote = bool(adapter is not None and adapter.is_remote())
        except Exception:  # noqa: BLE001
            remote = adapter is not None and not isinstance(adapter, LocalTargetAdapter)
        if remote:
            if not extra_target:
                try:
                    extra_target.update({"transport": "ssh", "host": adapter.target_host()})
                except Exception:  # noqa: BLE001
                    extra_target.update({"transport": "remote"})
            # Reachability first: an SSH/transport failure is "target_unreachable", not "no such process".
            run_ssh = getattr(adapter, "run_ssh", None)
            if callable(run_ssh):
                try:
                    rc, _out, err = run_ssh("true")
                except Exception as exc:  # noqa: BLE001
                    rc, err = -1, f"{type(exc).__name__}: {exc}"
                if rc != 0:
                    why = (err or "").strip().splitlines()[-1:] or [f"ssh exited with {rc}"]
                    return _early("target_unreachable", str(extra_target.get("host") or "remote target"),
                                  f"cannot reach the target over SSH: {why[0]}",
                                  "The remote target could not be reached over SSH, so the process was not diagnosed. "
                                  "No conclusion was reached.")
            if spec is not None and spec.auto_deploy_collector and hasattr(adapter, "ensure_remote_collector"):
                try:
                    info = adapter.ensure_remote_collector()
                except Exception as exc:  # noqa: BLE001
                    info = {"deployed": False, "status": "ERROR", "reason": f"{type(exc).__name__}: {exc}"}
                if isinstance(info, dict):
                    extra_target["collector"] = {k: info.get(k) for k in ("status", "collector_path", "collector_version")}
                if not (isinstance(info, dict) and info.get("collector_path")):
                    pre_nc.append({"kind": "collector_not_deployed", "item": "target collector",
                                   "reason": "the native collector could not be deployed ("
                                             f"{info.get('reason') if isinstance(info, dict) else info}); "
                                             "reads fall back to the slower batched POSIX shell path"})
            elif getattr(adapter, "collector_path", None):
                extra_target["collector"] = {"status": "CONFIGURED", "collector_path": adapter.collector_path}
            if debug_image is None or not str(debug_image).strip():
                return _early("missing_debug_image", "debug_image",
                              "a remote target needs the debug image on this host: provide the matching unstripped "
                              "ELF (with DWARF) of the target program; the target's own /proc/PID/exe is normally "
                              "stripped and is not used as a default",
                              "No debug image was given for the remote target, so it was not diagnosed. Provide the "
                              "matching unstripped ELF. No conclusion was reached.")
        return _diagnose_run(pid, debug_image, symptom, adapter=adapter, corpus_dir=corpus_dir,
                             time_limit_s=time_limit_s, max_steps=max_steps, include_report=include_report,
                             engine=engine, extra_target=extra_target, pre_nc=pre_nc, t0=t0, remote=remote,
                             symptom_fields=symptom_fields)
    finally:
        if own_adapter is not None:
            try:
                own_adapter.close()
            except Exception:  # noqa: BLE001
                pass


REMOTE_DEFAULT_TIME_LIMIT_S = 120.0  # default wall-clock budget of a remote diagnosis
# Default wall-clock budget of a LOCAL diagnosis.  The always-run baseline (thread sampling window, memory trend,
# fd probe, heap integrity, lock/deadlock checks) takes ~2 s idle and up to ~8 s on a loaded 4-vCPU machine; the
# tracker's generic 5 s default cut the baseline short there and turned a real deadlock into INCONCLUSIVE.
LOCAL_DEFAULT_TIME_LIMIT_S = 20.0


def _remote_target_gaps(adapter: Any, already: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """What a REMOTE diagnosis cannot examine (never guessed; always listed in ``not_covered``)."""
    gaps = [
        {"kind": "remote_limitation", "item": "thread_local_storage",
         "reason": "remote TLS/TCB discovery is not implemented: thread-local variables and the per-thread "
                   "struct pthread (tcb_address) are not read on a remote target"},
        {"kind": "remote_limitation", "item": "running_thread_stacks",
         "reason": "a thread that is running in user space at collection time exposes no stack pointer in "
                   "/proc/PID/task/TID/syscall, and nothing is stopped to obtain one: such threads have no "
                   "stack unwound (blocked threads do)"},
        {"kind": "remote_limitation", "item": "library_symbolisation",
         "reason": "shared-library frames are symbolised from images fetched from the target "
                   "over the link (size-capped at 32 MiB, cached per session); a library that cannot be fetched or has "
                   "no symbol table stays unsymbolised and the stack beyond it is labelled estimated"},
    ]
    if not getattr(adapter, "collector_path", None) and not any(n.get("kind") == "collector_not_deployed" for n in already):
        gaps.append({"kind": "remote_limitation", "item": "target_collector",
                     "reason": "no native collector is configured on the target: memory and thread reads use the "
                               "slower batched POSIX shell path (pass auto_deploy_collector / collector_path)"})
    return gaps


def _diagnose_run(
    pid: int,
    debug_image: Optional[str],
    symptom: Optional[str],
    *,
    adapter: Optional[TargetExecutionAdapter],
    corpus_dir: Optional[str],
    time_limit_s: Optional[float],
    max_steps: Optional[int],
    include_report: bool,
    engine: Optional["ExpertDiagnosticEngine"],
    extra_target: Dict[str, Any],
    pre_nc: List[Dict[str, Any]],
    t0: float,
    remote: bool,
    symptom_fields: Any = None,
) -> DiagnoseResult:
    res = _new_diagnose_result(pid, debug_image)
    res.target.update(extra_target)
    nc = res.not_covered
    nc.extend(pre_nc)

    def _finish(summary: str) -> DiagnoseResult:
        res.summary = summary
        if not res.healthy_scope:
            res.healthy_scope = not_healthy_scope(nc, summary)
        res.duration_s = round(time.monotonic() - t0, 3)
        return res

    try:
        adapter = adapter or LocalTargetAdapter()
        name, bad = _preflight_target(pid, adapter)
        res.target["process_name"] = name
        if bad:
            nc.append({"kind": "target_unreadable", "item": f"pid {pid}", "reason": bad})
            return _finish(f"The process could not be examined: {bad}. No conclusion was reached.")
        pid = int(pid)
        res.target["pid"] = pid
        if debug_image is None and isinstance(adapter, LocalTargetAdapter):
            debug_image = f"/proc/{pid}/exe"
        res.target["debug_image"] = debug_image
        if (isinstance(adapter, LocalTargetAdapter) or remote) and (not debug_image or not os.path.exists(debug_image)):
            nc.append({"kind": "missing_debug_image", "item": str(debug_image),
                       "reason": "debug image does not exist; symbol-level diagnosis is impossible"})
            return _finish("The debug image was not found, so the process was not diagnosed. No conclusion was reached.")
        try:
            from .target_abi import detect_target_abi, abi_support_summary
            abi = detect_target_abi(adapter, pid, probe_version=False)
            res.target["abi"] = abi.to_dict()
            for feat, dec in abi_support_summary(abi).items():
                if dec.get("status") != "SUPPORTED":
                    nc.append({"kind": "unsupported_on_target", "item": feat,
                               "reason": f"{dec.get('status')}: {dec.get('message')}"})
        except Exception as exc:  # noqa: BLE001
            nc.append({"kind": "abi_detection_failed", "item": "target ABI", "reason": f"{type(exc).__name__}: {exc}"})

        if remote:
            nc.extend(_remote_target_gaps(adapter, pre_nc))

        engine = engine or ExpertDiagnosticEngine(corpus_dir=corpus_dir)
        limits = ObservationBudgetLimits(max_wall_clock_ms=float(time_limit_s) * 1000.0) if time_limit_s else None
        if limits is None and remote:
            # every sample costs SSH round trips (about 0.5 s each on the slow QEMU guest): the local 5 s default
            # exhausts before the baseline checks ran.  An explicit time_limit_s is always honoured.
            limits = ObservationBudgetLimits(max_wall_clock_ms=REMOTE_DEFAULT_TIME_LIMIT_S * 1000.0)
        elif limits is None:
            limits = ObservationBudgetLimits(max_wall_clock_ms=LOCAL_DEFAULT_TIME_LIMIT_S * 1000.0)
        # IMP-020: bracket the whole collection with the target-load meter (never raises; unmeasured -> None).
        from .collection_impact import CollectionImpactMeter, impact_summary_for_report
        meter = CollectionImpactMeter(adapter, pid).start()
        session = None
        stage = "start_investigation"
        try:
            session = engine.start_investigation(
                problem_statement=symptom or ("" if symptom_fields else DIAGNOSE_DEFAULT_SYMPTOM),
                pid=pid, companion_elf=debug_image, adapter=adapter, budget_limits=limits,
                symptom_fields=symptom_fields,
            )
            res.investigation_id = session.investigation_id
            if getattr(session, "budget_tracker", None) is not None:
                session.budget_tracker.attach_target_cpu_probe(meter.attributable_cpu_ms)
            stage = "run_to_completion"
            conclusion = session.run_to_completion(max_steps=max_steps)
        except Exception as exc:  # noqa: BLE001
            nc.append({"kind": "stage_failed", "item": stage, "reason": f"{type(exc).__name__}: {exc}"})
            if session is not None:
                res.state = session.state
                res.checks_run = [_diagnose_check_row(c) for c in session.checks
                                  if c.status not in (CheckStatus.NOT_EXECUTED, CheckStatus.SKIPPED)]
            return _finish(f"The diagnosis failed during '{stage}' ({type(exc).__name__}). No conclusion was reached.")

        res.state = session.state
        if session.classification_result is not None and session.classification_result.interpretation:
            res.symptom_interpretation = dict(session.classification_result.interpretation)
        res.stop_reason = conclusion.stop_reason if conclusion else None
        executed = [c for c in session.checks if c.status not in (CheckStatus.NOT_EXECUTED, CheckStatus.SKIPPED)]
        res.checks_run = [_diagnose_check_row(c) for c in executed]
        # Baseline checks that never ran (budget / time limit / step cap) must be visible, with the reason
        ran = {c.recipe_id for c in executed}
        why_stopped = res.stop_reason or session.state
        for st in (session.plan.steps if session.plan else []):
            if st.recipe_id in BASELINE_RECIPE_IDS and st.recipe_id not in ran:
                nc.append({"kind": "baseline_check_not_run", "item": st.recipe_id,
                           "reason": f"baseline check not executed: investigation ended with {why_stopped}"
                                     f" (step status {st.status})"})
        if session.state not in TERMINAL_STATES or not executed:
            nc.append({"kind": "not_executed", "item": "investigation",
                       "reason": f"session ended in state {session.state} with {len(executed)} executed check(s); "
                                 "a planned-only investigation produces no report"})
            return _finish("The investigation was planned but no check was executed, so no conclusion was reached.")

        stage = "build_diagnostic_report"
        try:
            report = session.build_diagnostic_report().to_dict()
        except Exception as exc:  # noqa: BLE001
            nc.append({"kind": "stage_failed", "item": stage, "reason": f"{type(exc).__name__}: {exc}"})
            return _finish("The checks ran but the report could not be built. No conclusion was reached.")

        sec_a = report.get("section_a_executive_summary", {})
        sec_b = report.get("section_b_target_context", {})
        res.verdict = str(sec_a.get("overall_result") or "INCONCLUSIVE")
        res.confidence = float(getattr(conclusion, "confidence", 0.0) or 0.0)
        res.confidence_basis = str(getattr(conclusion, "confidence_basis", "") or "")

        sec_e = report.get("section_e_findings_and_root_cause", {})
        for rec in list(sec_e.get("confirmed_root_causes", [])) + list(sec_e.get("probable_causes", [])):
            rules = list(rec.get("applicable_diagnostic_rules") or [])
            details = _finding_subjects(session, rules)
            res.findings.append({
                "category": rec.get("affected_entity"),
                "severity": rec.get("severity"),
                "status": rec.get("classification"),
                "description": rec.get("problem_description"),
                "subjects": [d["name"] for d in details],
                "subject_details": details,
                "recipe_ids": rules,
                "evidence_ids": list(rec.get("supporting_evidence_ids") or []),
                # IMP-018: what the failing checks observed (e.g. the fd-count trend), verbatim
                "observed": [c.technical_interpretation for c in session.checks
                             if c.recipe_id in rules and c.status == CheckStatus.FAIL and c.technical_interpretation],
            })

        # A confirmed finding must name its subject (lock / thread / variable / function); one that names nothing
        # is an unattributed observation and is downgraded.
        for f in res.findings:
            if f["status"] == "CONFIRMED_ROOT_CAUSE" and not f["subjects"]:
                f["status"] = "PROBABLE_CAUSE"
                nc.append({"kind": "unattributed_finding", "item": str(f["category"]),
                           "reason": "the finding named no lock, thread, variable or function, so it was not confirmed"})
        if res.verdict == "CONFIRMED_FAULT" and not any(f["status"] == "CONFIRMED_ROOT_CAUSE" for f in res.findings):
            res.verdict = "PROBABLE_FAULT" if res.findings else "INCONCLUSIVE"
        # Findings that are all INFO (a degradation the rule marked as not a fault, e.g. heap retention) never
        # make a fault verdict: DEGRADED (aggregator vocabulary; never HEALTHY either, since there is a finding).
        if res.findings and res.verdict in ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT") \
                and all(f.get("severity") == "INFO" for f in res.findings):
            res.verdict = "DEGRADED"
            sec_a["overall_result"] = res.verdict
            sec_a["verdict_rationale"] = ("No fault was found; the finding(s) describe a degradation, not a fault: "
                                          + ", ".join(dict.fromkeys(str(f["category"]) for f in res.findings)) + ".")

        # IMP-008: the leak-owner part (heap walks) could not be done / completed on this target
        leak_nc_seen = set()
        for c in session.checks:
            li = (c.actual_observations or {}).get("leak_investigation") if isinstance(c.actual_observations, dict) else None
            if isinstance(li, dict) and li.get("status") in ("UNSUPPORTED", "LIMITED"):
                why = "; ".join(str(x) for x in (li.get("limitations") or [])) or str(li.get("status"))
                if why not in leak_nc_seen:
                    leak_nc_seen.add(why)
                    nc.append({"kind": "unsupported_on_target" if li["status"] == "UNSUPPORTED" else "leak_owner_limited",
                               "item": "leak_owner_attribution",
                               "reason": ("not supported on this target: " if li["status"] == "UNSUPPORTED" else "")
                               + why})
        # IMP-009: what the memory-integrity check could not examine (heap above the baseline cap, unsupported
        # allocator, no DWARF for the global check, ...)
        mi_seen = set()
        for c in session.checks:
            mi = (c.actual_observations or {}).get("memory_integrity") if isinstance(c.actual_observations, dict) else None
            if not isinstance(mi, dict):
                continue
            for why in mi.get("limitations") or []:
                if why in mi_seen:
                    continue
                mi_seen.add(why)
                kind = "unsupported_on_target" if "not supported on this target" in why else (
                    "integrity_not_checked" if "not checked" in why else "integrity_limited")
                nc.append({"kind": kind, "item": "memory_integrity", "reason": str(why)})
        # DEF-ARM-1: a lock check that could not run because mutex owners cannot be decoded on this target
        lock_nc_seen = set()
        lock_unsupported_checks = set()
        for c in session.checks:
            ob = c.actual_observations if isinstance(c.actual_observations, dict) else {}
            if ob.get("lock_owner_unsupported") and recipe_requires_lock_owner(c.recipe_id):
                lock_unsupported_checks.add(c.check_id)
                why = ("not supported on this target: lock-owner decoding (%s) %s" % (
                    ob.get("lock_owner_status"), ob.get("lock_owner_status_reason") or "")).strip()
                if why not in lock_nc_seen:
                    lock_nc_seen.add(why)
                    nc.append({"kind": "unsupported_on_target", "item": "lock_owner_decoding", "reason": why})
        for c in session.checks:
            if c.status in (CheckStatus.PASS, CheckStatus.FAIL):
                continue
            if c.check_id in lock_unsupported_checks:
                nc.append({"kind": "unsupported_on_target", "item": c.recipe_id,
                           "reason": "not checked: lock-owner decoding is not supported on this target"})
                continue
            why = "; ".join(list(c.limitations or []) + list(c.missing_evidence or [])) or (c.error_details or "") \
                or (c.technical_interpretation or "")
            nc.append({"kind": f"check_{str(c.status).lower()}", "item": c.recipe_id, "reason": why or str(c.status)})
        for lim in (list(getattr(conclusion, "diagnostic_limitations", []) or [])
                    + list(getattr(conclusion, "missing_evidence_and_unknowns", []) or [])
                    + list(sec_b.get("environmental_limitations") or [])
                    + list(sec_b.get("collection_failures") or [])
                    + list(report.get("section_h_limitations_and_unverified", {}).get("missing_symbols_or_dwarf") or [])):
            nc.append({"kind": "limitation", "item": "engine", "reason": str(lim)})
        _excl_rows = report.get("section_c_diagnostic_strategy", {}).get("recipes_excluded", [])
        excluded = [e.get("recipe_id") for e in _excl_rows if not e.get("unsupported_capability")]
        # Checks this mode cannot execute (declared capability requirement): "not examined", one row per capability.
        for _cap in dict.fromkeys(e["unsupported_capability"] for e in _excl_rows if e.get("unsupported_capability")):
            _ids = [e.get("recipe_id") for e in _excl_rows if e.get("unsupported_capability") == _cap]
            nc.append({"kind": "unsupported_in_mode", "item": ",".join(map(str, _ids)), "capability": _cap,
                       "reason": "not supported in this mode: needs " + CAPABILITY_DESCRIPTIONS.get(_cap, (_cap, _cap))[0]})
        if excluded:
            nc.append({"kind": "recipes_not_planned", "item": ",".join(map(str, excluded)),
                       "reason": "not selected by the planner for this symptom classification"})

        metrics = getattr(session.budget_tracker, "metrics", None)
        exhausted = bool(getattr(metrics, "is_budget_exhausted", False)) or session.state == STATE_BUDGET_EXHAUSTED
        if exhausted:
            nc.append({"kind": "budget_exhausted", "item": "observation budget",
                       "reason": str(getattr(metrics, "exhaustion_reason", None) or res.stop_reason)})

        # HEALTHY rule (extractor.healthy_verdict): every baseline check cleared, nothing blocking -> HEALTHY
        # within the stated scope; otherwise never HEALTHY (an aggregator HEALTHY is re-checked by the same rule).
        nc.extend(long_wait_scope_items(executed))
        res.healthy_scope = evaluate_healthy(
            verdict=res.verdict, findings=res.findings, checks=executed, not_covered=nc,
            baseline_ids=BASELINE_RECIPE_IDS,
            recipe_names={r.recipe_id: r.name for r in DiagnosticRecipeRegistry.list_recipes()})
        if res.healthy_scope["healthy"]:
            res.verdict = VERDICT_HEALTHY
        elif res.verdict == VERDICT_HEALTHY:
            res.verdict = "INCONCLUSIVE"
        if res.verdict in (VERDICT_HEALTHY, "INCONCLUSIVE"):
            sec_a["overall_result"] = res.verdict
            if res.verdict == VERDICT_HEALTHY:
                sec_a["decision_rule_id"] = HEALTHY_RULE_ID
                sec_a["verdict_rationale"] = healthy_summary_sentence(res.healthy_scope, len(BASELINE_RECIPE_IDS))
                sec_a["unresolved_questions"] = []
        report["healthy_scope"] = res.healthy_scope

        stop_ms = float(sec_b.get("target_stop_duration_ms") or 0.0)
        res.collection_impact = {
            "capture_mode": sec_b.get("collection_mode"),
            "measured_stop_ms": stop_ms,
            "zero_stop": stop_ms == 0.0,
            "bytes_read": int(getattr(metrics, "bytes_read", 0) or 0),
            "wall_clock_ms": float(getattr(metrics, "wall_clock_elapsed_ms", 0.0) or 0.0),
            "samples_collected": int(getattr(metrics, "samples_collected", 0) or 0),
            "budget_exhausted": exhausted,
        }
        rec = meter.finish(bytes_read=int(getattr(metrics, "bytes_read", 0) or 0), measured_stop_ms=stop_ms)
        res.collection_impact.update(impact_summary_for_report(
            rec, capture_mode=sec_b.get("collection_mode"), measured_stop_ms=stop_ms,
            bytes_read=int(getattr(metrics, "bytes_read", 0) or 0), budget_exhausted=exhausted,
            exhaustion_reason=getattr(metrics, "exhaustion_reason", None)))

        try:
            rep_dir = os.path.join(engine.corpus_dir, "reports")
            os.makedirs(rep_dir, exist_ok=True)
            path = os.path.join(rep_dir, f"{session.investigation_id}.report.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(report, fh, default=str)
            res.report_path = path
        except OSError as exc:
            nc.append({"kind": "report_not_saved", "item": "report", "reason": str(exc)})
        if include_report:
            res.report = json.loads(json.dumps(report, default=str))

        passed = sum(1 for r in res.checks_run if r["status"] == CheckStatus.PASS)
        if res.verdict == VERDICT_HEALTHY:
            return _finish(f"Verdict HEALTHY: {healthy_summary_sentence(res.healthy_scope, len(BASELINE_RECIPE_IDS))}"
                           f" {passed} of {len(res.checks_run)} executed checks passed (see healthy_scope).")
        if res.findings:
            cats = ", ".join(dict.fromkeys(str(f["category"]) for f in res.findings))
            head = f"Verdict {res.verdict}: found {cats}."
        else:
            head = f"Verdict {res.verdict}: no problem finding was produced."
        return _finish(f"{head} {passed} of {len(res.checks_run)} executed checks passed; "
                       f"{len(nc)} item(s) could not be examined (see not_covered).")
    except Exception as exc:  # noqa: BLE001 - diagnose must not raise for target-side problems
        res.verdict = "INCONCLUSIVE"
        res.healthy_scope = {}  # recomputed by _finish: never healthy
        nc.append({"kind": "unexpected_error", "item": "diagnose", "reason": f"{type(exc).__name__}: {exc}"})
        return _finish(f"The diagnosis failed unexpectedly ({type(exc).__name__}). No conclusion was reached.")
