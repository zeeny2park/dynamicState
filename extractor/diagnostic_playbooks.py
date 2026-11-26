"""Problem-specific Diagnostic Playbooks & Front-Door Router (pstack-inspired).

Provides:
- 6 structured diagnostic playbooks covering memory leaks/large heaps, heap corruption/UAF/double-free,
  hangs/deadlocks/lock contention, FD/IPC stalls, variable/state corruption, and intermittent temporal bugs.
- A single front-door router (`select_playbook`) that routes a symptom or an initial diagnose result
  to the best matching playbook with a strict checkable Exit Predicate, ordered step checklist,
  Plateau -> Pivot rules, and explicit Escape Hatch stop conditions.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class PlaybookStep:
    step: int
    tier: str
    tool: str
    cli_hint: str
    purpose_en: str
    purpose_ko: str
    expected_evidence: str


@dataclass(frozen=True)
class PivotRule:
    when: str
    pivot_to_tool: str
    pivot_reason_en: str
    pivot_reason_ko: str


@dataclass(frozen=True)
class DiagnosticPlaybook:
    playbook_id: str
    title_en: str
    title_ko: str
    symptom_keywords: List[str]
    recipe_prefixes: List[str]
    exit_predicate_en: str
    exit_predicate_ko: str
    default_max_iterations: int
    steps: List[PlaybookStep]
    pivot_rules: List[PivotRule]
    stop_conditions: List[str]
    markdown_file: str = ""

    def to_dict(self, lang: str = "en") -> Dict[str, Any]:
        ko = lang == "ko"
        return {
            "playbook_id": self.playbook_id,
            "title": self.title_ko if ko else self.title_en,
            "title_en": self.title_en,
            "title_ko": self.title_ko,
            "exit_predicate": self.exit_predicate_ko if ko else self.exit_predicate_en,
            "exit_predicate_en": self.exit_predicate_en,
            "exit_predicate_ko": self.exit_predicate_ko,
            "default_max_iterations": self.default_max_iterations,
            "steps": [
                {
                    "step": st.step,
                    "tier": st.tier,
                    "tool": st.tool,
                    "cli_hint": st.cli_hint,
                    "purpose": st.purpose_ko if ko else st.purpose_en,
                    "expected_evidence": st.expected_evidence,
                }
                for st in self.steps
            ],
            "pivot_rules": [
                {
                    "when": pr.when,
                    "pivot_to_tool": pr.pivot_to_tool,
                    "reason": pr.pivot_reason_ko if ko else pr.pivot_reason_en,
                }
                for pr in self.pivot_rules
            ],
            "stop_conditions": list(self.stop_conditions),
            "markdown_file": self.markdown_file,
        }


PLAYBOOKS: Dict[str, DiagnosticPlaybook] = {
    "memory-leak-and-growth": DiagnosticPlaybook(
        playbook_id="memory-leak-and-growth",
        title_en="Memory Leak, RSS Growth & Large-Heap Attribution",
        title_ko="메모리 누수·RSS 증가 및 대형 힙 원인 추적",
        symptom_keywords=[
            "leak", "memory", "rss", "oom", "heap", "growth", "retention", "mmap",
            "메모리", "누수", "힙", "증가", "증폭", "단편화",
        ],
        recipe_prefixes=[
            "RECIPE_PROCESS_MEMORY_GROWTH", "RECIPE_HEAP_GROWTH", "RECIPE_ALLOCATION_FREE_IMBALANCE",
            "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION", "RECIPE_REPEATED_ALLOCATION_PATTERNS",
            "RECIPE_HEAP_RETENTION", "RECIPE_MAPPING_GROWTH", "RECIPE_OBJECT_LIFETIME_ANOMALIES",
        ],
        exit_predicate_en=(
            "Root cause confirmed with owning variable/container path (or unreachable size class + code anchor), "
            "OR sustained growth refuted across >=2 time-separated observations."
        ),
        exit_predicate_ko=(
            "소유 변수·컨테이너 경로(또는 미참조 청크 크기 클래스 + 코드 앵커)가 특정되거나, "
            "2회 이상 시차 관측에서 지속적 증가가 없음을 반증할 때 종료."
        ),
        default_max_iterations=6,
        steps=[
            PlaybookStep(
                1, "TIER0_ENTRY", "runtime_diagnose_process",
                "dynamic-state diagnose -p <pid> -d <elf> --symptom 'memory leak'",
                "Run baseline diagnosis + Tier-2 bounded sampling on large heaps (>50MB).",
                "기본 진단 및 대형 힙(>50MB) Tier-2 단계별 샘플링을 수행합니다.",
                "verdict, memory_integrity.heap.sampling_tier, inconclusive_drilldown",
            ),
            PlaybookStep(
                2, "TIER1_NARROWING", "runtime_heap_leak_candidates",
                "dynamic-state heap-leaks -p <pid> -d <elf>",
                "Identify top unreachable or growing glibc chunk size classes and sample addresses.",
                "미참조·증가 중인 상위 힙 청크 크기 클래스와 샘플 주소를 추출합니다.",
                "candidate size classes and hex addresses",
            ),
            PlaybookStep(
                3, "TIER2_DEEP_INSPECT", "runtime_heap_owner_lookup",
                "dynamic-state heap-owner -p <pid> -d <elf> <addr>",
                "Reverse-lookup owning globals/containers retaining the candidate addresses.",
                "후보 주소를 붙잡고 있는 전역 변수·컨테이너 소유 경로를 역추적합니다.",
                "variable_path, root_kind, decl_file:decl_line",
            ),
            PlaybookStep(
                4, "TIER2_DEEP_INSPECT", "runtime_eval_memory_path",
                "dynamic-state eval -p <pid> -d <elf> --expr <owner_path>",
                "Inspect live size, capacity, and retention fields of the owning container.",
                "소유 컨테이너의 실시간 크기·용량·보유 상태를 직접 조회합니다.",
                "live container size/capacity values",
            ),
            PlaybookStep(
                5, "TIER2_DEEP_INSPECT", "runtime_correlate_source_and_state",
                "dynamic-state correlate-source -p <pid> -d <elf>",
                "Bridge confirmed runtime ownership to exact source file:line for fixing.",
                "확인된 런타임 소유 구조를 실제 소스 코드 file:line 위치로 연결합니다.",
                "code_anchors (file:line, function, variable_path)",
            ),
        ],
        pivot_rules=[
            PivotRule(
                "heap_leak_candidates returns 0 unreachable blocks",
                "runtime_scan_heap_objects",
                "Growth may live in reachable C++ containers or custom pools; pivot to vtable object census.",
                "미참조 블록이 없으므로 도달 가능한 C++ 컨테이너 누적·커스텀 풀 확인을 위해 vtable 스캔으로 피벗합니다.",
            ),
            PivotRule(
                "2 consecutive iterations show no delta or non-monotonic RSS",
                "runtime_capture_and_diff",
                "Escalate to a 5s before/after temporal diff or condition watch to capture slow growth.",
                "2회 연속 진전이 없으므로 5초 전후 비교 캡처 또는 조건 감시로 시간축 추적을 승격합니다.",
            ),
        ],
        stop_conditions=[
            "MET: owning container/variable path + code_anchors confirmed, or growth refuted",
            "BLOCKED: target_unreadable / process_exited",
            "EXHAUSTED: max_iterations reached (emit decision_log + remaining open leads)",
        ],
        markdown_file="skills/diagnose-process/playbooks/memory-leak-and-growth.md",
    ),
    "heap-corruption-and-uaf": DiagnosticPlaybook(
        playbook_id="heap-corruption-and-uaf",
        title_en="Heap Metadata Corruption, Double-Free & Use-After-Free",
        title_ko="힙 메타데이터 손상·이중 해제·Use-After-Free 추적",
        symptom_keywords=[
            "corrupt", "uaf", "use-after-free", "double free", "double-free", "invalid free",
            "segfault", "sigsegv", "sigabrt", "tcache", "fastbin", "손상", "이중 해제", "크래시",
        ],
        recipe_prefixes=[
            "RECIPE_HEAP_METADATA_CORRUPTION", "RECIPE_DOUBLE_FREE", "RECIPE_FREED_MEMORY_USE",
            "RECIPE_USE_AFTER_FREE", "RECIPE_INVALID_FREE", "RECIPE_INVALID_MEMORY_ACCESS",
        ],
        exit_predicate_en=(
            "Corrupted chunk/free-list/dangling pointer identified with owning variable or symbol anchor, "
            "OR full/Tier-2 integrity checks confirm no active corruption."
        ),
        exit_predicate_ko=(
            "손상된 청크·프리리스트·댕글링 포인터와 소유 변수/심볼 앵커가 특정되거나, "
            "무결성 검사에서 활성 손상이 없음을 확인할 때 종료."
        ),
        default_max_iterations=6,
        steps=[
            PlaybookStep(
                1, "TIER0_ENTRY", "runtime_diagnose_process",
                "dynamic-state diagnose -p <pid> -d <elf> --symptom 'heap corruption'",
                "Run memory integrity + Tier-2 tcache/fastbin cycle & UAF sampling.",
                "메모리 무결성 검사 및 대형 힙 Tier-2 tcache/fastbin 사이클·UAF 샘플링을 실행합니다.",
                "heap defects, SAMPLED_DEFECTS_FOUND or PARTIAL_SAMPLED",
            ),
            PlaybookStep(
                2, "TIER1_NARROWING", "runtime_audit_memory_integrity",
                "dynamic-state audit -p <pid> -d <elf>",
                "Audit DWARF pointers, sentinel values, and pool headers for corruption.",
                "DWARF 포인터·센티넬·풀 헤더의 무결성을 정밀 감사합니다.",
                "corrupted pointer/header addresses",
            ),
            PlaybookStep(
                3, "TIER2_DEEP_INSPECT", "runtime_heap_owner_lookup",
                "dynamic-state heap-owner -p <pid> -d <elf> <corrupt_addr>",
                "Find the variable or buffer adjacent to or referencing the damaged chunk.",
                "손상된 청크를 참조하거나 인접한 버퍼의 소유 변수를 역추적합니다.",
                "owning variable_path and referrer root",
            ),
            PlaybookStep(
                4, "TIER2_DEEP_INSPECT", "runtime_correlate_source_and_state",
                "dynamic-state correlate-source -p <pid> -d <elf>",
                "Map the owning pointer/buffer to exact source file:line allocation/free sites.",
                "소유 포인터·버퍼를 소스 코드의 할당/해제 위치(file:line)로 연결합니다.",
                "code_anchors for fix & ASan reproduction",
            ),
        ],
        pivot_rules=[
            PivotRule(
                "Tier-2 sampling clean (PARTIAL_SAMPLED) but corruption still suspected",
                "runtime_symbol_search",
                "Locate suspect pool/buffer globals by name and inspect them directly with runtime_eval_memory_path.",
                "Tier-2 샘플링에서 이상이 없으나 손상이 의심되면 의심 풀·버퍼 심볼을 검색해 직접 조회합니다.",
            ),
            PivotRule(
                "Symbol search returns 0 hits",
                "runtime_scan_heap_objects",
                "Pivot to vtable-based C++ object scan or fast_only=True symtab lookup.",
                "심볼 검색 결과가 없으면 vtable 스캔 또는 fast_only=True 심볼표 검색으로 피벗합니다.",
            ),
        ],
        stop_conditions=[
            "MET: damaged chunk/pointer + owner + code_anchors confirmed",
            "BLOCKED: target_unreadable / process_exited",
            "EXHAUSTED: max_iterations reached",
        ],
        markdown_file="skills/diagnose-process/playbooks/heap-corruption-and-uaf.md",
    ),
    "hang-deadlock-and-contention": DiagnosticPlaybook(
        playbook_id="hang-deadlock-and-contention",
        title_en="Process Hang, Deadlock, Lock Contention & Thread Leak",
        title_ko="프로세스 행·데드락·락 경합 및 스레드 누수 추적",
        symptom_keywords=[
            "hang", "hung", "stuck", "deadlock", "mutex", "lock", "futex", "contention",
            "thread leak", "thread", "blocked", "slow", "stall", "행", "멈춤", "교착", "데드락", "락", "스레드", "지연",
        ],
        recipe_prefixes=[
            "RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "RECIPE_LOCK_CONTENTION", "RECIPE_ORPHAN_LOCK",
            "RECIPE_SELF_DEADLOCK", "RECIPE_LONG_RUNNING_BLOCKED_THREADS",
            "RECIPE_THREAD_STATE_ANOMALIES", "RECIPE_THREAD_LEAK", "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP",
        ],
        exit_predicate_en=(
            "Blocking lock/owner cycle or stalled thread frame confirmed across >=2 observations (stuck delta > 0s) "
            "with source file:line anchor, OR all threads confirmed progressing normally."
        ),
        exit_predicate_ko=(
            "2회 이상 관측에서 동일 락·프레임에 고정된 스레드(stuck delta)와 소유자 체인·소스 위치가 확정되거나, "
            "모든 스레드가 정상 진행 중임을 확인할 때 종료."
        ),
        default_max_iterations=6,
        steps=[
            PlaybookStep(
                1, "TIER0_ENTRY", "runtime_diagnose_process",
                "dynamic-state diagnose -p <pid> -d <elf> --symptom 'process hang / deadlock'",
                "Run baseline diagnosis to classify thread states, lock waits, and liveness.",
                "기본 진단으로 스레드 상태·락 대기·활동성(liveness)을 분류합니다.",
                "liveness status, waiting TIDs, inconclusive_drilldown",
            ),
            PlaybookStep(
                2, "TIER1_NARROWING", "runtime_inspect_thread_callstack_and_locks",
                "dynamic-state callstacks -p <pid> -d <elf>",
                "Capture exact per-thread call stacks, blocking syscalls, and mutex owner/waiter edges.",
                "스레드별 콜스택·차단 시스템콜·뮤텍스 소유/대기 관계를 조회합니다.",
                "waiting TIDs, lock addresses, top source frames",
            ),
            PlaybookStep(
                3, "TIER1_NARROWING", "runtime_build_dependency_graph",
                "dynamic-state dependency-graph -p <pid> -d <elf>",
                "Synthesize cross-thread/lock/IPC dependency graph to isolate root blocker nodes.",
                "스레드·락·IPC 의존성 그래프를 생성해 근본 차단 노드를 분리합니다.",
                "root_blocker_nodes and causal_chains",
            ),
            PlaybookStep(
                4, "TIER2_DEEP_INSPECT", "runtime_correlate_source_and_state",
                "dynamic-state correlate-source -p <pid> -d <elf>",
                "Map root-blocker frames and mutex symbols to exact repository file:line.",
                "근본 차단 프레임과 뮤텍스 심볼을 실제 소스 파일 위치로 연결합니다.",
                "code_anchors for lock acquisition/release sites",
            ),
        ],
        pivot_rules=[
            PivotRule(
                "Threads are blocked in epoll_wait/read/recv/poll rather than futex",
                "runtime_trace_ipc_pipeline",
                "Stall is external I/O or IPC peer backpressure; pivot to IPC pipeline trace.",
                "futex가 아닌 I/O 시스템콜 대기이므로 외부 피어·IPC 병목 확인을 위해 IPC 파이프라인 추적으로 피벗합니다.",
            ),
            PivotRule(
                "Single callstack snapshot cannot distinguish transient contention from permanent stall",
                "runtime_inspect_thread_callstack_and_locks",
                "Re-sample callstacks after a few seconds and inspect delta_from_last_call.stuck_threads.",
                "잠시 후 콜스택을 재조회해 delta_from_last_call.stuck_threads로 영구 정체 vs 정상 경합을 구분합니다.",
            ),
        ],
        stop_conditions=[
            "MET: root blocker TID/lock + code_anchors confirmed, or threads confirmed progressing",
            "BLOCKED: target_unreadable / process_exited",
            "EXHAUSTED: max_iterations reached",
        ],
        markdown_file="skills/diagnose-process/playbooks/hang-deadlock-and-contention.md",
    ),
    "fd-and-ipc-stall": DiagnosticPlaybook(
        playbook_id="fd-and-ipc-stall",
        title_en="File Descriptor Leak & IPC / Socket / Shared-Memory Stall",
        title_ko="파일 디스크립터(FD) 누수 및 IPC·소켓·공유메모리 병목 추적",
        symptom_keywords=[
            "fd leak", "fd", "file descriptor", "emfile", "socket", "pipe", "ipc", "shm", "shared memory",
            "backlog", "network", "파일 디스크립터", "소켓", "파이프", "공유메모리", "통신",
        ],
        recipe_prefixes=["RECIPE_FD_LEAK"],
        exit_predicate_en=(
            "Leaking FD target or stalled IPC peer/backlog identified with owning call stack/code anchor, "
            "OR FD count and IPC peers confirmed stable."
        ),
        exit_predicate_ko=(
            "누수 중인 FD 유형 또는 정체된 IPC 피어·백로그와 호출 스택/코드 앵커가 특정되거나, "
            "FD 수와 IPC 상태가 정상임을 확인할 때 종료."
        ),
        default_max_iterations=5,
        steps=[
            PlaybookStep(
                1, "TIER0_ENTRY", "runtime_diagnose_process",
                "dynamic-state diagnose -p <pid> -d <elf> --symptom 'fd leak / ipc stall'",
                "Measure FD trend, limits, and top newly opened descriptor targets.",
                "FD 증가 추세, 한도(rlimit), 신규 디스크립터 타깃을 확인합니다.",
                "fd_count_trend, new_fd_targets",
            ),
            PlaybookStep(
                2, "TIER1_NARROWING", "runtime_trace_ipc_pipeline",
                "dynamic-state ipc-pipeline -p <pid> -d <elf>",
                "Trace sockets, pipes, shared memory rings, backlog utilization, and peer PIDs.",
                "소켓·파이프·공유메모리 링 백로그와 연결된 피어 프로세스를 추적합니다.",
                "peer_processes, pending_backlog, shm_regions",
            ),
            PlaybookStep(
                3, "TIER1_NARROWING", "runtime_inspect_thread_callstack_and_locks",
                "dynamic-state callstacks -p <pid> -d <elf>",
                "Correlate blocked I/O descriptors with active thread stack frames.",
                "차단된 I/O 디스크립터와 스레드 콜스택을 대조합니다.",
                "source frames of read/write/accept/open sites",
            ),
        ],
        pivot_rules=[
            PivotRule(
                "FD growth is non-monotonic in a short window",
                "runtime_watch_until_condition",
                "Arm a condition watch on open_fds growth or run runtime_capture_and_diff over a longer window.",
                "단기 창에서 FD 변화가 비단조이므로 open_fds 조건 감시 또는 전후 비교 캡처로 피벗합니다.",
            ),
        ],
        stop_conditions=[
            "MET: leaking FD/stalled peer + code_anchors confirmed",
            "BLOCKED: target_unreadable / process_exited",
            "EXHAUSTED: max_iterations reached",
        ],
        markdown_file="skills/diagnose-process/playbooks/fd-and-ipc-stall.md",
    ),
    "state-and-variable-bug": DiagnosticPlaybook(
        playbook_id="state-and-variable-bug",
        title_en="Unexpected Variable Mutation, State Machine & Pointer Anomaly",
        title_ko="변수 값 이상·상태 머신 위반·널/무효 포인터 추적",
        symptom_keywords=[
            "variable", "state", "flag", "counter", "null", "pointer", "boundary", "invariant",
            "race", "wrong value", "변수", "상태", "포인터", "경계", "데이터 레이스",
        ],
        recipe_prefixes=[
            "RECIPE_UNEXPECTED_VARIABLE_CHANGES", "RECIPE_STATE_TRANSITION_VIOLATIONS",
            "RECIPE_INCONSISTENT_RELATED_VARIABLES", "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS",
            "RECIPE_SUSPICIOUS_BOUNDARY_VALUES", "RECIPE_SHARED_STATE_INCONSISTENCIES",
        ],
        exit_predicate_en=(
            "Target symbol values evaluated directly in live memory and correlated to source file:line, "
            "confirming or refuting the invariant violation."
        ),
        exit_predicate_ko=(
            "대상 심볼의 실시간 메모리 값을 직접 조회해 소스 코드 위치와 대조하고, "
            "불변식 위반 여부를 확정 또는 반증할 때 종료."
        ),
        default_max_iterations=5,
        steps=[
            PlaybookStep(
                1, "TIER2_DEEP_INSPECT", "runtime_symbol_search",
                "dynamic-state symbol-search -d <elf> --query '<keyword>'",
                "Discover exact DWARF symbol names for the suspect state struct, flag, or counter.",
                "의심 상태 구조체·플래그·카운터의 정확한 DWARF 심볼명을 검색합니다.",
                "matched symbol names and decl_file:decl_line",
            ),
            PlaybookStep(
                2, "TIER2_DEEP_INSPECT", "runtime_eval_memory_path",
                "dynamic-state eval -p <pid> -d <elf> --expr '<sym>'",
                "Read live values of the matched symbols with 0ms process stop.",
                "프로세스 중단 없이 검색된 심볼의 실시간 메모리 값을 조회합니다.",
                "live field values and pointer validity",
            ),
            PlaybookStep(
                3, "TIER3_TEMPORAL_WATCH", "runtime_capture_and_diff",
                "dynamic-state diff -p <pid> -d <elf> --expr '<sym>' --wait-ms 3000",
                "Sample the expression twice to verify whether it is mutating unexpectedly or stuck.",
                "표현식을 시차를 두고 2회 샘플링해 비정상 변이인지 정체인지 확인합니다.",
                "changed vs unchanged struct fields",
            ),
            PlaybookStep(
                4, "TIER2_DEEP_INSPECT", "runtime_correlate_source_and_state",
                "dynamic-state correlate-source -p <pid> -d <elf>",
                "Bind the live anomaly to exact source lines for code review and patching.",
                "관측된 상태 이상을 소스 코드 라인과 연결해 수정 지점을 특정합니다.",
                "code_anchors",
            ),
        ],
        pivot_rules=[
            PivotRule(
                "runtime_symbol_search returns 0 hits",
                "runtime_symbol_search",
                "Retry with fast_only=True ELF symtab and shorter root token, or pivot to runtime_scan_heap_objects.",
                "심볼 검색이 0건이면 fast_only=True 심볼표 재검색 또는 runtime_scan_heap_objects로 피벗합니다.",
            ),
            PivotRule(
                "runtime_eval_memory_path fails on expression syntax",
                "runtime_coerce_expression",
                "Normalize the pointer/member path via runtime_coerce_expression and re-evaluate.",
                "표현식 평가가 실패하면 runtime_coerce_expression으로 경로를 정규화한 뒤 재조회합니다.",
            ),
        ],
        stop_conditions=[
            "MET: symbol values verified + code_anchors extracted",
            "BLOCKED: missing_debug_image with no symtab / target_unreadable",
            "EXHAUSTED: max_iterations reached",
        ],
        markdown_file="skills/diagnose-process/playbooks/state-and-variable-bug.md",
    ),
    "intermittent-temporal-bug": DiagnosticPlaybook(
        playbook_id="intermittent-temporal-bug",
        title_en="Intermittent, Load-Dependent & Short-Window Inconclusive Bug",
        title_ko="간헐적·부하 의존·단기 관측 판정 불가 문제 추적",
        symptom_keywords=[
            "intermittent", "flaky", "spike", "periodic", "sometimes", "load", "inconclusive",
            "간헐", "가끔", "스파이크", "부하", "재현", "판정 불가",
        ],
        recipe_prefixes=[],
        exit_predicate_en=(
            "Condition-triggered capture or before/after diff catches the anomaly window with concrete delta "
            "and source-code anchors, OR observation window expires with documented baseline telemetry."
        ),
        exit_predicate_ko=(
            "조건 감시 또는 전후 비교 캡처로 이상 발생 순간의 변화량과 코드 앵커를 포착하거나, "
            "관측 시간 만료 시 기준 텔레메트리를 기록하고 종료."
        ),
        default_max_iterations=5,
        steps=[
            PlaybookStep(
                1, "TIER0_ENTRY", "runtime_explain_process_behavior",
                "dynamic-state explain -p <pid> -d <elf>",
                "Establish baseline subsystem behavior and candidate metrics to monitor.",
                "기준 서브시스템 동작과 감시 대상 메트릭을 설정합니다.",
                "baseline RSS, FDs, threads, active subsystems",
            ),
            PlaybookStep(
                2, "TIER3_TEMPORAL_WATCH", "runtime_capture_and_diff",
                "dynamic-state diff -p <pid> -d <elf> --wait-ms 5000",
                "Capture a 5s before/after delta during workload activity.",
                "부하 중 5초 간격 전후 비교 캡처로 변화량을 확인합니다.",
                "changed metrics/expressions over 5s",
            ),
            PlaybookStep(
                3, "TIER3_TEMPORAL_WATCH", "runtime_watch_until_condition",
                "dynamic-state watch-until -p <pid> -d <elf> --condition '<expr>' --timeout-ms 30000",
                "Arm a zero-stop condition watcher to capture state the moment thresholds cross.",
                "임계치 초과 순간을 자동 포착하도록 무중단 조건 감시를 설정합니다.",
                "triggered snapshot at anomaly instant",
            ),
            PlaybookStep(
                4, "TIER2_DEEP_INSPECT", "runtime_correlate_source_and_state",
                "dynamic-state correlate-source -p <pid> -d <elf>",
                "Map the triggered state to source code locations.",
                "포착된 이상 시점의 상태를 소스 코드 위치로 연결합니다.",
                "code_anchors",
            ),
        ],
        pivot_rules=[
            PivotRule(
                "No threshold crossed within timeout",
                "runtime_inspect_thread_callstack_and_locks",
                "Inspect live call stacks to confirm whether the workload is exercising the suspect code path.",
                "타임아웃 내 임계치가 넘지 않으면 콜스택을 조회해 의심 코드 경로가 실제로 실행 중인지 확인합니다.",
            ),
        ],
        stop_conditions=[
            "MET: anomaly window captured with delta + code_anchors",
            "BLOCKED: target_unreadable / process_exited",
            "EXHAUSTED: max_iterations or watch timeout reached",
        ],
        markdown_file="skills/diagnose-process/playbooks/intermittent-temporal-bug.md",
    ),
}


def list_playbooks(lang: str = "en") -> List[Dict[str, Any]]:
    return [pb.to_dict(lang=lang) for pb in PLAYBOOKS.values()]


def get_playbook(playbook_id: str) -> Optional[DiagnosticPlaybook]:
    return PLAYBOOKS.get(str(playbook_id or "").strip())


def select_playbook(
    *,
    symptom: Optional[str] = None,
    diagnose_result: Optional[Dict[str, Any]] = None,
    coverage: Optional[Dict[str, Any]] = None,
    lang: str = "en",
) -> Dict[str, Any]:
    """Front-door playbook router (inspired by cursor/plugins/pstack).

    Scores all 6 playbooks against:
    1. Free-text `symptom` keywords,
    2. `diagnose_result.checks_run` inconclusive/supported recipe IDs,
    3. `coverage` / `memory_integrity` signals (e.g., large-heap Tier-2 sampling).
    Returns the chosen playbook dict plus routing rationale.
    """
    scores: Dict[str, int] = {pid: 0 for pid in PLAYBOOKS}
    reasons: Dict[str, List[str]] = {pid: [] for pid in PLAYBOOKS}

    sym_low = str(symptom or "").strip().lower()
    if sym_low:
        for pid, pb in PLAYBOOKS.items():
            matched_kw = [kw for kw in pb.symptom_keywords if kw in sym_low]
            if matched_kw:
                scores[pid] += 3 * len(matched_kw)
                reasons[pid].append(f"symptom matched: {', '.join(matched_kw[:3])}")

    res = diagnose_result if isinstance(diagnose_result, dict) else {}
    rids: List[str] = []
    for c in (res.get("checks_run") or []):
        if isinstance(c, dict):
            st = str(c.get("status") or "").upper()
            if st in ("INCONCLUSIVE", "ERROR", "TIMEOUT", "FAIL", "SUPPORTED"):
                rids.append(str(c.get("recipe_id") or c.get("item") or "").upper())
    for f in (res.get("findings") or []):
        if isinstance(f, dict) and f.get("recipe_id"):
            rids.append(str(f["recipe_id"]).upper())

    if rids:
        for pid, pb in PLAYBOOKS.items():
            matched_r = [r for r in rids if any(r.startswith(pref) for pref in pb.recipe_prefixes)]
            if matched_r:
                scores[pid] += 4 * len(matched_r)
                reasons[pid].append(f"recipes matched: {', '.join(dict.fromkeys(matched_r[:3]))}")

    # Large-heap Tier-2 sampling signal strongly points to memory-leak-and-growth or heap-corruption
    cov = coverage if isinstance(coverage, dict) else {}
    policy_skipped = list(((cov.get("detail") or {}).get("policy_skipped") or []))
    if any(p.get("kind") in ("integrity_not_checked", "uaf_not_checked", "double_free_not_checked") for p in policy_skipped):
        scores["memory-leak-and-growth"] += 2
        reasons["memory-leak-and-growth"].append("large-heap cap / Tier-2 sampling signal")

    best_id = max(scores.keys(), key=lambda k: scores[k])
    if scores[best_id] == 0:
        # Default fallback: if verdict is INCONCLUSIVE -> intermittent-temporal-bug; else hang-deadlock-and-contention
        verdict = str(cov.get("verdict") or res.get("verdict") or "").upper()
        best_id = "intermittent-temporal-bug" if verdict == "INCONCLUSIVE" else "hang-deadlock-and-contention"
        reasons[best_id].append("default general-purpose routing")

    chosen = PLAYBOOKS[best_id].to_dict(lang=lang)
    chosen["routing_score"] = scores[best_id]
    chosen["routing_reasons"] = reasons[best_id]
    return chosen


def write_playbook_markdown_files(base_dir: str) -> List[str]:
    """Generate/sync human & agent-readable markdown files under skills/diagnose-process/playbooks/."""
    os.makedirs(base_dir, exist_ok=True)
    written: List[str] = []
    for pid, pb in PLAYBOOKS.items():
        path = os.path.join(base_dir, f"{pid}.md")
        lines = [
            f"# Playbook: {pb.title_en}",
            "",
            f"- **ID**: `{pb.playbook_id}`",
            f"- **Exit Predicate (never relax)**: {pb.exit_predicate_en}",
            f"- **Max Iterations**: {pb.default_max_iterations}",
            "",
            "## Steps",
        ]
        for st in pb.steps:
            lines.append(f"{st.step}. **[{st.tier}] `{st.tool}`** — {st.purpose_en}")
            lines.append(f"   - CLI: `{st.cli_hint}`")
            lines.append(f"   - Expected evidence: {st.expected_evidence}")
        lines.extend(["", "## Plateau -> Pivot Rules"])
        for pr in pb.pivot_rules:
            lines.append(f"- **When**: {pr.when} -> **Pivot to `{pr.pivot_to_tool}`**: {pr.pivot_reason_en}")
        lines.extend(["", "## Stop Conditions (Escape Hatch)"])
        for sc in pb.stop_conditions:
            lines.append(f"- {sc}")
        lines.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        written.append(path)
    return written
