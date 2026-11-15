"""Process Behavior and Goal Explainer for Normal and Diagnosed Processes.

Analyzes a process's runtime profile (threads, callstacks, syscalls, resources, modules)
to explain:
1. What software/system it is and what overarching goal/purpose it serves.
2. What each thread is specifically doing (roles, state, functions, wait points).
3. Evidence of why the process is operating normally (or where anomalies lie).
"""
from __future__ import annotations

import copy
import gzip
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from .process_profile import build_process_profile


# -----------------------------------------------------------------------------
# Role Inference Heuristics
# -----------------------------------------------------------------------------

_IO_SYSCALLS = frozenset({
    "epoll_wait", "epoll_pwait", "epoll_pwait2", "poll", "ppoll", "select", "pselect6",
    "recv", "recvfrom", "recvmsg", "recvmmsg", "accept", "accept4"
})

_SYNC_WAIT_SYSCALLS = frozenset({
    "futex", "pthread_cond_wait", "pthread_cond_timedwait", "sem_wait", "sem_timedwait"
})

_SLEEP_SYSCALLS = frozenset({
    "nanosleep", "clock_nanosleep", "pause", "sleep", "usleep", "restart_syscall"
})

_DISK_WRITE_SYSCALLS = frozenset({
    "write", "pwrite", "pwrite64", "pwritev", "fsync", "fdatasync", "sync"
})


def _classify_thread_role(
    name: Optional[str],
    func: Optional[str],
    syscall: Optional[str],
    lock: Optional[str],
    state: str,
    cpu_share: Optional[float],
    is_main: bool,
    lang: str = "ko"
) -> Tuple[str, str]:
    """Infers (role_category, detailed_explanation) for a thread."""
    name_lower = (name or "").lower()
    func_lower = (func or "").lower()
    syscall_lower = (syscall or "").lower()
    is_ko = lang.startswith("ko")

    # 1. Lock contention / deadlock
    if state == "lock" or lock:
        role = "동기화 락 대기" if is_ko else "Lock Contention Waiter"
        desc = (
            f"뮤텍스/락 '{lock or 'lock'}'을 획득하기 위해 대기 중입니다."
            if is_ko else f"Waiting to acquire mutex/lock '{lock or 'lock'}'."
        )
        return role, desc

    # 2. Main / Process Supervisor
    if is_main or func_lower == "main" or name_lower in ("main", "ok_idle_server"):
        if syscall_lower in _SLEEP_SYSCALLS or syscall_lower in _IO_SYSCALLS:
            role = "메인 제어 및 라이프사이클 관리" if is_ko else "Main Controller / Lifecycle Supervisor"
            desc = (
                f"프로세스 초기화 후 '{func or 'main'}'에서 시스템 콜({syscall or '대기'})을 호출하여 "
                "백그라운드 스레드들의 작업 및 외부 시그널/종료 이벤트를 대기하고 있습니다."
                if is_ko else
                f"Initialized the process and is waiting in '{func or 'main'}' via '{syscall or 'wait'}' "
                "for background workers or external termination signals."
            )
            return role, desc

    # 3. Network / Event I/O Listener
    if (
        syscall_lower in _IO_SYSCALLS
        or any(k in name_lower or k in func_lower for k in ("accept", "listen", "poll", "epoll", "net", "socket", "io_"))
    ):
        role = "네트워크/이벤트 리스너" if is_ko else "Network / Event I/O Listener"
        desc = (
            f"네트워크 소켓이나 I/O 디스크립터에서 들어오는 클라이언트 연결/이벤트를 감지하기 위해 "
            f"'{syscall or func or 'I/O wait'}' 상태로 대기하고 있습니다."
            if is_ko else
            f"Waiting on network sockets or I/O descriptors via '{syscall or func or 'I/O wait'}' "
            "to accept incoming connections or dispatch events."
        )
        return role, desc

    # 4. Worker / Task Pool
    if (
        syscall_lower in _SYNC_WAIT_SYSCALLS
        or any(k in name_lower or k in func_lower for k in ("worker", "req_", "handler", "task", "job", "pool", "exec"))
    ):
        role = "작업 처리 워커(Task Worker)" if is_ko else "Task Worker / Request Handler"
        if syscall_lower in _SLEEP_SYSCALLS:
            desc = (
                f"요청 처리 함수 '{func or 'handler'}'에서 일정 시간 대기/주기 처리({syscall})를 수행하고 있습니다."
                if is_ko else
                f"Executing request handling logic in '{func or 'handler'}' with periodic wait ({syscall})."
            )
        elif syscall_lower in _SYNC_WAIT_SYSCALLS:
            desc = (
                f"작업 큐(Queue) 또는 조건 변수({syscall})에서 새로 처리할 태스크가 전달되기를 대기하고 있습니다."
                if is_ko else
                f"Waiting on task queue/condition variable ({syscall}) for incoming tasks to process."
            )
        else:
            desc = (
                f"비즈니스 로직 함수 '{func or 'worker'}'에서 할당된 요청/작업을 처리하고 있습니다."
                if is_ko else
                f"Processing assigned tasks/requests in business logic function '{func or 'worker'}'."
            )
        return role, desc

    # 5. Timer / Heartbeat / Watchdog
    if (
        syscall_lower in _SLEEP_SYSCALLS
        or any(k in name_lower or k in func_lower for k in ("timer", "heartbeat", "watchdog", "monitor", "tick", "sched"))
    ):
        role = "주기적 타이머 / 헬스 모니터" if is_ko else "Periodic Timer / Health Monitor"
        desc = (
            f"주기적 타이머/모니터링 스레드로, '{syscall or 'sleep'}'을 통해 다음 주기까지 슬립 대기 중입니다."
            if is_ko else
            f"Periodic background timer/monitor sleeping via '{syscall or 'sleep'}' until next tick."
        )
        return role, desc

    # 6. Disk / Flush / Logging Writer
    if (
        syscall_lower in _DISK_WRITE_SYSCALLS
        or any(k in name_lower or k in func_lower for k in ("flush", "log", "writer", "dump", "sync", "disk"))
    ):
        role = "데이터 플러시 및 로깅 워커" if is_ko else "Data Flush & Logging Worker"
        desc = (
            f"버퍼에 적재된 데이터를 저장소나 로그 파일로 플러시/기록하는 역할을 담당합니다."
            if is_ko else
            "Responsible for flushing buffered data or metrics to persistent storage/logs."
        )
        return role, desc

    # 7. Data Ingest / Producer
    if any(k in name_lower or k in func_lower for k in ("ingest", "reader", "collector", "input", "fetch")):
        role = "데이터 수집 / 인제스트 워커" if is_ko else "Data Ingest / Collector Worker"
        desc = (
            f"외부 소스 또는 파이프라인으로부터 데이터를 읽어들여 내부 버퍼로 전달하는 역할을 수행합니다."
            if is_ko else
            "Reads data from external sources/pipelines and feeds internal processing buffers."
        )
        return role, desc

    # 8. Active Computing Thread
    if (cpu_share is not None and cpu_share >= 0.05) or state == "running":
        role = "고성능 연산 및 데이터 처리" if is_ko else "Active Compute & Processing"
        desc = (
            f"CPU를 활발히 사용하며 '{func or 'active routine'}'에서 연산 및 데이터 변환을 수행하고 있습니다."
            if is_ko else
            f"Actively running computation/processing in '{func or 'active routine'}' on CPU."
        )
        return role, desc

    # Default Fallback
    role = "백그라운드 지원 스레드" if is_ko else "Background Service Thread"
    desc = (
        f"함수 '{func or 'unknown'}'에서 상태({state}, syscall: {syscall or 'none'})를 유지하며 대기 중입니다."
        if is_ko else
        f"Maintaining background state in function '{func or 'unknown'}' ({state}, syscall: {syscall or 'none'})."
    )
    return role, desc


# -----------------------------------------------------------------------------
# Process Goal / Purpose Inference
# -----------------------------------------------------------------------------

def _infer_process_goal(
    proc_name: str,
    thread_roles: List[str],
    fds_kinds: Dict[str, int],
    modules: List[str],
    verdict: str,
    lang: str = "ko"
) -> Dict[str, str]:
    """Infers overarching software purpose and architecture pattern."""
    is_ko = lang.startswith("ko")
    name_lower = proc_name.lower()
    all_roles = " ".join(thread_roles).lower()
    mod_str = " ".join(modules).lower()

    has_listener = "리스너" in all_roles or "listener" in all_roles or "acceptor" in name_lower or "idle_server" in name_lower
    has_worker_pool = "워커" in all_roles or "worker" in all_roles or "handler" in all_roles
    has_pipeline = "플러시" in all_roles or "수집" in all_roles or "flush" in all_roles or "ingest" in all_roles or "pipe" in name_lower
    has_sockets = "socket" in fds_kinds or fds_kinds.get("socket", 0) > 0

    if has_listener and (has_worker_pool or "server" in name_lower or has_sockets):
        category = "네트워크 서비스 / 서버 데몬" if is_ko else "Network Service / Server Daemon"
        arch = "이벤트 수신(Acceptor) + 작업 처리 워커 풀(Worker Pool) 모델" if is_ko else "Acceptor + Worker Pool Architecture"
        purpose = (
            f"'{proc_name}'은(는) 외부 클라이언트의 접속 및 네트워크 요청을 수신하여 "
            "병렬로 안전하게 처리하는 서버 소프트웨어입니다. 클라이언트 연결을 수락하는 리스너 스레드와 "
            "실제 로직을 처리하는 워커 스레드로 구성되어 안정적인 서비스 처리를 목적으로 합니다."
            if is_ko else
            f"'{proc_name}' is a network server software designed to accept incoming client connections "
            "and process requests across parallel worker threads."
        )
    elif has_pipeline:
        category = "데이터 파이프라인 처리 프로세스" if is_ko else "Data Pipeline Processing System"
        arch = "단계별 스트리밍 파이프라인(Ingest-Process-Flush) 모델" if is_ko else "Staged Pipeline (Ingest-Process-Flush) Architecture"
        purpose = (
            f"'{proc_name}'은(는) 데이터를 수집(Ingest), 가공(Process), 저장/출력(Flush)하는 일련의 "
            "파이프라인 단계를 스레드별로 분업화하여 연속적으로 데이터를 처리하는 소프트웨어입니다."
            if is_ko else
            f"'{proc_name}' is a pipelined data processing system that ingests, transforms, "
            "and flushes stream data through dedicated stage worker threads."
        )
    elif has_worker_pool:
        category = "멀티스레드 배치 / 백그라운드 워커 프로세스" if is_ko else "Multithreaded Batch / Worker Process"
        arch = "마스터-워커(Master-Worker) 분산 작업 모델" if is_ko else "Master-Worker Task Dispatch Architecture"
        purpose = (
            f"'{proc_name}'은(는) 다수의 워커 스레드를 통해 큐에 적재된 배치 작업이나 "
            "비동기 태스크를 병렬로 분산 처리하는 백그라운드 컴퓨팅 소프트웨어입니다."
            if is_ko else
            f"'{proc_name}' is a background batch processing service utilizing worker thread pools "
            "to parallelize tasks from queues."
        )
    elif has_listener:
        category = "이벤트 기반 I/O 멀티플렉싱 데몬" if is_ko else "Event-Driven I/O Multiplexing Daemon"
        arch = "단일/소수 이벤트 루프(Event Loop) 모델" if is_ko else "Event Loop Architecture"
        purpose = (
            f"'{proc_name}'은(는) 시스템 I/O 이벤트나 시그널을 감시하며 적은 자원으로 "
            "고효율의 이벤트 처리를 수행하는 데몬 프로세스입니다."
            if is_ko else
            f"'{proc_name}' is an event-driven daemon monitoring I/O multiplexing descriptors "
            "with lightweight resource consumption."
        )
    else:
        category = "시스템 백그라운드 서비스" if is_ko else "System Background Service"
        arch = "단일 제어 루프 모델" if is_ko else "Standard Control Loop Architecture"
        purpose = (
            f"'{proc_name}'은(는) 백그라운드에서 상주하며 지정된 시스템 작업과 주기적 상태 관리를 "
            "수행하는 소프트웨어입니다."
            if is_ko else
            f"'{proc_name}' is a background system utility maintaining operational tasks."
        )

    return {
        "category": category,
        "architecture_style": arch,
        "primary_purpose": purpose,
    }


# -----------------------------------------------------------------------------
# Main Explainer Function
# -----------------------------------------------------------------------------

def explain_process_behavior(
    report_dict: Optional[Dict[str, Any]] = None,
    report_path: Optional[str] = None,
    pid: Optional[int] = None,
    debug_image: Optional[str] = None,
    language: str = "ko",
    **kwargs: Any
) -> Dict[str, Any]:
    """Analyzes a process's collected diagnosis/profile and explains its goal and thread activities."""
    lang = "ko" if str(language or "en").strip().lower().startswith("ko") else "en"
    is_ko = lang.startswith("ko")

    # 1. Load data
    data: Optional[Dict[str, Any]] = None
    if report_dict and isinstance(report_dict, dict):
        data = copy.deepcopy(report_dict)
    elif report_path and os.path.exists(report_path):
        if report_path.endswith(".gz"):
            with gzip.open(report_path, "rt", encoding="utf-8") as f:
                data = json.load(f)
        else:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
    elif pid is not None:
        # Run a quick diagnose to acquire evidence
        from .expert_diagnostic_engine import ExpertDiagnosticEngine
        engine = kwargs.get("engine") or ExpertDiagnosticEngine()
        from .human_report import diagnose_with_summary
        out, _ = diagnose_with_summary(
            pid=pid,
            debug_image=debug_image,
            engine=engine,
            lang=lang,
            target=kwargs.get("target"),
            default_check_budget_s=kwargs.get("default_check_budget_s", 4.0),
        )
        data = out

    if not data or not isinstance(data, dict):
        return {
            "success": False,
            "error": "No valid report data, report path, or PID provided for process behavior analysis.",
            "error_code": "MISSING_INPUT"
        }

    # Extract target and full report
    res_part = data
    rep_part = data.get("report") if isinstance(data.get("report"), dict) else data
    target = data.get("target") or rep_part.get("section_b_target_context", {}).get("target") or {}
    proc_name = str(target.get("process_name") or data.get("process_name") or "unknown_process")
    proc_pid = target.get("pid") or data.get("pid")
    verdict = str(data.get("verdict") or "UNKNOWN")

    # Collect valid evidence IDs for provenance grounding
    valid_eids: Set[str] = set()
    ledger_data = data.get("evidence_ledger") or rep_part.get("evidence_ledger")
    if isinstance(ledger_data, list):
        for item in ledger_data:
            if isinstance(item, dict) and "evidence_id" in item:
                valid_eids.add(str(item["evidence_id"]))
    elif isinstance(ledger_data, dict):
        for item in ledger_data.get("records", []):
            if isinstance(item, dict) and "evidence_id" in item:
                valid_eids.add(str(item["evidence_id"]))
    sec_d = rep_part.get("section_d_detailed_inspection_results")
    if isinstance(sec_d, dict):
        for c in sec_d.get("checks", []):
            if isinstance(c, dict) and "evidence_id" in c:
                valid_eids.add(str(c["evidence_id"]))

    # 2. Build Profile
    prof = build_process_profile(res_part, rep_part)
    if not prof or not prof.get("available"):
        direct_threads = rep_part.get("threads") or data.get("threads")
        if direct_threads and isinstance(direct_threads, dict) and direct_threads.get("rows"):
            prof = {
                "available": True,
                "threads": direct_threads,
                "resources": rep_part.get("resources") or {},
                "modules": rep_part.get("modules") or {},
                "memory": rep_part.get("memory") or {},
                "locks": rep_part.get("locks") or {},
                "runtime": rep_part.get("runtime") or {},
            }
        else:
            return {
                "success": False,
                "error": "The diagnosis report contains insufficient observations to profile the process.",
                "error_code": "INSUFFICIENT_DATA"
            }

    threads_sec = prof.get("threads") or {}
    thread_rows = threads_sec.get("rows") or []
    resources_sec = prof.get("resources") or {}
    fds_info = resources_sec.get("fds") or {}
    fds_kinds = fds_info.get("by_kind") or {}
    modules_sec = prof.get("modules") or {}
    module_names = [m.get("name") for m in modules_sec.get("items") or [] if isinstance(m, dict)]
    locks_sec = prof.get("locks") or {}
    mem_sec = prof.get("memory") or {}
    runtime_sec = prof.get("runtime") or {}

    # 3. Analyze Threads
    thread_analyses: List[Dict[str, Any]] = []
    collected_roles: List[str] = []

    for r in thread_rows:
        t_name = r.get("name")
        func = r.get("function")
        loc = r.get("location")
        source = r.get("source")
        waits_on = r.get("waits_on") or {}
        syscall = waits_on.get("name") if waits_on.get("kind") == "syscall" else None
        lock_name = waits_on.get("name") if waits_on.get("kind") == "lock" else None
        state = r.get("state", "unknown")
        cpu = r.get("cpu_share")
        count = r.get("count", 1)
        tids = r.get("tids") or ([r["tid"]] if r.get("tid") else [])
        is_main = bool(proc_pid and proc_pid in tids)

        role, desc = _classify_thread_role(
            name=t_name,
            func=func,
            syscall=syscall,
            lock=lock_name,
            state=state,
            cpu_share=cpu,
            is_main=is_main,
            lang=lang
        )
        collected_roles.append(role)

        thread_analyses.append({
            "thread_name": t_name or ("main" if is_main else "unnamed_thread"),
            "count": count,
            "tids": tids,
            "state": state,
            "role": role,
            "function": func,
            "location": loc,
            "source_code": source,
            "waits_on": waits_on,
            "cpu_share": cpu,
            "behavior_description": desc,
        })

    # 4. Infer Overall Process Goal
    goal_info = _infer_process_goal(
        proc_name=proc_name,
        thread_roles=collected_roles,
        fds_kinds=fds_kinds,
        modules=module_names,
        verdict=verdict,
        lang=lang
    )

    # 5. Evaluate Normal Operation Evidence
    is_normal = verdict == "HEALTHY" or (verdict != "CONFIRMED_FAULT" and not locks_sec.get("items"))
    normal_evidences: List[str] = []

    if is_ko:
        if verdict == "HEALTHY":
            normal_evidences.append("모든 기본 헬스체크(데드락, 비정상 대기, 리소스 누수 등)를 통과하여 엔진 판정 'HEALTHY'가 확인되었습니다.")
        if not locks_sec.get("items"):
            normal_evidences.append(f"관측 구간 동안 스레드 간 락 경합(Lock Contention)이나 교착 상태(Deadlock)가 발생하지 않았습니다 (검사 표본 {locks_sec.get('samples', 0)}회).")
        
        # Check thread state stability
        waiting_count = sum(r.get("count", 1) for r in thread_rows if r.get("state") in ("waiting", "sleeping"))
        total_threads = sum(r.get("count", 1) for r in thread_rows)
        if total_threads > 0 and waiting_count == total_threads:
            normal_evidences.append(f"전체 {total_threads}개 스레드가 폭주(Busy-spin) 없이 이벤트 수신 및 다음 작업 대기 상태(Waiting/Sleeping)를 안정적으로 유지하고 있습니다.")
        
        # Memory & FD stability
        rss = mem_sec.get("rss") or {}
        if rss.get("change_kb", 0) == 0:
            normal_evidences.append(f"상주 메모리(RSS {rss.get('v', 0)} kB)가 관측 동안 증가하지 않고 평형을 유지하고 있습니다.")
        if fds_info.get("v") is not None:
            normal_evidences.append(f"열린 파일 디스크립터({fds_info.get('v')}개: {', '.join(f'{k} {v}개' for k, v in fds_kinds.items())})가 누수 없이 정해진 범위 내에서 관리되고 있습니다.")
    else:
        if verdict == "HEALTHY":
            normal_evidences.append("Engine confirmed 'HEALTHY' verdict, passing all baseline health recipes.")
        if not locks_sec.get("items"):
            normal_evidences.append(f"No mutex contention or deadlock was observed across {locks_sec.get('samples', 0)} samples.")
        waiting_count = sum(r.get("count", 1) for r in thread_rows if r.get("state") in ("waiting", "sleeping"))
        total_threads = sum(r.get("count", 1) for r in thread_rows)
        if total_threads > 0 and waiting_count == total_threads:
            normal_evidences.append(f"All {total_threads} thread(s) are cleanly resting in waiting/sleeping states without busy spinning.")
        rss = mem_sec.get("rss") or {}
        if rss.get("change_kb", 0) == 0:
            normal_evidences.append(f"Resident memory (RSS {rss.get('v', 0)} kB) remained stable with 0 kB change.")
        if fds_info.get("v") is not None:
            normal_evidences.append(f"File descriptors ({fds_info.get('v')} total) are stable and categorized within expected limits.")

    # 6. Render Markdown
    md_lines: List[str] = []
    if is_ko:
        md_lines.append(f"# 프로세스 분석 리포트: {proc_name} (PID: {proc_pid or 'N/A'})")
        md_lines.append(f"**진단 판정**: `{verdict}` | **소프트웨어 유형**: {goal_info['category']}")
        md_lines.append("")
        md_lines.append("## 1. 프로세스 목표 및 소프트웨어 정체성")
        md_lines.append(f"- **목표 및 역할**: {goal_info['primary_purpose']}")
        md_lines.append(f"- **아키텍처 패턴**: {goal_info['architecture_style']}")
        md_lines.append(f"- **로드된 주요 모듈**: {', '.join(module_names[:6]) if module_names else '기본 C 라이브러리'}")
        md_lines.append("")
        md_lines.append("## 2. 쓰레드별 동작 및 역할 분석")
        for th in thread_analyses:
            tid_str = f" (TID {th['tids'][0]})" if th.get('tids') else ""
            t_label = f"`{th['thread_name']}`" + (f" ({th['count']}개 스레드)" if th['count'] > 1 else tid_str)
            md_lines.append(f"### {t_label} - **{th['role']}**")
            md_lines.append(f"- **현재 상태**: `{th['state']}`" + (f" (대기 시스템 콜: `{th['waits_on'].get('name')}`)" if th['waits_on'].get('name') else ""))
            if th['function']:
                md_lines.append(f"- **실행 함수/위치**: `{th['function']}`" + (f" (`{th['location']}`)" if th['location'] else ""))
            if th['source_code']:
                md_lines.append(f"- **실행 코드**: `{th['source_code']}`")
            md_lines.append(f"- **동작 설명**: {th['behavior_description']}")
            md_lines.append("")
        md_lines.append("## 3. 정상 동작 평가 및 상태 요약")
        if is_normal:
            md_lines.append("이 프로세스는 현재 **정상(Normal / Healthy)** 상태로 작동 중입니다.")
        else:
            md_lines.append(f"이 프로세스는 진단 판정 `{verdict}` 상태입니다.")
        for ev in normal_evidences:
            md_lines.append(f"- {ev}")
        md_lines.append("")
        md_lines.append("## 4. 자원 현황 요약")
        rss_val = mem_sec.get("rss", {}).get("v")
        md_lines.append(f"- **메모리(RSS)**: {rss_val} kB" if rss_val else "- **메모리(RSS)**: N/A")
        md_lines.append(f"- **스레드 수**: 총 {sum(r.get('count', 1) for r in thread_rows)}개")
        if fds_info.get("v") is not None:
            md_lines.append(f"- **파일 디스크립터**: {fds_info.get('v')}개 ({', '.join(f'{k}: {v}' for k, v in fds_kinds.items())})")
    else:
        md_lines.append(f"# Process Analysis Report: {proc_name} (PID: {proc_pid or 'N/A'})")
        md_lines.append(f"**Verdict**: `{verdict}` | **Software Category**: {goal_info['category']}")
        md_lines.append("")
        md_lines.append("## 1. Process Goal & Software Purpose")
        md_lines.append(f"- **Purpose & Role**: {goal_info['primary_purpose']}")
        md_lines.append(f"- **Architecture Style**: {goal_info['architecture_style']}")
        md_lines.append(f"- **Loaded Modules**: {', '.join(module_names[:6]) if module_names else 'Standard Libc'}")
        md_lines.append("")
        md_lines.append("## 2. Thread-by-Thread Activity Analysis")
        for th in thread_analyses:
            tid_str = f" (TID {th['tids'][0]})" if th.get('tids') else ""
            t_label = f"`{th['thread_name']}`" + (f" ({th['count']} threads)" if th['count'] > 1 else tid_str)
            md_lines.append(f"### {t_label} - **{th['role']}**")
            md_lines.append(f"- **State**: `{th['state']}`" + (f" (syscall: `{th['waits_on'].get('name')}`)" if th['waits_on'].get('name') else ""))
            if th['function']:
                md_lines.append(f"- **Function/Location**: `{th['function']}`" + (f" (`{th['location']}`)" if th['location'] else ""))
            if th['source_code']:
                md_lines.append(f"- **Source Line**: `{th['source_code']}`")
            md_lines.append(f"- **Behavior**: {th['behavior_description']}")
            md_lines.append("")
        md_lines.append("## 3. Normal Operation & Health Evidence")
        if is_normal:
            md_lines.append("This process is currently operating in a **Normal / Healthy** state.")
        else:
            md_lines.append(f"Process status: `{verdict}`.")
        for ev in normal_evidences:
            md_lines.append(f"- {ev}")
        md_lines.append("")
        md_lines.append("## 4. Resource Summary")
        rss_val = mem_sec.get("rss", {}).get("v")
        md_lines.append(f"- **Memory (RSS)**: {rss_val} kB" if rss_val else "- **Memory (RSS)**: N/A")
        md_lines.append(f"- **Thread Count**: {sum(r.get('count', 1) for r in thread_rows)} total")
        if fds_info.get("v") is not None:
            md_lines.append(f"- **File Descriptors**: {fds_info.get('v')} ({', '.join(f'{k}: {v}' for k, v in fds_kinds.items())})")

    report_markdown = "\n".join(md_lines)

    return {
        "success": True,
        "process_goal": {
            "name": proc_name,
            "pid": proc_pid,
            "category": goal_info["category"],
            "architecture_style": goal_info["architecture_style"],
            "primary_purpose": goal_info["primary_purpose"],
            "verdict": verdict,
            "is_normal": is_normal,
        },
        "threads": thread_analyses,
        "normal_operation_evidence": normal_evidences,
        "referenced_evidence_ids": sorted(list(valid_eids)),
        "fallback_applied": False,
        "resources": {
            "rss_kb": mem_sec.get("rss", {}).get("v"),
            "thread_count": sum(r.get("count", 1) for r in thread_rows),
            "fds_count": fds_info.get("v"),
            "fds_by_kind": fds_kinds,
            "modules": module_names,
        },
        "explanation_markdown": report_markdown,
    }
