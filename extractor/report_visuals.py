"""Visual front section of the standalone HTML incident report.

``build_visual_summary`` turns a ``DiagnoseResult`` dict (plus the full A-I report dict when available) into an
HTML fragment that is placed before the plain-language summary:

* a verdict header with the conclusion sentence and the collection figures,
* one card per finding with a picture drawn from the structured evidence
  (deadlock: thread/lock sequence diagram; heap overflow: memory map of the buffer and what lies behind it;
  leak: in-use heap over the heap walks; use after free: pointer -> freed block; any thread finding: the
  per-sample thread states),
* the check list grouped by outcome, each row expandable, with filter and search.

Rules this module keeps:

* Everything is rendered on the server side and there is no script in the output at all: stepping through a
  sequence and filtering the check list are done with radio inputs and CSS.  The report therefore opens anywhere
  (also under a ``script-src 'none'`` policy), prints the same, and a string from the target can never run as code.
* No external resource is referenced (the report must open offline).
* Only values present in the evidence are drawn.  What is reconstructed rather than observed (for example the order
  in which two threads took their first lock) is labelled as reconstructed; what was not collected (for example
  the bytes inside a buffer) is drawn as "not collected", never invented.
* Every string that comes from the target or the caller is HTML-escaped.
"""

from __future__ import annotations

import html
import math
import re
from typing import Any, Dict, List, Optional, Tuple

from .report_registry import category_label, finding_viz, recipe_label
from .human_report import (CATEGORY_LABEL, T, VERDICT_WORD, _by_kind, _checks, _cycle, _growth, _inline_html,
                           _observations, _thread_rows, _user_funcs, conclusion_sentence, ko_text, _ko_free_list, _ko_write_basis)

E = html.escape

# key -> (en, ko)
_L: Dict[str, Tuple[str, str]] = {
    "nav_glance": ("At a glance", "한눈에 보기"),
    "nav_findings": ("Findings", "발견된 문제"),
    "nav_checks": ("Check list", "검사 체크리스트"),
    "nav_summary": ("Plain-language summary", "쉬운 말 요약"),
    "nav_detail": ("Detailed report", "상세 보고서"),
    "verdict": ("Verdict", "판정"),
    "checks": ("Checks", "검사"),
    "checks_run": ("Checks run", "실행한 검사"),
    "checks_not_run": ("+ {n} not run", "실행하지 않은 검사 {n}개 별도"),
    "stop_time": ("Target stop time", "대상 정지 시간"),
    "zero_stop": ("never paused", "한 번도 멈추지 않음"),
    "bytes_read": ("Data read", "읽은 데이터"),
    "duration": ("Diagnosis time", "진단 소요 시간"),
    "no_findings": ("No problem was found within the checked scope. The check list below shows what was and was not "
                    "examined.",
                    "점검한 범위 안에서는 문제가 발견되지 않았습니다. 무엇을 검사했고 무엇을 검사하지 못했는지는 아래 "
                    "체크리스트에 있습니다."),
    "no_decision": ("The checks did not reach a decision. This is not a statement that the process is healthy; the "
                    "check list below shows what could not be examined and why.",
                    "검사가 결론에 이르지 못했습니다. 프로세스가 정상이라는 뜻이 아닙니다. 무엇을 왜 확인하지 못했는지는 "
                    "아래 체크리스트에 있습니다."),
    "finding": ("Finding {i}", "발견 {i}"),
    "severity": ("severity", "심각도"),
    "observed": ("observed", "관측"),
    "reconstructed": ("reconstructed", "재구성"),
    "not_observed": ("not observed", "관측 안 됨"),
    "legend_obs": ("observed = read directly from the running process", "관측 = 실행 중인 프로세스에서 직접 읽은 사실"),
    "legend_rec": ("reconstructed = follows logically from what was observed; the exact moment was not seen",
                   "재구성 = 관측된 사실에서 논리적으로 따라 나오는 것. 그 순간 자체를 본 것은 아님"),
    "step_play": ("▶ Play", "▶ 재생"), "step_all": ("Show all", "전체 보기"),
    "step_of": ("Step", "단계"), "step_hint": ("Select a step to see the state at that moment.", "단계를 선택하면 그 시점의 상태를 볼 수 있습니다."),
    "evidence": ("Evidence", "근거"),
    "as_text": ("The same, as text", "같은 내용을 글로 보기"),
    "subjects": ("Named in the evidence", "근거에 나온 이름"),
    "where": ("Where", "위치"),
    # deadlock
    "dl_title": ("How the threads got stuck", "스레드들이 멈추게 된 순서"),
    "dl_thread": ("thread", "스레드"), "dl_lock": ("lock", "락"),
    "dl_acq": ("{thr} takes lock {lock}", "{thr}: 락 {lock} 획득"),
    "dl_acq_note": ("Seen as the current owner of this lock. Where it took the lock was not observed.",
                    "현재 이 락의 소유자로 관측됨. 어디에서 획득했는지는 관측되지 않음."),
    "dl_wait": ("{thr} asks for lock {lock}, which {owner} holds, and blocks", "{thr}: {owner}이(가) 잡고 있는 락 {lock}을(를) 요청하고 대기"),
    "dl_wait_at": ("Stopped at {loc}", "{loc} 에서 멈춤"),
    "dl_closed": ("The circle is closed: every thread waits for a lock the next one holds, so none can continue.",
                  "고리가 닫힘: 각 스레드가 다음 스레드가 잡은 락을 기다리므로 아무도 진행할 수 없음."),
    "dl_closed_obs": ("{n} samples over {win} s: no CPU time, same wait in every sample.",
                      "{win}초 동안 {n}회 샘플: CPU 사용 0, 모든 샘플에서 같은 대기."),
    "dl_persist": ("The same cycle was seen in {n} separate observations.", "같은 고리가 서로 다른 {n}번의 관측에서 확인됨."),
    "dl_order_note": ("Each thread must have taken its first lock before asking for the second. Which thread went "
                      "first is not known; the diagram shows one possible order.",
                      "각 스레드는 두 번째 락을 요청하기 전에 첫 번째 락을 이미 잡고 있었습니다. 어느 스레드가 먼저였는지는 "
                      "알 수 없으며, 그림은 가능한 순서 하나를 보여 줍니다."),
    "dl_lbl_acq": ("lock ✔ taken", "lock ✔ 획득"),
    "dl_lbl_wait": ("lock ✖ waits", "lock ✖ 대기"),
    "dl_held_by": ("held by {thr}", "{thr} 소유"),
    "dl_blocked": ("BLOCKED", "대기 중"),
    "dl_deadlock": ("DEADLOCK", "교착 상태"),
    # thread strip
    "ts_title": ("What each thread was doing during the observation", "관측하는 동안 각 스레드의 상태"),
    "ts_sub": ("{n} samples over {win} s", "{win}초 동안 {n}회 샘플"),
    "ts_thread": ("Thread", "스레드"), "ts_samples": ("State per sample", "샘플별 상태"),
    "ts_cpu": ("CPU", "CPU"), "ts_doing": ("Where it was", "머문 위치"),
    "ts_in_cycle": ("in the cycle", "고리에 포함"),
    "ts_waits_lock": ("waiting for lock {lock}", "락 {lock} 대기"),
    "ts_R": ("running", "실행"), "ts_S": ("sleeping / waiting", "대기(sleep)"), "ts_D": ("uninterruptible wait", "중단 불가 대기"),
    "ts_Z": ("zombie", "좀비"), "ts_T": ("stopped", "정지"), "ts_other": ("other", "기타"),
    "ts_runnable": ("ready to run in {p}% of samples", "샘플의 {p}%에서 실행 가능 상태"),
    "ts_dispatches": ("put on a CPU {n} times, never blocked", "CPU에 {n}번 올려졌고 한 번도 대기하지 않음"),
    # overflow
    "ov_title": ("How the write ran past the buffer", "쓰기가 버퍼를 넘어간 모습"),
    "ov_hdr": ("block header", "블록 헤더"),
    "ov_buf": ("{name}: usable {n} bytes", "{name}: 사용 가능 {n}바이트"),
    "ov_buf_plain": ("buffer", "버퍼"),
    "ov_over": ("{n} bytes written past the end", "끝을 넘어 {n}바이트 기록됨"),
    "ov_victim": ("next block: {name}", "다음 블록: {name}"),
    "ov_victim_top": ("unallocated heap (top)", "미할당 힙 영역(top)"),
    "ov_end": ("usable end {addr}", "사용 가능 끝 {addr}"),
    "ov_gap": ("… {n} bytes …", "… {n}바이트 …"),
    "ov_role_size": ("size field of the next block", "다음 블록의 size 필드"),
    "ov_short_size": ("size field", "size 필드"), "ov_short_vdata": ("next block", "다음 블록"), "ov_short_past": ("past end", "초과"),
    "ov_role_vdata": ("data of the next block", "다음 블록의 데이터"),
    "ov_role_past": ("past the end", "끝을 넘은 영역"),
    "ov_role_buf": ("inside the buffer", "버퍼 안"),
    "ov_not_collected": ("contents not collected", "내용 미수집"),
    "ov_s1": ("The buffer {name} has {n} usable bytes ({a} to {b}).", "버퍼 {name}의 사용 가능 크기는 {n}바이트입니다 ({a} ~ {b})."),
    "ov_s2": ("The write does not stop at the end of the buffer and overwrites the header of the next heap block. "
              "The size field there now reads {val}.",
              "쓰기가 버퍼 끝에서 멈추지 않고 다음 힙 블록의 헤더를 덮어씁니다. 그 자리의 size 필드는 현재 {val} 로 읽힙니다."),
    "ov_s2_plain": ("The write does not stop at the end of the buffer and overwrites the header of the next heap block.",
                    "쓰기가 버퍼 끝에서 멈추지 않고 다음 힙 블록의 헤더를 덮어씁니다."),
    "ov_s3": ("In total the write reached {n} bytes past the usable end.",
              "쓰기는 사용 가능 끝을 총 {n}바이트 넘어갔습니다."),
    "ov_s4": ("The damaged block belongs to {name}. Its contents, and any later malloc/free that reads this header, "
              "can no longer be trusted.",
              "손상된 블록은 {name}의 것입니다. 그 내용과, 이후 이 헤더를 읽는 malloc/free 동작은 더 이상 신뢰할 수 없습니다."),
    "ov_s4_top": ("The damaged header is the top of the heap. A later malloc that reads it can fail or return "
                  "an invalid block.",
                  "손상된 헤더는 힙의 맨 끝(top)입니다. 이후 이 헤더를 읽는 malloc이 실패하거나 잘못된 블록을 돌려줄 수 있습니다."),
    "ov_stable": ("The damage read the same in {n} re-reads, so it is not a torn read of a live update.",
                  "{n}번 다시 읽어도 같은 값이어서, 갱신 중인 값을 잘못 읽은 것이 아닙니다."),
    "ov_writer": ("Which code wrote these bytes, and when, was not observed (the process was read without stopping "
                  "it). Start from the code that writes into {name}.",
                  "어느 코드가 언제 이 바이트를 썼는지는 관측되지 않았습니다(프로세스를 멈추지 않고 읽음). {name}에 쓰는 코드부터 확인하세요."),
    "ov_order": ("The left-to-right fill is a reconstruction (writes run from low to high addresses); the final "
                 "state is what was observed.",
                 "왼쪽에서 오른쪽으로 채워지는 순서는 재구성입니다(낮은 주소에서 높은 주소로 기록). 관측된 것은 최종 상태입니다."),
    "ov_low": ("low address", "낮은 주소"), "ov_high": ("high address", "높은 주소"),
    "ov_each": ("one cell = 8 bytes; a dot means the contents were not collected", "한 칸 = 8바이트, 점(·)은 내용 미수집"),
    "ov_text": ("as text", "문자로"),
    # leak
    "lk_title": ("Heap in use over the observation", "관측하는 동안 사용 중인 힙"),
    "lk_y": ("in use (KB)", "사용 중 (KB)"), "lk_x": ("seconds since first heap walk", "첫 힙 조사 이후 경과(초)"),
    "lk_point": ("heap walk {i}: {kb} KB in {n} blocks", "힙 조사 {i}: {kb} KB, 블록 {n}개"),
    "lk_owner": ("Where the growing blocks hang", "늘어나는 블록이 매달린 곳"),
    "lk_root": ("variable", "변수"), "lk_node": ("block", "블록"),
    "lk_delta": ("+{blocks} blocks / +{kb} KB in {win} s ({rate} KB/s)", "{win}초 동안 블록 +{blocks}개 / +{kb} KB ({rate} KB/s)"),
    "lk_thread": ("allocated by thread {thr}", "할당한 스레드: {thr}"),
    "lk_still": ("Still reachable from {var}: the program keeps a reference to every block, so nothing frees them.",
                 "{var}에서 여전히 닿을 수 있음: 프로그램이 모든 블록의 참조를 쥐고 있어 해제되지 않습니다."),
    "lk_first": ("first", "처음"), "lk_last": ("last", "마지막"),
    # uaf
    "ua_title": ("A pointer still refers to freed memory", "포인터가 해제된 메모리를 여전히 가리킴"),
    "ua_var": ("pointer variable", "포인터 변수"), "ua_slot": ("stored at {addr}", "저장 위치 {addr}"),
    "ua_points": ("points to", "가리킴"),
    "ua_chunk": ("heap block {addr}", "힙 블록 {addr}"), "ua_size": ("{n} bytes", "{n}바이트"),
    "ua_freed": ("FREED", "해제됨"),
    "ua_list": ("allocator free list", "할당자의 빈 블록 목록"), "ua_contains": ("lists it as free", "빈 블록으로 보유"),
    "ua_seen": ("Seen free in {n} reads over {win} s while the pointer kept its value.",
                "{win}초 동안 {n}회 읽는 내내 해제 상태였고 포인터 값은 그대로였습니다."),
    "ua_written": ("A write into the block was observed while it was free: the freed memory is being used.",
                   "해제된 상태에서 블록에 쓰기가 관측되었습니다: 해제된 메모리가 실제로 사용되고 있습니다."),
    "ua_not_written": ("No write into the freed block was observed, so an actual use is not proven. The danger is the "
                       "next read or write through this pointer, or the allocator handing the block to someone else.",
                       "해제된 블록에 대한 쓰기는 관측되지 않아 실제 사용은 입증되지 않았습니다. 위험은 이 포인터를 통한 다음 "
                       "읽기·쓰기, 또는 할당자가 이 블록을 다른 곳에 다시 내주는 경우입니다."),
    "ua_l1": ("allocated", "할당"), "ua_l2": ("freed", "해제"), "ua_l3": ("pointer kept", "포인터 유지"),
    "ua_l4": ("used again", "다시 사용"),
    "ua_level_candidate": ("candidate", "후보"), "ua_level_confirmed": ("confirmed", "확정"),
    # checklist
    "ck_title": ("Check list", "검사 체크리스트"),
    "ck_intro": ("Every check the diagnosis considered, by outcome. Select a row for what it looks for and what it found.",
                 "진단이 고려한 모든 검사를 결과별로 정리했습니다. 행을 선택하면 무엇을 확인하는 검사이고 무엇이 나왔는지 볼 수 있습니다."),
    "ck_all": ("All", "전체"),
    "ck_FAIL": ("Found a problem", "이상 발견"), "ck_PASS": ("Clean", "이상 없음"),
    "ck_INCONCLUSIVE": ("Could not judge", "판단하지 못함"), "ck_SKIPPED": ("Not run", "실행하지 않음"),
    "ck_ERROR": ("Error", "오류"),
    "ck_FAIL_hint": ("the check found what it looks for", "검사가 찾던 이상을 발견함"),
    "ck_PASS_hint": ("ran to completion and found nothing", "끝까지 실행했고 아무것도 발견하지 못함"),
    "ck_INCONCLUSIVE_hint": ("ran but could not reach an answer; not evidence that the process is fine",
                             "실행했지만 답을 내지 못함. 문제가 없다는 근거가 아님"),
    "ck_SKIPPED_hint": ("not executed; not evidence that the process is fine", "실행하지 않음. 문제가 없다는 근거가 아님"),
    "ck_ERROR_hint": ("the check itself failed", "검사 자체가 실패함"),
    "ck_what": ("Looks for", "확인하는 것"), "ck_result": ("Result", "결과"),
    "ck_why": ("Why no answer", "답을 내지 못한 이유"), "ck_time": ("Time", "소요 시간"),
    "ck_evidence": ("Evidence records", "근거 기록"), "ck_linked": ("Supports", "연결된 발견"),
    "ck_id": ("Check id", "검사 ID"), "ck_required": ("baseline check", "기본 검사"),
    "ck_not_planned": ("Not selected for this symptom.", "이 증상에 대해서는 선택되지 않았습니다."),
    "ck_need_cap": ("needs a capability that is not available here: {cap}", "여기서 사용할 수 없는 기능이 필요함: {cap}"),
    "ck_no_reason": ("The check recorded no reason.", "검사가 사유를 기록하지 않았습니다."),
    "ck_none": ("No check record is available for this diagnosis.", "이 진단에는 검사 기록이 없습니다."),
    "nc_title": ("Also not examined", "그 밖에 확인하지 못한 것"),
    "dom_CONCURRENCY": ("Threads and locks", "스레드와 락"), "dom_MEMORY_GROWTH": ("Memory growth", "메모리 증가"),
    "dom_MEMORY_INTEGRITY": ("Memory integrity", "메모리 무결성"), "dom_ABNORMAL_STATE": ("Program state", "프로그램 상태"),
    "dom_OTHER": ("Other", "기타"),
    # collapsed blocks of detailed records (the records themselves are in English)
    "d_verdict": ("How the verdict was derived (detailed records, English)", "판정 근거 상세 (상세 기록, 영문)"),
    "d_finding": ("Detailed evidence for this finding (English)", "이 발견의 상세 근거 (영문)"),
    "d_check": ("Detailed result of this check (English)", "이 검사의 상세 결과 (영문)"),
    "d_scope": ("Check totals and limitations (detailed records, English)", "검사 집계와 제한 사항 (상세 기록, 영문)"),
    "d_method": ("Target, collection and plan (detailed records, English)", "대상·수집·계획 상세 (상세 기록, 영문)"),
    "d_other": ("Other detailed records (English)", "그 밖의 상세 기록 (영문)"),
    "d_repro": ("Exact start and end time of every check (detailed records, English)",
                "검사별 정확한 시작·종료 시각 (상세 기록, 영문)"),
}

# recipe id -> (domain, name en, name ko, looks-for en, looks-for ko)
_RECIPES: Dict[str, Tuple[str, str, str, str, str]] = {
    "RECIPE_THREAD_STATE_ANOMALIES": ("CONCURRENCY", "Thread state anomalies", "스레드 상태 이상",
        "threads that spin without progress, zombie threads, threads stuck in an abnormal state",
        "진전 없이 도는 스레드, 좀비 스레드, 비정상 상태에 머문 스레드"),
    "RECIPE_LONG_RUNNING_BLOCKED_THREADS": ("CONCURRENCY", "Long-blocked threads", "오래 막힌 스레드",
        "threads blocked on a lock whose owner makes no progress", "락 소유자가 진행하지 않는데 그 락을 기다리는 스레드"),
    "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP": ("CONCURRENCY", "Suspicious lock ownership", "의심스러운 락 소유",
        "locks held by a dead or invalid owner, or held in a circle", "죽었거나 잘못된 소유자가 잡은 락, 원형으로 잡힌 락"),
    "RECIPE_POTENTIAL_DEADLOCK_PATTERNS": ("CONCURRENCY", "Deadlock (wait-for cycle)", "교착 상태(대기 고리)",
        "a closed chain of threads each waiting for a lock the next one holds", "각 스레드가 다음 스레드가 잡은 락을 기다리는 닫힌 고리"),
    "RECIPE_SHARED_STATE_INCONSISTENCIES": ("CONCURRENCY", "Shared-state inconsistency", "공유 상태 불일치",
        "shared data that changes in a way a correct locking discipline would not allow", "올바른 락 규칙에서는 나올 수 없는 공유 데이터 변화"),
    "RECIPE_PROCESS_MEMORY_GROWTH": ("MEMORY_GROWTH", "Process memory growth", "프로세스 메모리 증가",
        "resident memory (RSS) that keeps rising over the observation", "관측하는 동안 계속 늘어나는 상주 메모리(RSS)"),
    "RECIPE_HEAP_GROWTH": ("MEMORY_GROWTH", "Heap growth", "힙 증가",
        "heap blocks in use that keep accumulating between heap walks", "힙 조사 사이에 계속 쌓이는 사용 중 블록"),
    "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION": ("MEMORY_GROWTH", "Accumulating long-lived objects", "오래 남는 객체 누적",
        "objects that stay referenced and only increase in number", "참조가 유지된 채 개수만 늘어나는 객체"),
    "RECIPE_OBJECT_LIFETIME_ANOMALIES": ("MEMORY_GROWTH", "Object lifetime anomalies", "객체 수명 이상",
        "objects released too early or kept too long (needs allocation tracing)", "너무 일찍 해제되거나 너무 오래 유지되는 객체(할당 추적 필요)"),
    "RECIPE_ALLOCATION_FREE_IMBALANCE": ("MEMORY_GROWTH", "Allocation / free imbalance", "할당·해제 불균형",
        "more allocations than frees over time (needs allocation tracing)", "시간에 따라 해제보다 많은 할당(할당 추적 필요)"),
    "RECIPE_REPEATED_ALLOCATION_PATTERNS": ("MEMORY_GROWTH", "Repeated allocation pattern", "반복 할당 패턴",
        "the same allocation repeating without a matching release", "짝이 되는 해제 없이 반복되는 같은 할당"),
    "RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS": ("MEMORY_GROWTH", "Suspicious allocation pattern", "의심스러운 할당 패턴",
        "allocation sizes or counts that do not fit normal use", "정상 사용에 맞지 않는 할당 크기·횟수"),
    "RECIPE_HEAP_METADATA_CORRUPTION": ("MEMORY_INTEGRITY", "Heap metadata integrity", "힙 메타데이터 무결성",
        "damaged heap block headers, the usual trace of a write past the end of a buffer", "손상된 힙 블록 헤더(버퍼 끝을 넘은 쓰기의 전형적 흔적)"),
    "RECIPE_FREED_MEMORY_USE": ("MEMORY_INTEGRITY", "Use of freed memory", "해제된 메모리 사용",
        "pointers that still refer to freed blocks, and writes into freed blocks", "해제된 블록을 여전히 가리키는 포인터, 해제된 블록에 대한 쓰기"),
    "RECIPE_USE_AFTER_FREE": ("MEMORY_INTEGRITY", "Use after free (traced)", "해제 후 사용(추적 기반)",
        "an access to a block after its free, seen by tracing allocation events", "할당 이벤트 추적으로 확인하는 해제 이후 접근"),
    "RECIPE_DOUBLE_FREE": ("MEMORY_INTEGRITY", "Double free", "이중 해제",
        "the same block freed twice", "같은 블록의 두 번 해제"),
    "RECIPE_INVALID_FREE": ("MEMORY_INTEGRITY", "Invalid free", "잘못된 해제",
        "free of an address that was never returned by the allocator", "할당자가 돌려준 적 없는 주소의 해제"),
    "RECIPE_INVALID_MEMORY_ACCESS": ("MEMORY_INTEGRITY", "Invalid memory access", "잘못된 메모리 접근",
        "signs of access to unmapped or protected memory", "매핑되지 않았거나 보호된 메모리에 접근한 흔적"),
    "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS": ("MEMORY_INTEGRITY", "Null or invalid pointers", "널·잘못된 포인터",
        "pointer variables holding null or an address outside any mapping", "널이거나 어떤 매핑에도 속하지 않는 주소를 담은 포인터 변수"),
    "RECIPE_SUSPICIOUS_BOUNDARY_VALUES": ("MEMORY_INTEGRITY", "Suspicious boundary values", "의심스러운 경계 값",
        "indexes and lengths at or beyond the limits of their buffers", "버퍼 한계에 닿았거나 넘어선 인덱스·길이"),
    "RECIPE_UNEXPECTED_VARIABLE_CHANGES": ("ABNORMAL_STATE", "Unexpected variable changes", "예상 밖 변수 변화",
        "variables that leave their expected range", "예상 범위를 벗어나는 변수"),
    "RECIPE_STATE_TRANSITION_VIOLATIONS": ("ABNORMAL_STATE", "State transition violations", "상태 전이 위반",
        "a state machine that makes a transition its rules do not allow", "규칙상 허용되지 않는 상태 기계 전이"),
    "RECIPE_INCONSISTENT_RELATED_VARIABLES": ("ABNORMAL_STATE", "Inconsistent related variables", "연관 변수 불일치",
        "variables that should agree with each other but do not", "서로 맞아야 하는데 맞지 않는 변수"),
}

_DOMAIN_ORDER = ("CONCURRENCY", "MEMORY_INTEGRITY", "MEMORY_GROWTH", "ABNORMAL_STATE", "OTHER")
_STATUS_ORDER = ("FAIL", "INCONCLUSIVE", "PASS", "SKIPPED")   # = human_report.CHECK_GROUPS
_STATUS_ICON = {"FAIL": "✖", "PASS": "✔", "INCONCLUSIVE": "?", "SKIPPED": "–", "ERROR": "!"}
_THREAD_COLORS = ("#2563eb", "#9333ea", "#0d9488", "#c2410c", "#be185d", "#4d7c0f")
_VERDICT_TONE = {"CONFIRMED_FAULT": "bad", "FAULT": "bad", "PROBABLE_FAULT": "warn", "DEGRADED": "warn",
                 "HEALTHY": "good", "INCONCLUSIVE": "unk", "ABORTED": "unk"}

_CSS = """
.dsv { --bg:#ffffff; --panel:#f8fafc; --ink:#0f172a; --mute:#64748b; --line:#cbd5e1; --soft:#e2e8f0;
  --bad:#b91c1c; --bad-bg:#fee2e2; --warn:#b45309; --warn-bg:#fef3c7; --good:#15803d; --good-bg:#dcfce7;
  --unk:#475569; --unk-bg:#e2e8f0; --buf:#dbeafe; --buf-line:#3b82f6; --hdr:#e2e8f0; --accent:#2563eb;
  max-width: 1100px; margin: 0 auto 24px; color: var(--ink);
  font: 15px/1.6 -apple-system, "Segoe UI", "Noto Sans KR", "Apple SD Gothic Neo", sans-serif; }
@media (prefers-color-scheme: dark) {
  .dsv { --bg:#0f172a; --panel:#1e293b; --ink:#e2e8f0; --mute:#94a3b8; --line:#475569; --soft:#334155;
    --bad:#f87171; --bad-bg:#450a0a; --warn:#fbbf24; --warn-bg:#451a03; --good:#4ade80; --good-bg:#052e16;
    --unk:#cbd5e1; --unk-bg:#334155; --buf:#1e3a8a; --buf-line:#60a5fa; --hdr:#334155; --accent:#60a5fa; }
}
.dsv *, .dsv *::before, .dsv *::after { box-sizing: border-box; }
.dsv code, .dsv .dsv-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
.dsv code { background: var(--soft); padding: 1px 5px; border-radius: 4px; overflow-wrap: anywhere; }
.dsv h2 { font-size: 20px; margin: 28px 0 10px; padding: 0; border: 0; color: var(--ink); }
.dsv h3 { font-size: 16px; margin: 0 0 8px; color: var(--ink); }
.dsv h4 { font-size: 14px; margin: 18px 0 6px; color: var(--ink); }
.dsv p { margin: 6px 0; }
.dsv-card { background: var(--bg); border: 1px solid var(--line); border-radius: 10px; padding: 18px 22px; margin: 14px 0; }
.dsv-hero { border-left: 8px solid var(--tone); }
.dsv-tone-bad { --tone: var(--bad); --tone-bg: var(--bad-bg); } .dsv-tone-warn { --tone: var(--warn); --tone-bg: var(--warn-bg); }
.dsv-tone-good { --tone: var(--good); --tone-bg: var(--good-bg); } .dsv-tone-unk { --tone: var(--unk); --tone-bg: var(--unk-bg); }
.dsv-title { font-size: 22px; font-weight: 700; margin: 0 0 4px; border: 0; padding: 0; line-height: 1.3; overflow-wrap: anywhere; }
.dsv-badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-weight: 700; font-size: 13px;
  background: var(--tone-bg); color: var(--tone); border: 1px solid var(--tone); white-space: nowrap; }
.dsv-chip { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; border: 1px solid var(--line);
  color: var(--mute); background: var(--panel); white-space: nowrap; }
.dsv-chip-obs { color: var(--good); border-color: var(--good); } .dsv-chip-rec { color: var(--warn); border-color: var(--warn); }
.dsv-chip-no { color: var(--unk); border-style: dashed; }
.dsv-concl { font-size: 17px; margin: 10px 0 14px; }
.dsv-tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
.dsv-tile { background: var(--panel); border: 1px solid var(--soft); border-radius: 8px; padding: 10px 12px; }
.dsv-tile b { display: block; font-size: 20px; line-height: 1.3; }
.dsv-tile span { font-size: 12px; color: var(--mute); }
.dsv-bar { display: flex; height: 10px; border-radius: 5px; overflow: hidden; background: var(--soft); margin: 6px 0 2px; }
.dsv-bar i { display: block; height: 100%; }
.dsv-s-FAIL { --sc: var(--bad); --sb: var(--bad-bg); } .dsv-s-PASS { --sc: var(--good); --sb: var(--good-bg); }
.dsv-s-INCONCLUSIVE { --sc: var(--warn); --sb: var(--warn-bg); } .dsv-s-SKIPPED { --sc: var(--unk); --sb: var(--unk-bg); }
.dsv-s-ERROR { --sc: var(--bad); --sb: var(--bad-bg); }
.dsv-bar i { background: var(--sc); }
.dsv-nav { display: flex; flex-wrap: wrap; gap: 6px 14px; font-size: 13px; margin-top: 14px; }
.dsv-nav a { color: var(--accent); text-decoration: none; } .dsv-nav a:hover { text-decoration: underline; }
.dsv-fhead { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 6px; }
.dsv-fhead h3 { margin: 0; }
.dsv-note { font-size: 13px; color: var(--mute); }
.dsv-legend { display: flex; flex-wrap: wrap; gap: 4px 14px; font-size: 12px; color: var(--mute); margin: 8px 0 0; }
.dsv-facts { margin: 8px 0 0; padding-left: 20px; font-size: 14px; } .dsv-facts li { margin: 3px 0; }
/* stepper and filter: hidden radio inputs, labels drawn as buttons */
.dsv-r { position: absolute; opacity: 0; width: 1px; height: 1px; margin: 0; pointer-events: none; }
.dsv-r + label { display: inline-block; font-size: 13px; padding: 3px 12px; margin: 0 4px 8px 0; border-radius: 6px; cursor: pointer;
  border: 1px solid var(--line); background: var(--panel); color: var(--ink); user-select: none; }
.dsv-r + label:hover { border-color: var(--accent); }
.dsv-r:checked + label { background: var(--ink); color: var(--bg); border-color: var(--ink); }
.dsv-r:focus-visible + label { outline: 2px solid var(--accent); outline-offset: 2px; }
.dsv-r + label .dsv-n { font-weight: 700; margin-left: 5px; }
.dsv-steplbl { font-size: 13px; color: var(--mute); margin-right: 6px; }
@keyframes dsv-appear { from { opacity: 0; } to { opacity: 1; } }
@media (prefers-reduced-motion: no-preference) {
  .dsv-rplay:checked ~ [data-step], .dsv-rplay:checked ~ * [data-step] { animation: dsv-appear .45s both; animation-delay: calc(var(--d) * 1.1s); }
}
.dsv-seq { display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); gap: 18px; align-items: start; }
@media (max-width: 820px) { .dsv-seq { grid-template-columns: minmax(0, 1fr); } }
.dsv-svgbox { overflow-x: auto; border: 1px solid var(--soft); border-radius: 8px; background: var(--panel); padding: 6px; }
.dsv svg { display: block; max-width: 100%; height: auto; }
.dsv svg text { fill: var(--ink); font-family: -apple-system, "Segoe UI", "Noto Sans KR", sans-serif; }
.dsv svg .dsv-t-mute { fill: var(--mute); } .dsv svg .dsv-t-bad { fill: var(--bad); font-weight: 700; }
.dsv svg .dsv-t-on { fill: #ffffff; font-weight: 700; }
.dsv svg .dsv-life { stroke: var(--line); stroke-width: 1.5; stroke-dasharray: 4 4; }
.dsv svg .dsv-lockbox { fill: var(--bg); stroke: var(--ink); stroke-width: 1.5; }
.dsv svg .dsv-arrow { stroke: var(--ink); stroke-width: 2; fill: none; }
.dsv svg .dsv-arrow-bad { stroke: var(--bad); stroke-width: 2; stroke-dasharray: 6 4; fill: none; }
.dsv svg .dsv-blocked { stroke: var(--bad); stroke-width: 5; }
.dsv svg .dsv-banner { fill: var(--bad-bg); stroke: var(--bad); stroke-width: 1.5; }
.dsv svg .dsv-grid { stroke: var(--soft); stroke-width: 1; } .dsv svg .dsv-axis { stroke: var(--line); stroke-width: 1.5; }
.dsv svg .dsv-area { fill: var(--bad-bg); } .dsv svg .dsv-linep { stroke: var(--bad); stroke-width: 2.5; fill: none; }
.dsv svg .dsv-pt { fill: var(--bg); stroke: var(--bad); stroke-width: 2.5; } .dsv svg .dsv-pt:hover { fill: var(--bad); }
.dsv-steps { list-style: none; counter-reset: dsvs; margin: 0; padding: 0; }
.dsv-steps li { counter-increment: dsvs; position: relative; padding: 8px 10px 8px 42px; border: 1px solid transparent; border-radius: 8px; }
.dsv-steps li::before { content: counter(dsvs); position: absolute; left: 8px; top: 8px; width: 24px; height: 24px; border-radius: 50%;
  background: var(--soft); color: var(--ink); font-size: 13px; font-weight: 700; text-align: center; line-height: 24px; }
.dsv-steps .dsv-sub { display: block; font-size: 13px; color: var(--mute); }
/* thread strip */
.dsv-tbl { width: 100%; border-collapse: collapse; font-size: 13px; margin: 6px 0; }
.dsv-tbl th, .dsv-tbl td { border: 0; border-bottom: 1px solid var(--soft); padding: 6px 8px; text-align: left; vertical-align: middle; background: none; }
.dsv-tbl th { color: var(--mute); font-weight: 600; font-size: 12px; }
.dsv-tbl tr.dsv-hot td:first-child { box-shadow: inset 4px 0 0 var(--bad); }
.dsv-scroll { overflow-x: auto; }
.dsv-scroll > .dsv-tbl { min-width: 560px; }   /* narrow screens scroll the table instead of squeezing it */
.dsv-smp { display: inline-flex; gap: 2px; vertical-align: middle; }
.dsv-smp i { display: inline-block; width: 16px; height: 16px; border-radius: 3px; font-style: normal; font-size: 10px; line-height: 16px;
  text-align: center; color: #ffffff; background: var(--unk); }
.dsv-smp .dsv-st-R { background: var(--good); color: #052e16; } .dsv-smp .dsv-st-S { background: #94a3b8; }
.dsv-smp .dsv-st-D { background: var(--warn); color: #451a03; } .dsv-smp .dsv-st-Z, .dsv-smp .dsv-st-T { background: var(--bad); }
.dsv-meter { display: inline-block; width: 70px; height: 8px; border-radius: 4px; background: var(--soft); vertical-align: middle; overflow: hidden; }
.dsv-meter i { display: block; height: 100%; background: var(--accent); }
/* memory map */
.dsv-mem { display: flex; align-items: flex-end; gap: 0; overflow-x: auto; padding: 8px 2px 4px; }
.dsv-seg { flex: 0 0 auto; }
.dsv-seg > span { display: block; font-size: 12px; font-weight: 600; padding: 0 4px 3px; white-space: nowrap; }
.dsv-seg-over > span { color: var(--bad); } .dsv-seg-buf > span { color: var(--buf-line); }
.dsv-cells { display: flex; }
.dsv-cell { width: 62px; height: 66px; border: 1px solid var(--line); margin-right: -1px; padding: 3px 4px; font-size: 11px; line-height: 1.25;
  display: flex; flex-direction: column; justify-content: space-between; background: var(--bg); overflow: hidden; }
.dsv-cell b { font-size: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
.dsv-cell small { color: var(--mute); font-size: 10px; white-space: nowrap; }
.dsv-c-hdr { background: var(--hdr); } .dsv-c-buf { background: var(--buf); border-color: var(--buf-line); }
.dsv-c-over { background: repeating-linear-gradient(135deg, var(--bad-bg), var(--bad-bg) 6px, var(--bg) 6px, var(--bg) 12px);
  border-color: var(--bad); color: var(--bad); }
.dsv-c-over small { color: var(--bad); }
.dsv-c-gap { width: 96px; border-style: dashed; justify-content: center; text-align: center; color: var(--mute); }
.dsv-c-rest { border-style: dashed; color: var(--mute); justify-content: center; text-align: center; }
.dsv-wall { flex: 0 0 auto; align-self: stretch; width: 0; border-left: 3px solid var(--bad); margin: 0 5px 0 6px; position: relative; }
.dsv-memaxis { display: flex; justify-content: space-between; font-size: 12px; color: var(--mute); margin: 2px 2px 0; }
/* pointer diagram */
.dsv-ptr { display: flex; flex-wrap: wrap; align-items: stretch; gap: 8px; margin: 8px 0; }
.dsv-box { border: 2px solid var(--line); border-radius: 8px; padding: 8px 12px; background: var(--panel); min-width: 150px; }
.dsv-box small { display: block; color: var(--mute); font-size: 12px; }
.dsv-box-bad { border-color: var(--bad); background: var(--bad-bg); }
.dsv-arrowtxt { align-self: center; font-size: 12px; color: var(--mute); text-align: center; white-space: nowrap; }
.dsv-arrowtxt b { display: block; font-size: 20px; line-height: 1; color: var(--ink); }
.dsv-life { display: flex; flex-wrap: wrap; gap: 0; margin: 12px 0 4px; font-size: 13px; }
.dsv-life div { padding: 5px 14px 5px 18px; background: var(--panel); border: 1px solid var(--line); margin-right: -1px; }
.dsv-life div.dsv-on { background: var(--bad-bg); border-color: var(--bad); color: var(--bad); font-weight: 600; z-index: 1; }
.dsv-life div.dsv-maybe { border-style: dashed; color: var(--mute); }
/* checklist */
.dsv-ckgroup > h4 { display: flex; align-items: baseline; gap: 8px; margin: 18px 0 4px; }
.dsv-ckgroup > h4 small { font-weight: 400; color: var(--mute); font-size: 12px; }
.dsv-dot { display: inline-flex; width: 22px; height: 22px; border-radius: 50%; align-items: center; justify-content: center; flex: 0 0 22px;
  font-size: 13px; font-weight: 700; background: var(--sb); color: var(--sc); border: 1.5px solid var(--sc); }
details.dsv-ck { border: 1px solid var(--soft); border-left: 4px solid var(--sc); border-radius: 6px; margin: 4px 0; padding: 0; background: var(--bg); font-size: 14px; }
details.dsv-ck > summary { list-style: none; cursor: pointer; display: flex; align-items: center; gap: 10px; padding: 7px 12px; font-weight: 400; }
details.dsv-ck > summary::-webkit-details-marker { display: none; }
details.dsv-ck > summary::after { content: "▸"; margin-left: auto; color: var(--mute); }
details.dsv-ck[open] > summary::after { content: "▾"; }
details.dsv-ck > summary:hover { background: var(--panel); }
.dsv-ck-name { font-weight: 600; } .dsv-ck-line { color: var(--mute); font-size: 13px; overflow-wrap: anywhere; }
.dsv-ck-main { display: flex; flex-direction: column; min-width: 0; }
.dsv-ck dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 4px 14px; margin: 0; padding: 4px 14px 12px 44px; font-size: 13px; }
.dsv-ck dt { color: var(--mute); } .dsv-ck dd { margin: 0; overflow-wrap: anywhere; }
.dsv-nc { font-size: 13px; padding-left: 20px; } .dsv-nc li { margin: 3px 0; overflow-wrap: anywhere; }
/* outline: one section per part of the report, numbered like the Markdown report */
.dsv-head { margin: 8px 0 4px; }
.dsv-sec > h2 { font-size: 20px; margin: 30px 0 10px; padding: 0 0 4px; border-bottom: 1px solid var(--soft); }
.dsv-sec h3 { font-size: 16px; margin: 14px 0 6px; }
.dsv-text p, .dsv-card > p { margin: 6px 0; }
.dsv-text ol, .dsv-text ul, .dsv-card > ul, .dsv-card > ol { padding-left: 22px; margin: 6px 0; }
.dsv-text pre, .dsv-card pre { background: var(--panel); border: 1px solid var(--soft); border-radius: 6px; padding: 8px 10px; overflow-x: auto; font-size: 12px; }
.dsv-keyfacts { list-style: none; padding-left: 0 !important; }
.dsv-tile-sub { display: block; }
details.dsv-ckgroup { margin: 10px 0; }
details.dsv-ckgroup > summary { cursor: pointer; display: flex; align-items: baseline; flex-wrap: wrap; gap: 8px; font-weight: 600; padding: 6px 0; }
details.dsv-ckgroup > summary small { font-weight: 400; color: var(--mute); font-size: 12px; }
/* detailed records (English) attached to the part they belong to */
details.dsv-detail { margin: 10px 0 2px; border: 1px dashed var(--line); border-radius: 8px; background: var(--panel); }
details.dsv-detail > summary { cursor: pointer; padding: 6px 12px; font-size: 13px; color: var(--accent); }
.dsv-detail-body { padding: 4px 12px 10px; font-size: 12px; overflow-wrap: anywhere; }
.dsv-detail-body h4 { font-size: 13px; margin: 10px 0 4px; }
.dsv-detail-body p { margin: 4px 0; }
.dsv-detail-body .dsd-scroll { overflow-x: auto; }
.dsv-detail-body table { border-collapse: collapse; width: 100%; min-width: 520px; margin: 4px 0; }
.dsv-detail-body th, .dsv-detail-body td { border: 1px solid var(--soft); padding: 4px 6px; text-align: left; vertical-align: top; }
.dsv-detail-body td code { white-space: pre-wrap; word-break: break-all; }
.dsv-detail-body .dsd-pre { white-space: pre-wrap; word-break: break-all; }
.dsv-ck .dsv-detail { margin: 0 14px 10px 44px; }
@media (max-width: 600px) {
  .dsv-card { padding: 14px 14px; }
  .dsv-ck dl { padding-left: 14px; grid-template-columns: minmax(0, 1fr); }
  .dsv-ck .dsv-detail { margin: 0 8px 10px 8px; }
  .dsv-title { font-size: 19px; }
}
@media print {
  .dsv-r, .dsv-r + label, .dsv-steplbl, .dsv-nav { display: none !important; }
  .dsv-card { break-inside: avoid; }
  .dsv [data-step], .dsv [data-step] > * { visibility: visible !important; opacity: 1 !important; animation: none !important; }
  .dsv-ckgroup { display: block !important; }
}
"""

_MAX_STEPS = 16


def _interaction_css() -> str:
    """Stepping and filtering without any script: radio inputs drive sibling selectors.

    An element that belongs to step k carries ``dsv-h1 .. dsv-h(k-1)`` (hidden while an earlier step is selected) and
    ``dsv-c{k}`` (highlighted while step k is selected).
    """
    out = []
    for j in range(1, _MAX_STEPS + 1):
        r = f".dsv-r{j}:checked ~"
        out.append(f"{r} .dsv-h{j}, {r} * .dsv-h{j} {{ visibility: hidden; }}")
        out.append(f"{r} * li.dsv-h{j} {{ visibility: visible; opacity: .3; }}")
        out.append(f"{r} * .dsv-cell.dsv-h{j} {{ visibility: visible; background: var(--bg) !important; "
                   f"border-color: var(--line); }}")
        out.append(f"{r} * .dsv-cell.dsv-h{j} > * {{ visibility: hidden; }}")
        out.append(f"{r} * li.dsv-c{j} {{ border-color: var(--accent); background: var(--panel); }}")
    return "\n".join(out)


class _Lx:
    """Label lookup for one language."""

    def __init__(self, lang: str):
        self.lang = lang
        self.i = 1 if lang == "ko" else 0

    def t(self, key: str, **kw: Any) -> str:
        s = _L[key][self.i]
        return s.format(**kw) if kw else s

    def h(self, key: str, **kw: Any) -> str:
        """Label with every argument escaped and wrapped as code; the result is safe HTML."""
        return E(_L[key][self.i]).format(**{k: _code(v) for k, v in kw.items()}) if kw else E(_L[key][self.i])


def _code(x: Any) -> str:
    return f"<code>{E(str(x))}</code>"


def _addr(x: Any) -> Optional[int]:
    try:
        return int(str(x), 16) if isinstance(x, str) else (int(x) if x is not None else None)
    except (TypeError, ValueError):
        return None


def _fnum(x: Any, digits: int = 2) -> str:
    try:
        v = float(x)
    except (TypeError, ValueError):
        return str(x)
    return str(int(v)) if v == int(v) else f"{v:.{digits}f}"


def _size(n: Any) -> str:
    try:
        v = float(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024 or unit == "GB":
            return f"{int(v)} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024.0
    return "?"


def _chip(lx: _Lx, kind: str) -> str:
    key = {"obs": "observed", "rec": "reconstructed", "no": "not_observed"}[kind]
    return f'<span class="dsv-chip dsv-chip-{kind}">{E(lx.t(key))}</span>'


def _sa(k: int, cls: str = "", style: str = "") -> str:
    """Attributes of an element that belongs to step ``k`` of a sequence."""
    classes = " ".join(([cls] if cls else []) + [f"dsv-h{j}" for j in range(1, min(k, _MAX_STEPS + 1))] + [f"dsv-c{k}"])
    return f' data-step="{k}" class="{classes}" style="--d:{k - 1}{";" + style if style else ""}"'


def _stepper_controls(lx: _Lx, uid: str, n: int) -> str:
    """Radio inputs (direct children of the stepper, before the content they control); empty when too long."""
    if n > _MAX_STEPS:
        return ""
    name = f"dsv-step-{E(uid)}"
    out = [f'<input class="dsv-r dsv-rall" type="radio" name="{name}" id="{name}-all" checked>'
           f'<label for="{name}-all">{E(lx.t("step_all"))}</label>',
           f'<input class="dsv-r dsv-rplay" type="radio" name="{name}" id="{name}-play">'
           f'<label for="{name}-play">{E(lx.t("step_play"))}</label>',
           f'<span class="dsv-steplbl">{E(lx.t("step_of"))}</span>']
    out += [f'<input class="dsv-r dsv-r{k}" type="radio" name="{name}" id="{name}-{k}">'
            f'<label for="{name}-{k}" title="{E(lx.t("step_hint"))}">{k}</label>' for k in range(1, n + 1)]
    return "".join(out)


def _legend(lx: _Lx, *kinds: str) -> str:
    parts = []
    if "obs" in kinds:
        parts.append(f"<span>{_chip(lx, 'obs')} {E(lx.t('legend_obs'))}</span>")
    if "rec" in kinds:
        parts.append(f"<span>{_chip(lx, 'rec')} {E(lx.t('legend_rec'))}</span>")
    return f'<div class="dsv-legend">{"".join(parts)}</div>' if parts else ""


# ------------------------------------------------------------------------------------------------ drawing kit
# Helpers a recipe definition file may use for its registered picture (report_registry.register_finding_viz).
def esc(x: Any) -> str:
    """HTML-escape a value from the target."""
    return E(str(x))


def code(x: Any) -> str:
    """An identifier (variable, thread, lock, file:line) as escaped inline code."""
    return _code(x)


def chip(lx: "_Lx", kind: str) -> str:
    """Epistemic tag: 'obs' (observed), 'rec' (reconstructed) or 'no' (not observed)."""
    return _chip(lx, kind)


def facts_list(items: List[str]) -> str:
    """A bullet list; every item must already be safe HTML (build it with esc/code)."""
    return f'<ul class="dsv-facts">{"".join(f"<li>{x}</li>" for x in items)}</ul>' if items else ""


def series_chart(xs: List[float], ys: List[float], title: str, x_label: str, y_label: str,
                 tips: Optional[List[str]] = None, unit: str = "") -> str:
    """Zero-based area chart of an observed series (at least two points); labels are escaped here."""
    if len(xs) < 2 or len(xs) != len(ys):
        return ""
    w, h, ml, mr, mt, mb = 640, 246, 62, 20, 34, 42
    xmax = (max(xs) - min(xs)) or 1.0
    x0 = min(xs)
    ymax = (max(ys) * 1.1) or 1.0
    px = lambda v: ml + (w - ml - mr) * (v - x0) / xmax  # noqa: E731
    py = lambda v: mt + (h - mt - mb) * (1 - v / ymax)  # noqa: E731
    s = [f'<svg viewBox="0 0 {w} {h}" width="{w}" role="img" aria-label="{E(title)}">']
    for i in range(5):
        v = ymax * i / 4
        s.append(f'<line class="dsv-grid" x1="{ml}" y1="{py(v):.1f}" x2="{w - mr}" y2="{py(v):.1f}"/>'
                 f'<text class="dsv-t-mute" x="{ml - 8}" y="{py(v) + 4:.1f}" text-anchor="end" font-size="11">{v:,.0f}</text>')
    s.append(f'<line class="dsv-axis" x1="{ml}" y1="{py(0):.1f}" x2="{w - mr}" y2="{py(0):.1f}"/>')
    pts = " ".join(f"{px(a):.1f},{py(b):.1f}" for a, b in zip(xs, ys))
    s.append(f'<polygon class="dsv-area" points="{px(xs[0]):.1f},{py(0):.1f} {pts} {px(xs[-1]):.1f},{py(0):.1f}"/>'
             f'<polyline class="dsv-linep" points="{pts}"/>')
    for i, (a, b) in enumerate(zip(xs, ys)):
        tip = f"<title>{E(tips[i])}</title>" if tips and i < len(tips) else ""
        s.append(f'<circle class="dsv-pt" cx="{px(a):.1f}" cy="{py(b):.1f}" r="5">{tip}</circle>'
                 f'<text class="dsv-t-mute" x="{px(a):.1f}" y="{h - mb + 16}" text-anchor="middle" font-size="11">+{a - x0:.2f}</text>')
    for i, anchor in ((0, "start"), (len(ys) - 1, "end")):
        s.append(f'<text x="{px(xs[i]) + (8 if i == 0 else -8):.1f}" y="{py(ys[i]) - 10:.1f}" text-anchor="{anchor}" '
                 f'font-size="12" font-weight="700">{ys[i]:,.0f}{E(unit)}</text>')
    s.append(f'<text class="dsv-t-mute" x="{(ml + w - mr) / 2}" y="{h - 6}" text-anchor="middle" font-size="11">{E(x_label)}</text>'
             f'<text class="dsv-t-mute" x="12" y="14" font-size="11">{E(y_label)}</text></svg>')
    return f'<div class="dsv-svgbox">{"".join(s)}</div>'


def share_bars(items: List[Tuple[str, float]], unit: str = "") -> str:
    """Horizontal bars for a few labelled quantities (label escaped here)."""
    top = max((v for _, v in items), default=0) or 1.0
    rows = "".join(f'<tr><td>{_code(k)}</td><td style="width:60%"><span class="dsv-meter" style="width:100%">'
                   f'<i style="width:{max(0.0, min(100.0, v * 100 / top)):.0f}%"></i></span></td>'
                   f'<td>{_fnum(v)}{E(unit)}</td></tr>' for k, v in items)
    return f'<div class="dsv-scroll"><table class="dsv-tbl"><tbody>{rows}</tbody></table></div>' if rows else ""


def thread_strip(lx: "_Lx", finding: Dict[str, Any], report: Optional[Dict[str, Any]], hot_tids: List[Any]) -> str:
    """The per-sample thread state table, with ``hot_tids`` marked."""
    return _thread_strip(lx, _thread_rows(report, finding.get("recipe_ids")), hot_tids, _sampling(report, finding))


def observations(report: Optional[Dict[str, Any]], finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The observation dicts of the checks behind a finding."""
    return _observations(report, finding.get("recipe_ids"))


# ------------------------------------------------------------------------------------------------ thread strip
def _thread_strip(lx: _Lx, rows: Dict[int, Dict[str, Any]], hot: List[Any], sampling: Tuple[Any, Any]) -> str:
    rows = {tid: r for tid, r in rows.items() if isinstance(r.get("states"), list) and r["states"]}
    if not rows:
        return ""
    order = [t for t in hot if t in rows] + [t for t in rows if t not in hot]
    body = []
    for tid in order[:16]:
        r = rows[tid]
        cells = []
        for st in r["states"][:40]:
            s = str(st)[:1].upper()
            key = "ts_" + s if ("ts_" + s) in _L else "ts_other"
            cells.append(f'<i class="dsv-st-{E(s)}" title="{E(lx.t(key))}">{E(s)}</i>')
        where = []
        fn, loc = r.get("top_function") or r.get("function"), r.get("top_source_location")
        if fn:
            where.append(_code(fn) + (f" {_code(loc)}" if loc else ""))
        if r.get("top_source_text") and r.get("top_source_line_exact"):
            where.append(_code(str(r["top_source_text"]).strip()))
        if r.get("waiting_on_lock"):
            where.append(lx.h("ts_waits_lock", lock=r["waiting_on_lock"]))
        elif r.get("syscall"):
            where.append(_code(r["syscall"]))
        share = r.get("cpu_share")
        try:
            pct = max(0.0, min(100.0, float(share) * 100.0)) if share is not None else None
        except (TypeError, ValueError):
            pct = None
        cpu = (f'<span class="dsv-meter"><i style="width:{pct:.0f}%"></i></span> {pct:.0f}%' if pct is not None else "")
        if r.get("judgement_basis") == "schedstat_runnable_fraction_dispatches" and isinstance(r.get("cpu_dispatches"), int):
            # a yield-polling busy wait: its CPU share depends on the host load, so show what was judged instead
            try:
                run = max(0.0, min(100.0, float(r.get("runnable_fraction") or 0.0) * 100.0))
            except (TypeError, ValueError):
                run = 0.0
            cpu = (f'<span class="dsv-meter"><i style="width:{run:.0f}%"></i></span> '
                   f'{E(lx.t("ts_runnable", p=round(run)))}<br><span class="dsv-note">'
                   f'{E(lx.t("ts_dispatches", n=r["cpu_dispatches"]))}</span>')
        elif r.get("runnable_fraction") is not None and pct is not None and pct >= 1:
            try:
                cpu += f'<br><span class="dsv-note">{E(lx.t("ts_runnable", p=round(float(r["runnable_fraction"]) * 100)))}</span>'
            except (TypeError, ValueError):
                pass
        tag = f' <span class="dsv-chip">{E(lx.t("ts_in_cycle"))}</span>' if tid in hot and len(hot) > 1 else ""
        body.append(f'<tr class="{"dsv-hot" if tid in hot else ""}"><td>{_code(r.get("name") or tid)} '
                    f'<span class="dsv-note">tid {E(str(tid))}</span>{tag}</td>'
                    f'<td><span class="dsv-smp">{"".join(cells)}</span></td><td>{cpu}</td><td>{"<br>".join(where)}</td></tr>')
    n, win = sampling
    sub = f' <span class="dsv-note">{E(lx.t("ts_sub", n=n, win=_fnum(win)))}</span>' if n and win is not None else ""
    used = sorted({str(st)[:1].upper() for r in rows.values() for st in r["states"]})
    legend = "".join(f'<span><span class="dsv-smp"><i class="dsv-st-{E(s)}">{E(s)}</i></span> '
                     f'{E(lx.t("ts_" + s if ("ts_" + s) in _L else "ts_other"))}</span>' for s in used)
    return (f'<h4>{E(lx.t("ts_title"))}{sub}</h4><div class="dsv-scroll"><table class="dsv-tbl"><thead><tr>'
            f'<th>{E(lx.t("ts_thread"))}</th><th>{E(lx.t("ts_samples"))}</th><th>{E(lx.t("ts_cpu"))}</th>'
            f'<th>{E(lx.t("ts_doing"))}</th></tr></thead><tbody>{"".join(body)}</tbody></table></div>'
            f'<div class="dsv-legend">{legend}</div>')


def _sampling(report: Optional[Dict[str, Any]], f: Dict[str, Any]) -> Tuple[Any, Any]:
    for o in _observations(report, f.get("recipe_ids")):
        ts = o.get("thread_sampling")
        if isinstance(ts, dict) and ts.get("samples_collected"):
            return ts.get("samples_collected"), ts.get("window_sec")
    return None, None


# ------------------------------------------------------------------------------------------------ deadlock
def _viz_deadlock(lx: _Lx, f: Dict[str, Any], report: Optional[Dict[str, Any]], uid: str = "0") -> str:
    cyc, obs = _cycle(report, f.get("recipe_ids"))
    rows = _thread_rows(report, f.get("recipe_ids"))
    sampling = _sampling(report, f)
    if not cyc:
        return _thread_strip(lx, rows, [], sampling)
    lock_of = lambda e: str(e.get("lock_name") or e.get("lock_address") or "?")  # noqa: E731
    tids: List[Any] = []
    names: Dict[Any, str] = {}
    for e in cyc:
        for tk, nk in (("waiter_tid", "waiter_name"), ("owner_tid", "owner_name")):
            if e.get(tk) is not None and e[tk] not in tids:
                tids.append(e[tk])
            if e.get(tk) is not None and e.get(nk):
                names.setdefault(e[tk], str(e[nk]))
    dup = len(set(names.values())) < len(names)

    def tlabel(tid: Any) -> str:
        n = names.get(tid)
        return f"{n} ({tid})" if n and dup else (n or f"tid {tid}")

    holds: Dict[Any, List[str]] = {t: [] for t in tids}
    waits: Dict[Any, str] = {}
    for e in cyc:
        if e.get("owner_tid") in holds and lock_of(e) not in holds[e["owner_tid"]]:
            holds[e["owner_tid"]].append(lock_of(e))
        if e.get("waiter_tid") is not None:
            waits.setdefault(e["waiter_tid"], lock_of(e))
    owner_of = {lock_of(e): e.get("owner_tid") for e in cyc}

    # columns: each thread followed by the locks it holds
    cols: List[Tuple[str, Any]] = []
    for t in tids:
        cols.append(("thread", t))
        for lk in holds[t]:
            if ("lock", lk) not in cols:
                cols.append(("lock", lk))
    for lk in waits.values():
        if ("lock", lk) not in cols:
            cols.append(("lock", lk))
    col_w, left, top, row_h = 150, 85, 64, 58
    x = {c: left + i * col_w for i, c in enumerate(cols)}
    acq = [(t, lk) for t in tids for lk in holds[t]]
    wts = [(t, waits[t]) for t in tids if t in waits]
    n_steps = len(acq) + len(wts) + 1
    width = left * 2 + (len(cols) - 1) * col_w
    y_of = lambda k: top + 34 + (k - 1) * row_h  # noqa: E731
    bottom = y_of(n_steps) + 44
    color = {t: _THREAD_COLORS[i % len(_THREAD_COLORS)] for i, t in enumerate(tids)}
    s: List[str] = [f'<svg viewBox="0 0 {width} {bottom + 8}" width="{width}" role="img" '
                    f'aria-label="{E(lx.t("dl_title"))}">',
                    '<defs><marker id="dsv-ah" markerWidth="9" markerHeight="8" refX="8" refY="4" orient="auto">'
                    '<path d="M0,0 L9,4 L0,8 z" fill="context-stroke"/></marker></defs>']
    for c in cols:
        cx = x[c]
        s.append(f'<line class="dsv-life" x1="{cx}" y1="{top}" x2="{cx}" y2="{bottom - 36}"/>')
        if c[0] == "thread":
            s.append(f'<rect x="{cx - 64}" y="14" width="128" height="{top - 22}" rx="8" fill="{color[c[1]]}"/>'
                     f'<text class="dsv-t-on" x="{cx}" y="32" text-anchor="middle" font-size="13">{E(tlabel(c[1])[:17])}</text>'
                     f'<text class="dsv-t-on" x="{cx}" y="48" text-anchor="middle" font-size="10" font-weight="400">'
                     f'{E(lx.t("dl_thread"))} · tid {E(str(c[1]))}</text>')
        else:
            s.append(f'<rect class="dsv-lockbox" x="{cx - 56}" y="18" width="112" height="{top - 30}" rx="3"/>'
                     f'<text x="{cx}" y="34" text-anchor="middle" font-size="13" font-weight="700">{E(str(c[1])[:15])}</text>'
                     f'<text class="dsv-t-mute" x="{cx}" y="47" text-anchor="middle" font-size="10">{E(lx.t("dl_lock"))}</text>')
    steps_html: List[str] = []
    k = 0
    for t, lk in acq:
        k += 1
        y, x1, x2 = y_of(k), x[("thread", t)], x[("lock", lk)]
        d = 1 if x2 > x1 else -1
        s.append(f'<g{_sa(k)}><line class="dsv-arrow" x1="{x1}" y1="{y}" x2="{x2 - d * 7}" y2="{y}" '
                 f'stroke="{color[t]}" style="stroke:{color[t]}" marker-end="url(#dsv-ah)"/>'
                 f'<text x="{(x1 + x2) / 2}" y="{y - 8}" text-anchor="middle" font-size="11">{E(lx.t("dl_lbl_acq"))}</text>'
                 f'<rect x="{x2 - 6}" y="{y}" width="12" height="{bottom - 36 - y}" fill="{color[t]}" opacity="0.85"/>'
                 f'<text class="dsv-t-mute" x="{x2 + 10}" y="{y + 16}" font-size="10">{E(lx.t("dl_held_by", thr=tlabel(t))[:22])}</text></g>')
        steps_html.append(f'<li{_sa(k)}>{lx.h("dl_acq", thr=tlabel(t), lock=lk)} {_chip(lx, "rec")}'
                          f'<span class="dsv-sub">{E(lx.t("dl_acq_note"))}</span></li>')
    for t, lk in wts:
        k += 1
        y, x1, x2 = y_of(k), x[("thread", t)], x[("lock", lk)]
        d = 1 if x2 > x1 else -1
        r = rows.get(t) or {}
        s.append(f'<g{_sa(k)}><line class="dsv-arrow-bad" x1="{x1}" y1="{y}" x2="{x2 - d * 14}" y2="{y}" '
                 f'marker-end="url(#dsv-ah)"/>'
                 f'<text class="dsv-t-bad" x="{(x1 + x2) / 2}" y="{y - 8}" text-anchor="middle" font-size="11">{E(lx.t("dl_lbl_wait"))}</text>'
                 f'<line class="dsv-blocked" x1="{x1}" y1="{y}" x2="{x1}" y2="{bottom - 36}"/>'
                 f'<text class="dsv-t-bad" x="{x1 - d * 8}" y="{y + 18}" text-anchor="{"end" if d > 0 else "start"}" '
                 f'font-size="10">{E(lx.t("dl_blocked"))}</text></g>')
        owner = owner_of.get(lk)
        sub = []
        if r.get("top_source_location"):
            sub.append(lx.h("dl_wait_at", loc=r["top_source_location"])
                       + (f": {_code(str(r['top_source_text']).strip())}"
                          if r.get("top_source_text") and r.get("top_source_line_exact") else ""))
        steps_html.append(f'<li{_sa(k)}>{lx.h("dl_wait", thr=tlabel(t), lock=lk, owner=tlabel(owner))} {_chip(lx, "obs")}'
                          + (f'<span class="dsv-sub">{"".join(sub)}</span>' if sub else "") + "</li>")
    k += 1
    yb = bottom - 30
    s.append(f'<g{_sa(k)}><rect class="dsv-banner" x="12" y="{yb}" width="{width - 24}" height="28" rx="6"/>'
             f'<text class="dsv-t-bad" x="{width / 2}" y="{yb + 19}" text-anchor="middle" font-size="13">'
             f'{E(lx.t("dl_deadlock"))}: {E(" → ".join(tlabel(t) for t in tids + tids[:1])[:90])}</text></g>')
    s.append("</svg>")
    sub = []
    n, win = sampling
    if n and win is not None:
        sub.append(E(lx.t("dl_closed_obs", n=n, win=_fnum(win))))
    if obs.get("cycle_persistent") and obs.get("observation_count"):
        sub.append(E(lx.t("dl_persist", n=obs["observation_count"])))
    steps_html.append(f'<li{_sa(k)}>{E(lx.t("dl_closed"))} {_chip(lx, "obs")}'
                      + (f'<span class="dsv-sub">{" ".join(sub)}</span>' if sub else "") + "</li>")
    return (f'<h4>{E(lx.t("dl_title"))}</h4><div class="dsv-stepper" data-steps="{n_steps}">{_stepper_controls(lx, uid, n_steps)}'
            f'<div class="dsv-seq"><div class="dsv-svgbox">{"".join(s)}</div>'
            f'<ol class="dsv-steps">{"".join(steps_html)}</ol></div></div>'
            f'<p class="dsv-note">{E(lx.t("dl_order_note"))}</p>{_legend(lx, "obs", "rec")}'
            + _thread_strip(lx, rows, tids, sampling))


# ------------------------------------------------------------------------------------------------ heap overflow
def _heap_defects(report: Optional[Dict[str, Any]], f: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for o in _observations(report, f.get("recipe_ids")) or _observations(report):
        heap = ((o.get("memory_integrity") or {}).get("heap") or {}) if isinstance(o.get("memory_integrity"), dict) else {}
        for d in heap.get("defects") or []:
            if isinstance(d, dict) and isinstance(d.get("overflowing_buffer"), dict) and isinstance(d.get("damage"), dict):
                out.append(d)
    return out


def _le_text(hexval: Any) -> Optional[str]:
    """ASCII reading of a 64-bit little-endian field, when every byte is printable."""
    v = _addr(hexval)
    if v is None or v < 0 or v >= 1 << 64:
        return None
    raw = v.to_bytes(8, "little")
    return raw.decode("ascii") if all(32 <= b < 127 for b in raw) else None


def _viz_overflow(lx: _Lx, f: Dict[str, Any], report: Optional[Dict[str, Any]], uid: str = "0") -> str:
    defects = _heap_defects(report, f)
    if not defects:
        return ""
    d = defects[0]
    buf, dmg, victim = d["overflowing_buffer"], d["damage"], d.get("victim") if isinstance(d.get("victim"), dict) else {}
    details = d.get("details") if isinstance(d.get("details"), dict) else {}
    try:
        usable = int(buf.get("usable_size"))
        past = int(dmg.get("bytes_past_usable_end"))
    except (TypeError, ValueError):
        return ""
    ua, ca = _addr(buf.get("user_address")), _addr(buf.get("chunk_address"))
    end = _addr(dmg.get("usable_end")) or ((ua + usable) if ua is not None else None)
    if ua is None or end is None or usable <= 0 or past <= 0:
        return ""
    vca = _addr(victim.get("chunk_address"))
    size_lo = (vca + 8) if vca is not None else end  # the size field of the block behind the buffer
    bname = str(buf.get("variable_path") or buf.get("variable") or lx.t("ov_buf_plain"))
    vname = victim.get("variable_path") or victim.get("variable")
    is_top = str(victim.get("state")) == "top"
    m = re.search(r"repeated byte (0x[0-9a-fA-F]{1,2})", str(dmg.get("pattern") or ""))
    rep = f"{int(m.group(1), 16):02x}" if m else None
    size_val = details.get("observed_size_field")
    W = 8
    hx = lambda a: f"0x{a:x}"  # noqa: E731

    def cell(cls: str, mid: str, low: str, title: str, step: Optional[int] = None, top_lbl: str = "", style: str = "") -> str:
        attrs = (_sa(step, f"dsv-cell {cls}", style) if step is not None
                 else f' class="dsv-cell {cls}"' + (f' style="{style}"' if style else ""))
        return (f'<div{attrs} title="{E(title)}"><small>{E(top_lbl)}</small>'
                f'<b>{E(mid)}</b><small>{E(low)}</small></div>')

    segs: List[str] = []
    if ca is not None and 0 < ua - ca <= 32:
        cells = "".join(cell("dsv-c-hdr", "", "…" + hx(ca + i * W)[-4:], f"{lx.t('ov_hdr')} {hx(ca + i * W)}") for i in range((ua - ca) // W))
        segs.append(f'<div class="dsv-seg"><span>{E(lx.t("ov_hdr"))}</span><div class="dsv-cells">{cells}</div></div>')
    n_buf = max(1, math.ceil(usable / W))
    shown = list(range(n_buf)) if n_buf <= 11 else [0, 1, 2, None] + list(range(n_buf - 4, n_buf))
    cells = ""
    for i in shown:
        if i is None:
            cells += (f'<div{_sa(1, "dsv-cell dsv-c-buf dsv-c-gap")}><b>{E(lx.t("ov_gap", n=(n_buf - 7) * W))}</b></div>')
            continue
        a = ua + i * W
        last = i == n_buf - 1
        mid = f"{rep}×8" if (rep and last and dmg.get("continues_buffer_content")) else "·"
        cells += cell("dsv-c-buf", mid, f"+{i * W}", f"{bname} +{i * W} ({hx(a)}): {lx.t('ov_role_buf')}"
                      + ("" if mid != "·" else f"; {lx.t('ov_not_collected')}"), 1)
    segs.append(f'<div class="dsv-seg dsv-seg-buf"><span>{E(lx.t("ov_buf", name=bname, n=usable))}</span>'
                f'<div class="dsv-cells">{cells}</div></div>')
    segs.append(f'<div class="dsv-wall" title="{E(lx.t("ov_end", addr=hx(end)))}"></div>')
    n_over = math.ceil(past / W)
    over_idx = list(range(n_over)) if n_over <= 9 else [0, 1, 2, None] + list(range(n_over - 3, n_over))
    step_of_cell: Dict[int, int] = {}
    cells = ""
    for j, i in enumerate(over_idx):
        step = 2 + min(j, 1) if n_over > 1 else 2
        if i is None:
            cells += f'<div{_sa(step, "dsv-cell dsv-c-over dsv-c-gap")}><b>{E(lx.t("ov_gap", n=(n_over - 6) * W))}</b></div>'
            continue
        a = end + i * W
        nbytes = min(W, past - i * W)
        if size_lo <= a < size_lo + W:
            role, short = lx.t("ov_role_size"), lx.t("ov_short_size")
            txt = None if rep else _le_text(size_val)
            mid = f"{rep}×{nbytes}" if rep else (f'"{txt}"' if txt else (str(size_val) if size_val else "·"))
        elif vca is not None and a >= vca + 16:
            role, short, mid = lx.t("ov_role_vdata"), lx.t("ov_short_vdata"), (f"{rep}×{nbytes}" if rep else "·")
        else:
            role, short, mid = lx.t("ov_role_past"), lx.t("ov_short_past"), (f"{rep}×{nbytes}" if rep else "·")
        style = ""
        if nbytes < W:
            pct = round(nbytes * 100 / W)
            style = (f"background: linear-gradient(90deg, var(--bad-bg) {pct}%, var(--bg) {pct}%)")
        step_of_cell[i] = step
        cells += cell("dsv-c-over", mid if len(mid) <= 20 else mid[:19] + "…", f"+{usable + i * W}",
                      f"{hx(a)}: {role}" + (f" = {size_val}" if (size_lo <= a < size_lo + W and size_val) else "")
                      + (f" ({nbytes} bytes)" if nbytes < W else ""), step, short, style)
    segs.append(f'<div class="dsv-seg dsv-seg-over"><span>{E(lx.t("ov_over", n=past))}</span><div class="dsv-cells">{cells}</div></div>')
    rest_name = lx.t("ov_victim_top") if is_top else (lx.t("ov_victim", name=vname) if vname else "")
    if rest_name:
        segs.append(f'<div class="dsv-seg"><span>{E(rest_name)}</span><div class="dsv-cells">'
                    f'<div class="dsv-cell dsv-c-rest"><b>…</b></div></div></div>')
    last_step = 3 if n_over > 1 else 2
    n_steps = last_step + 1
    txt = None if rep else _le_text(size_val)
    val_html = (_code(size_val) + (f" ({E(lx.t('ov_text'))} {_code(txt)})" if txt else "")) if size_val else ""
    steps = [f'<li{_sa(1)}>{lx.h("ov_s1", name=bname, n=usable, a=hx(ua), b=hx(end))} {_chip(lx, "obs")}</li>',
             f'<li{_sa(2)}>'
             + (E(_L["ov_s2"][lx.i]).format(val=val_html) if val_html else E(lx.t("ov_s2_plain")))
             + f' {_chip(lx, "obs")}</li>']
    basis = str(dmg.get("extent_basis") or dmg.get("pattern") or "")
    if lx.i == 1:
        basis = _ko_write_basis(basis)
    basis_html = f'<span class="dsv-sub">{E(basis)}</span>' if basis else ""
    if n_over > 1:
        steps.append(f'<li{_sa(3)}>{lx.h("ov_s3", n=past)} {_chip(lx, "obs")}{basis_html}</li>')
    else:
        steps[1] = steps[1].replace("</li>", f'<span class="dsv-sub">{lx.h("ov_s3", n=past)} {E(basis)}</span></li>')
    steps.append(f'<li{_sa(n_steps)}>'
                 + (E(lx.t("ov_s4_top")) if is_top or not vname else lx.h("ov_s4", name=vname))
                 + (f'<span class="dsv-sub">{E(lx.t("ov_stable", n=d.get("stable_rereads")))}</span>'
                    if d.get("stable") and d.get("stable_rereads") else "") + "</li>")
    return (f'<h4>{E(lx.t("ov_title"))}</h4><div class="dsv-stepper" data-steps="{n_steps}">{_stepper_controls(lx, uid, n_steps)}'
            f'<div class="dsv-mem">{"".join(segs)}</div>'
            f'<div class="dsv-memaxis"><span>← {E(lx.t("ov_low"))}</span><span>{E(lx.t("ov_each"))}</span><span>{E(lx.t("ov_high"))} →</span></div>'
            f'<ol class="dsv-steps">{"".join(steps)}</ol></div>'
            f'<p class="dsv-note">{E(lx.t("ov_order"))}</p>'
            f'<p class="dsv-note">{_chip(lx, "no")} {lx.h("ov_writer", name=bname)}</p>')


# ------------------------------------------------------------------------------------------------ leak
def _heap_walks(report: Optional[Dict[str, Any]], f: Dict[str, Any]) -> List[Dict[str, Any]]:
    for o in _observations(report, f.get("recipe_ids")):
        li = o.get("leak_investigation")
        walks = [w for w in ((li or {}).get("heap_walks") or []) if isinstance(w, dict)
                 and isinstance(w.get("t"), (int, float)) and isinstance(w.get("in_use_bytes"), (int, float))
                 and str(w.get("status", "OK")) == "OK"]
        if len(walks) >= 2:
            return walks
    return []


def _viz_leak(lx: _Lx, f: Dict[str, Any], report: Optional[Dict[str, Any]], uid: str = "0") -> str:
    out: List[str] = []
    walks = _heap_walks(report, f)
    if walks:
        t0 = walks[0]["t"]
        ys = [float(x["in_use_bytes"]) / 1024.0 for x in walks]
        tips = [lx.t("lk_point", i=i + 1, kb=f"{y:,.0f}", n=w.get("in_use_count", "?")) for i, (w, y) in enumerate(zip(walks, ys))]
        out.append(f'<h4>{E(lx.t("lk_title"))} {_chip(lx, "obs")}</h4>'
                   + series_chart([float(x["t"] - t0) for x in walks], ys, lx.t("lk_title"), lx.t("lk_x"), lx.t("lk_y"), tips, " KB"))
    g = _growth(f, report)
    if g and g.get("path"):
        root = g.get("var") or g["path"]
        boxes = [f'<div class="dsv-box"><small>{E(lx.t("lk_root"))}</small>{_code(root)}</div>',
                 f'<div class="dsv-arrowtxt"><b>→</b></div>',
                 f'<div class="dsv-box"><small>{E(lx.t("lk_node"))} 1</small>{E(lx.t("lk_first"))}</div>',
                 f'<div class="dsv-arrowtxt"><b>→ … →</b></div>',
                 f'<div class="dsv-box dsv-box-bad"><small>{E(lx.t("lk_node"))} N</small>'
                 + (f'+{E(str(g["blocks"]))}' if g.get("blocks") is not None else E(lx.t("lk_last"))) + "</div>"]
        facts = [f"<li>{_code(g['path'])}"
                 + (": " + E(lx.t("lk_delta", blocks=g["blocks"], kb=g["kb"], win=g["win"], rate=g["rate"]))
                    if g.get("blocks") is not None else "") + "</li>"]
        if g.get("still_ref") and g.get("var"):
            facts.append(f"<li>{lx.h('lk_still', var=g['var'])}</li>")
        if g.get("thr"):
            facts.append("<li>" + lx.h("lk_thread", thr=str(g["thr"]) + (f" (tid {g['tid']})" if g.get("tid") else "")) + "</li>")
        out.append(f'<h4>{E(lx.t("lk_owner"))}</h4><div class="dsv-ptr">{"".join(boxes)}</div>'
                   f'<ul class="dsv-facts">{"".join(facts)}</ul>')
    return "".join(out)


# ------------------------------------------------------------------------------------------------ use after free
def _viz_uaf(lx: _Lx, f: Dict[str, Any], report: Optional[Dict[str, Any]], uid: str = "0") -> str:
    items: List[Dict[str, Any]] = []
    for o in _observations(report, f.get("recipe_ids")):
        fm = o.get("freed_memory_use")
        for x in ((fm or {}).get("findings") or []) if isinstance(fm, dict) else []:
            if isinstance(x, dict) and x.get("freed_chunk"):
                items.append(x)
    if not items:
        return ""
    out = [f'<h4>{E(lx.t("ua_title"))}</h4>']
    for x in items[:3]:
        ptrs = [p for p in (x.get("dangling_pointers") or []) if isinstance(p, dict)] or [{"variable_path": x.get("variable_path") or x.get("variable")}]
        written = bool(x.get("written_while_free"))
        level = str(x.get("level") or "")
        lvl = lx.t("ua_level_" + level) if ("ua_level_" + level) in _L else level
        left = "".join(f'<div class="dsv-box"><small>{E(lx.t("ua_var"))}</small>{_code(p.get("variable_path") or p.get("variable") or "?")}'
                       + (f'<small>{E(lx.t("ua_slot", addr=p["slot_address"]))}</small>' if p.get("slot_address") else "") + "</div>"
                       for p in ptrs[:3])
        out.append('<div class="dsv-ptr">' + left
                   + f'<div class="dsv-arrowtxt">{E(lx.t("ua_points"))}<b>→</b></div>'
                   + f'<div class="dsv-box dsv-box-bad"><small>{E(lx.t("ua_chunk", addr=x.get("user_address") or x["freed_chunk"]))}</small>'
                     f'<strong>{E(lx.t("ua_freed"))}</strong>'
                   + (f' · {E(lx.t("ua_size", n=x["chunk_size"]))}' if x.get("chunk_size") else "")
                   + (f' <span class="dsv-chip">{E(lvl)}</span>' if lvl else "") + "</div>"
                   + (f'<div class="dsv-arrowtxt">{E(lx.t("ua_contains"))}<b>←</b></div>'
                      f'<div class="dsv-box"><small>{E(lx.t("ua_list"))}</small>{E(_ko_free_list(str(x["free_list"])) if lx.i == 1 else str(x["free_list"]))}</div>' if x.get("free_list") else "")
                   + "</div>")
        out.append('<div class="dsv-life">'
                   f'<div>{E(lx.t("ua_l1"))} {_chip(lx, "no")}</div><div>{E(lx.t("ua_l2"))} {_chip(lx, "obs")}</div>'
                   f'<div class="dsv-on">{E(lx.t("ua_l3"))} {_chip(lx, "obs")}</div>'
                   f'<div class="{"dsv-on" if written else "dsv-maybe"}">{E(lx.t("ua_l4"))} {_chip(lx, "obs" if written else "no")}</div></div>')
        facts = []
        if x.get("observed_free_in_reads") and x.get("window_s") is not None:
            facts.append(f"<li>{E(lx.t('ua_seen', n=x['observed_free_in_reads'], win=_fnum(x['window_s'])))}</li>")
        facts.append(f"<li>{E(lx.t('ua_written' if written else 'ua_not_written'))}</li>")
        out.append(f'<ul class="dsv-facts">{"".join(facts)}</ul>')
    return "".join(out)


# ------------------------------------------------------------------------------------------------ thread finding
def _viz_thread(lx: _Lx, f: Dict[str, Any], report: Optional[Dict[str, Any]], uid: str = "0") -> str:
    rows = _thread_rows(report, f.get("recipe_ids"))
    hot = []
    for o in _observations(report, f.get("recipe_ids")):
        for r in (o.get("runaway_threads") or []):
            if isinstance(r, dict) and r.get("tid") not in hot:
                hot.append(r.get("tid"))
    if not hot:
        hot = [int(t) for t in _by_kind(f).get("thread", []) if str(t).isdigit()]
    return _thread_strip(lx, rows, hot, _sampling(report, f))


_VIZ = {"DEADLOCK_INDICATORS": _viz_deadlock, "MEMORY_CORRUPTION": _viz_overflow, "MEMORY_LEAK": _viz_leak,
        "USE_AFTER_FREE": _viz_uaf, "PROCESS_INSTABILITY": _viz_thread}


def _md_html(lines: List[str]) -> str:
    """Markdown lines of the composition as HTML (the summary's own converter; everything escaped)."""
    from .human_report import markdown_to_html
    return markdown_to_html("\n".join(lines))


def _detail(lx: _Lx, key: str, body: str, anchor: str) -> str:
    """A collapsed block of detailed records (English) next to the part it belongs to.  The label is in the report
    language; the body is marked so that the language test exempts exactly the detail and nothing around it."""
    if not body:
        return ""
    return (f'<details class="dsv-detail" id="{E(anchor)}"><summary>{E(lx.t(key))}</summary>'
            f'<div class="dsv-detail-body" lang="en">{body}</div><!--/dsv-detail-body--></details>')


def _finding_card(lx: _Lx, i: int, f: Dict[str, Any], report: Optional[Dict[str, Any]],
                  block: Optional[Dict[str, Any]] = None, detail: str = "") -> str:
    cat = str(f.get("category"))
    reg = category_label(cat)
    label = reg[lx.i] if reg else (CATEGORY_LABEL[cat][lx.i] if cat in CATEGORY_LABEL else cat)
    status = str(f.get("status") or "")
    st_word = {"CONFIRMED_ROOT_CAUSE": T["k_fstatus_c"][lx.i], "PROBABLE_CAUSE": T["k_fstatus_p"][lx.i]}.get(status, status)
    tone = "bad" if status == "CONFIRMED_ROOT_CAUSE" else "warn"
    if str(f.get("severity") or "").upper() == "INFO" and status in ("CONFIRMED_ROOT_CAUSE", "PROBABLE_CAUSE"):
        st_word, tone = T["k_fstatus_i"][lx.i], "unk"  # not a fault: neutral badge and tone
    try:
        fn = finding_viz(cat) or _VIZ.get(cat)
        viz = (fn(lx, f, report, f"f{i}") or "") if fn else ""
    except Exception:  # noqa: BLE001 - a picture must never prevent the report from being written
        viz = ""
    kinds = _by_kind(f)
    chips = []
    for key in ("variable", "lock", "thread_name", "function", "source_location", "resource"):
        vals = _user_funcs(kinds.get(key, [])) if key == "function" else kinds.get(key, [])
        chips += [_code(v) for v in vals[:6] if _code(v) not in chips]
    facts = "".join(f"<li>{E(ko_text(str(o), lx.i))}</li>" for o in (f.get("observed") or [])[:4])
    desc = str(f.get("description") or "")
    if not viz and desc:
        facts = f"<li>{E(ko_text(desc, lx.i))}</li>" + facts
    head = (f'<h3>{E(lx.t("finding", i=i))}: {E(label)} {_code(cat)}</h3>' if block is None
            else f'<h3>{_inline_html(block["heading"])}</h3>')
    parts = [f'<section class="dsv-card dsv-tone-{tone}" id="finding-{i}"><span id="dsv-finding-{i}"></span>'
             f'<div class="dsv-fhead">{head}<span class="dsv-badge">{E(st_word)}</span></div>']
    if block is not None:
        parts.append('<ul class="dsv-facts dsv-keyfacts">' + "".join(f"<li>{_inline_html(x)}</li>" for x in block["facts"]) + "</ul>")
        if block["body"] and not viz:
            parts.append(f'<div class="dsv-text">{_md_html(block["body"])}</div>')
        elif not block["body"] and chips:
            parts.append(f'<p class="dsv-note">{E(lx.t("subjects"))}: {" ".join(chips)}</p>')
    elif chips:
        parts.append(f'<p class="dsv-note">{E(lx.t("subjects"))}: {" ".join(chips)}</p>')
    parts.append(viz)
    if block is not None and (block["body"] or block["diagram"]) and viz:
        # the picture states the same facts; the text (and the text diagram) stays one click away
        parts.append(f'<details class="dsv-ck dsv-s-SKIPPED dsv-astext"><summary><span class="dsv-ck-name">'
                     f'{E(lx.t("as_text"))}</span></summary><div class="dsv-text" style="padding:0 14px 8px">'
                     f'{_md_html(block["body"] + [""] + block["diagram"])}</div></details>')
    if block is not None and block["diagram"] and not viz:
        parts.append(_md_html(block["diagram"]))
    if block is not None and block["why"]:
        parts.append(f'<div class="dsv-text">{_md_html([T["f_why"][lx.i], ""] + [f"{n}. {x}" for n, x in enumerate(block["why"], 1)])}</div>')
    if facts:
        parts.append(f'<details class="dsv-ck dsv-s-SKIPPED"><summary><span class="dsv-ck-name">{E(lx.t("evidence"))}</span></summary>'
                     f'<ul class="dsv-facts" style="padding:4px 14px 12px 34px">{facts}</ul></details>')
    parts.append(_detail(lx, "d_finding", detail, f"finding-{i}-detail"))
    parts.append("</section>")
    return "".join(parts)


# ------------------------------------------------------------------------------------------------ check list
def _recipe_meta(rid: str) -> Optional[Tuple[str, str, str, str, str]]:
    """Check-list label of a recipe: a registration from its definition file first, then the built-in table."""
    return recipe_label(rid) or _RECIPES.get(rid)


def _norm_status(s: Any) -> str:
    from .human_report import check_group
    return check_group(s)


def _check_rows(res: Dict[str, Any], report: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The one check table (``human_report.check_rows``): every view counts from it."""
    from .human_report import check_rows
    return check_rows(res, report)


def _checklist(lx: _Lx, res: Dict[str, Any], report: Optional[Dict[str, Any]], findings: List[Dict[str, Any]],
               comp: Optional[Dict[str, Any]] = None, details: Optional[Dict[str, Any]] = None) -> str:
    """The scope part: counts once, then the checks grouped by outcome (clean and not-run collapsed), each row with
    what it looks for, what it found or why it could not judge, and its own detailed result."""
    from .human_report import _undecided_reason, check_counts, check_label
    from .human_report import _Ctx as _HCtx
    hctx = (comp or {}).get("ctx") or _HCtx(lx.lang)
    details = details or {}
    rows = (comp or {}).get("rows") or _check_rows(res, report)
    reasons: Dict[str, List[str]] = {}
    for n in res.get("not_covered") or []:
        if isinstance(n, dict) and str(n.get("kind") or "").startswith("check_") \
                and str(n.get("reason") or "") not in ("", "Check executed"):
            reasons.setdefault(str(n.get("item")), []).append(str(n["reason"]))
    linked: Dict[str, List[int]] = {}
    for i, f in enumerate(findings, 1):
        for rid in f.get("recipe_ids") or []:
            linked.setdefault(str(rid), []).append(i)
    cnt = check_counts(rows)
    if not rows:
        return f'<div class="dsv-card"><p>{E(lx.t("ck_none"))}</p></div>'
    total = len(rows)
    bar = "".join(f'<i class="dsv-s-{s}" style="width:{sum(1 for r in rows if r["status"] == s) * 100 / total:.2f}%" '
                  f'title="{E(lx.t("ck_" + s))}"></i>' for s in _STATUS_ORDER if any(r["status"] == s for r in rows))
    groups: List[str] = []
    for s in _STATUS_ORDER:
        grp = [r for r in rows if r["status"] == s]
        if not grp:
            continue
        grp.sort(key=lambda r: (_DOMAIN_ORDER.index((_recipe_meta(r["rid"]) or ("OTHER",))[0]), r["rid"]))
        items = []
        for r in grp:
            meta = _recipe_meta(r["rid"])
            name = meta[1 + lx.i] if meta else str(r.get("name") or r["rid"])
            what = meta[3 + lx.i] if meta else ""
            dom = meta[0] if meta else (str(r.get("domain")) if ("dom_" + str(r.get("domain"))) in _L else "OTHER")
            why = _undecided_reason(hctx, r, reasons) if s in ("INCONCLUSIVE", "SKIPPED") else ""
            interp = str(r.get("interp") or "")
            has_interp = bool(interp) and interp != "Check executed"
            interp = ko_text(interp, lx.i)
            line = interp if (has_interp and s in ("FAIL", "PASS")) else re.sub(r"`", "", why)
            dl = []
            if what:
                dl.append((lx.t("ck_what"), E(what)))
            if has_interp and s in ("FAIL", "PASS"):
                dl.append((lx.t("ck_result"), E(interp)))
            if why:
                dl.append((lx.t("ck_why"), _inline_html(why)))
            if linked.get(r["rid"]):
                dl.append((lx.t("ck_linked"), " ".join(f'<a href="#finding-{i}">{E(lx.t("finding", i=i))}</a>' for i in linked[r["rid"]])))
            if r.get("n_ev"):
                dl.append((lx.t("ck_evidence"), str(r["n_ev"])))
            if isinstance(r.get("dur"), (int, float)) and r.get("planned", True) and s != "SKIPPED":
                dl.append((lx.t("ck_time"), f"{float(r['dur']) * 1000:.0f} ms"))
            dl.append((lx.t("ck_id"), _code(r["rid"]) + (f' <span class="dsv-chip">{E(lx.t("ck_required"))}</span>' if r.get("required") else "")))
            items.append(f'<details class="dsv-ck dsv-s-{s}" data-status="{s}" id="check-{E(r["rid"])}"><summary><span class="dsv-dot" aria-hidden="true">{_STATUS_ICON[s]}</span>'
                         f'<span class="dsv-ck-main"><span><span class="dsv-ck-name">{E(name)}</span> '
                         f'<span class="dsv-chip">{E(lx.t("dom_" + dom))}</span></span>'
                         + (f'<span class="dsv-ck-line">{E(line[:160])}</span>' if line else "") + "</span></summary><dl>"
                         + "".join(f"<dt>{E(k)}</dt><dd>{v}</dd>" for k, v in dl) + "</dl>"
                         + _detail(lx, "d_check", (details.get("checks") or {}).get(r["rid"], ""), f"check-{r['rid']}-detail")
                         + "</details>")
        opened = " open" if s in ("FAIL", "INCONCLUSIVE") else ""
        groups.append(f'<details class="dsv-ckgroup dsv-s-{s}"{opened}><summary><span class="dsv-dot" aria-hidden="true">{_STATUS_ICON[s]}</span>'
                      f'{E(lx.t("ck_" + s))} ({len(grp)}) <small>{E(lx.t("ck_" + s + "_hint"))}</small></summary>{"".join(items)}</details>')
    head_lines = (comp or {}).get("scope_head") or []
    nc_lines = (comp or {}).get("not_examined") or []
    nc_html = ""
    if nc_lines:
        nc_html = f'<h3>{E(T["g_other"][lx.i])}</h3>' + _md_html(nc_lines)
    head = "".join(f"<p>{_inline_html(x)}</p>" for x in head_lines if x) or \
        f'<p>{E(T["s_counts"][lx.i].format(**cnt))}</p>'
    return (f'<div class="dsv-card dsv-checklist">{head}<div class="dsv-bar">{bar}</div>'
            f'<div class="dsv-ckgroups">{"".join(groups)}</div>{nc_html}'
            + _detail(lx, "d_scope", details.get("scope", ""), "scope-detail") + "</div>")


# ------------------------------------------------------------------------------------------------ header
def _hero(lx: _Lx, title: str, res: Dict[str, Any], rows: List[Dict[str, Any]], summary_md: str = "",
          comp: Optional[Dict[str, Any]] = None, details: Optional[Dict[str, Any]] = None) -> str:
    """The conclusion part: the verdict in words, the conclusion sentence, a few key figures."""
    from .human_report import check_counts, conclusion_sentence as _cs, fmt_bytes, fmt_ms
    verdict = str(res.get("verdict") or "INCONCLUSIVE")
    tone = _VERDICT_TONE.get(verdict, "unk")
    vkey = verdict if f"v_{verdict}" in T else "INCONCLUSIVE"
    concl = (comp or {}).get("conclusion") or _cs(summary_md)
    impact = res.get("collection_impact") if isinstance(res.get("collection_impact"), dict) else {}
    tiles = []
    if rows:
        c = check_counts(rows)
        bar = "".join(f'<i class="dsv-s-{s}" style="width:{sum(1 for r in rows if r["status"] == s) * 100 / len(rows):.2f}%"></i>'
                      for s in _STATUS_ORDER if any(r["status"] == s for r in rows))
        txt = " · ".join(f"{_STATUS_ICON[s]} {lx.t('ck_' + s)} {n}" for s, n in
                         (("FAIL", c["found"]), ("INCONCLUSIVE", c["undecided"]), ("PASS", c["clean"])) if n)
        tiles.append(f'<div class="dsv-tile"><span>{E(lx.t("checks_run"))}</span><b>{c["run"]}</b><div class="dsv-bar">{bar}</div>'
                     f'<span>{E(txt)}</span>' + (f'<span class="dsv-tile-sub">{E(lx.t("checks_not_run", n=c["not_run"]))}</span>'
                                                 if c["not_run"] else "") + '</div>')
    if isinstance(impact.get("measured_stop_ms"), (int, float)):
        stop = float(impact["measured_stop_ms"])
        tiles.append(f'<div class="dsv-tile"><span>{E(lx.t("stop_time"))}</span><b>{E(fmt_ms(stop, lx.i))}</b>'
                     + (f'<span>{E(lx.t("zero_stop"))}</span>' if stop == 0 and impact.get("zero_stop") else "") + "</div>")
    if isinstance(impact.get("bytes_read"), (int, float)):
        tiles.append(f'<div class="dsv-tile"><span>{E(lx.t("bytes_read"))}</span><b>{E(fmt_bytes(impact["bytes_read"]))}</b></div>')
    if isinstance(res.get("duration_s"), (int, float)):
        tiles.append(f'<div class="dsv-tile"><span>{E(lx.t("duration"))}</span><b>{E(fmt_ms(float(res["duration_s"]) * 1000, lx.i))}</b></div>')
    sym = "".join(f'<p class="dsv-note">{_inline_html(x)}</p>' for x in (comp or {}).get("symptom_note") or [])
    return (f'<div class="dsv-card dsv-hero dsv-tone-{tone}" id="dsv-glance">'
            f'<p><span class="dsv-badge">{E(T["v_line"][lx.i].split("{word}")[0].strip("* "))} {E(T["v_" + vkey][lx.i])}</span> '
            f'{_code(verdict)} <span class="dsv-note">{E(T["vm_" + vkey][lx.i])}</span></p>'
            + (f'<p class="dsv-concl">{_inline_html(concl)}</p>' if concl else "") + sym
            + (f'<div class="dsv-tiles">{"".join(tiles)}</div>' if tiles else "")
            + "</div>" + _detail(lx, "d_verdict", (details or {}).get("verdict", ""), "verdict-detail"))


_SEC_ID = {"conclusion": "sec-conclusion", "findings": "dsv-findings", "hypothesis": "sec-hypothesis",
           "next": "sec-next", "scope": "dsv-checks", "method": "sec-method", "reproducibility": "reproducibility",
           "reference": "sec-reference"}


def build_visual_summary(result: Dict[str, Any], report: Optional[Dict[str, Any]] = None, lang: str = "en",
                         title: str = "", summary_md: str = "", *, comp: Optional[Dict[str, Any]] = None,
                         details: Optional[Dict[str, Any]] = None, subtitle: str = "") -> str:
    """The HTML body of the report: the common outline (``human_report.compose``), each part with its picture or
    check list, and the detailed records of each part in a collapsed block next to it (``details``, from
    ``report_detail.partition``).  No script."""
    from .human_report import compose
    lx = _Lx(lang if lang in ("en", "ko") else "en")
    res = dict(result or {})
    report = report if isinstance(report, dict) else (res.get("report") if isinstance(res.get("report"), dict) else None)
    if comp is None:
        comp = compose(res, report, lx.lang)
    findings = [f for f in (res.get("findings") or []) if isinstance(f, dict)]
    rows = comp["rows"]
    details = details or {}
    nav = "".join(f'<a href="#{_SEC_ID[s["key"]]}">{E(s["heading"])}</a>' for s in comp["sections"])
    parts = [f"<style>{_CSS}{_interaction_css()}</style>", f'<div class="dsv" lang="{lx.lang}">',
             f'<header class="dsv-head"><h1 class="dsv-title">{E(title)}</h1>'
             + (f'<p class="dsv-note">{_inline_html(subtitle)}</p>' if subtitle else "")
             + f'<nav class="dsv-nav">{nav}</nav></header>']
    for s in comp["sections"]:
        key = s["key"]
        parts.append(f'<section class="dsv-sec" id="{_SEC_ID[key]}"><h2>{E(s["heading"])}</h2>')
        if key == "conclusion":
            parts.append(_hero(lx, title, res, rows, summary_md, comp, details))
        elif key == "findings":
            parts += [_finding_card(lx, i, f, report, b, (details.get("findings") or {}).get(i, ""))
                      for i, (f, b) in enumerate(zip(findings, comp["blocks"]), 1)]
        elif key == "scope":
            parts.append(_checklist(lx, res, report, findings, comp, details))
        elif key == "method":
            parts.append(f'<div class="dsv-card">{_md_html([x for x in s["lines"] if not x.startswith("_")])}'
                         + _detail(lx, "d_method", details.get("method", ""), "method-detail") + "</div>")
        elif key == "reproducibility":
            parts.append(f'<div class="dsv-card dsv-repro">{_md_html(s["lines"])}'
                         + _detail(lx, "d_repro", details.get("reproducibility", ""), "reproducibility-detail") + "</div>")
        elif key == "reference":
            # the "where is the detail" list is for the Markdown reader; here each part carries its own detail
            where = f"### {T['r_where'][lx.i]}"
            body = s["lines"][:s["lines"].index(where)] if where in s["lines"] else s["lines"]
            parts.append(f'<div class="dsv-card">{_md_html(body)}'
                         + _detail(lx, "d_other", details.get("other", ""), "other-detail") + "</div>")
        else:
            parts.append(f'<div class="dsv-card">{_md_html(s["lines"])}</div>')
        parts.append("</section>")
    parts.append("</div>")
    return "\n".join(parts)


def wrap_detail(report_html: str, label: str) -> str:
    """Put the long A-I report card of ``DiagnosticReport.to_html`` inside a collapsed block (kept for callers of
    the whole-document detail; the incident report attaches the detail per part instead)."""
    start = report_html.find('<div class="report-card">')
    end = report_html.rfind("</body>")
    if start < 0 or end < start:
        return report_html
    return (report_html[:start] + f'<details class="dsv-detail" id="dsv-detail"><summary>{E(label)}</summary>\n'
            + report_html[start:end] + "</details>\n" + report_html[end:])
