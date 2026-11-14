"""IMP-012: human-readable summary layer on top of the ``diagnose`` result.

``render_human_report(result, report=None, lang="en"|"ko")`` turns a ``DiagnoseResult`` dict (plus, when present,
the inline full report dict) into a deterministic, template-based Markdown summary.  No LLM, no randomness.

Structure (fixed order): 1 conclusion, 2 what is wrong (+ wait-for picture for deadlocks), 3 why we concluded
this, 4 how certain / what was not examined, 5 what to do next, 6 impact on the target, then a glossary.

Rules the renderer keeps:
* Every name (variable path, thread, lock, function, ``file:line``) is copied from the findings' subject_details,
  or from the full report's observations; nothing is invented.  A finding without names says so plainly.
* Identifiers are never translated.  Template wording is fully translated; engine-produced free text
  (``limitation`` / ``reason`` strings) is quoted verbatim and marked as such in Korean.
* An INCONCLUSIVE / ABORTED verdict is stated in the first sentence, with the reason, and never described as
  healthy.
* A HEALTHY verdict (extractor.healthy_verdict) is stated as "healthy within the checked scope" and the same first
  sentence names what was not checked (``healthy_scope.not_checked``).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

SUPPORTED_LANGS = ("en", "ko")

# ---------------------------------------------------------------------------------------------- templates
# key -> (English, Korean); {placeholders} are filled with names/numbers taken from the result.
T: Dict[str, Tuple[str, str]] = {
    "title": ("Diagnosis of {proc} (pid {pid})", "{proc} (pid {pid}) 진단 결과"),
    "h1": ("1. Conclusion", "1. 결론"),
    "h2": ("2. What is wrong", "2. 무엇이 문제인가"),
    "h3": ("3. Why we concluded this", "3. 왜 그렇게 판단했는가"),
    "h4": ("4. How certain, and what was not examined", "4. 얼마나 확실한가, 그리고 확인하지 못한 것"),
    "h5": ("5. What to do next", "5. 다음에 할 일"),
    "h6": ("6. Impact of the collection on the target", "6. 수집이 대상에 준 영향"),
    "hg": ("Glossary", "용어 풀이"),
    "h2_wait": ("Wait-for cycle", "대기 관계 그림 (교착 고리)"),
    "unknown_proc": ("unknown process", "알 수 없는 프로세스"),
    # --- conclusion
    "c_inconclusive": ("The diagnosis of {who} is inconclusive: {why}.",
                       "{who}의 진단은 판단 불가입니다. 이유: {why}."),
    "c_aborted": ("The diagnosis of {who} was aborted before a conclusion: {why}.",
                  "{who}의 진단은 결론이 나기 전에 중단되었습니다. 이유: {why}."),
    "c_healthy": ("{who} is healthy within the checked scope: all {n} baseline checks ran to completion and found "
                  "nothing. Not checked: {nc}.",
                  "{who}은(는) 점검한 범위 안에서 정상입니다. 기본 검사 {n}개가 모두 끝까지 실행되었고 아무것도 "
                  "발견하지 못했습니다. 점검하지 못한 것: {nc}."),
    "c_healthy_more": ("; and {n} more (section 4)", " 외 {n}건 (4번 항목)"),
    "c_healthy_noscope": ("The checks that ran found no problem in {who}; this does not prove the process is fine "
                          "(see section 4 for what was not examined).",
                          "{who}에서 실행된 검사로는 문제가 발견되지 않았습니다. 다만 이것이 문제가 없다는 증명은 아니며, "
                          "확인하지 못한 항목은 4번 항목에 있습니다."),
    "k_checked": ("Checked and found nothing (baseline):", "검사했고 아무것도 발견하지 못한 것 (기본 검사):"),
    "c_degraded": ("{who} is degraded: {what}.", "{who}은(는) 성능이 저하된 상태입니다: {what}."),
    "c_fault_conf": ("{who} has a confirmed problem: {what}.", "{who}에서 확인된 문제가 있습니다: {what}."),
    "c_fault_prob": ("{who} probably has a problem: {what}.", "{who}에 문제가 있을 가능성이 높습니다: {what}."),
    "c_more": (" {n} more finding(s) are listed in section 2.", " 그 밖의 발견 {n}건은 2번 항목에 있습니다."),
    # inconclusive reasons
    "r_nopid": ("the process does not exist (pid {pid})", "프로세스가 존재하지 않습니다 (pid {pid})"),
    "r_unread": ("the process cannot be read: {raw}", "프로세스를 읽을 수 없습니다: {raw}"),
    "r_noimg": ("the debug image {item} was not found, so symbols cannot be resolved",
                "디버그 이미지 {item}을(를) 찾을 수 없어 심볼을 해석할 수 없습니다"),
    "r_stage": ("the diagnosis stopped with an error ({item}): {raw}", "진단이 오류로 중단되었습니다 ({item}): {raw}"),
    "r_noexec": ("no check was executed ({raw})", "실행된 검사가 없습니다 ({raw})"),
    "r_nofinding": ("{ran} check(s) ran, {dec} of them decided, and none produced a finding that names a cause",
                    "검사 {ran}개가 실행되어 그중 {dec}개가 결론을 냈지만 원인을 가리키는 발견은 없었습니다"),
    "r_unspecified": ("the engine gave no further reason", "엔진이 더 이상의 이유를 알려주지 않았습니다"),
    "r_baseline_open": ("; it is not called healthy because the baseline check for {what} ({rid}) could not decide: "
                        "{raw}",
                        "; 기본 검사 '{what}'({rid})이(가) 결론을 내지 못해 정상으로 판정하지 않았습니다 "
                        "(엔진 원문: {raw})"),
    # --- what is wrong
    "w_none": ("No cause could be named: the diagnosis produced no finding.",
               "원인으로 지목할 대상이 없습니다. 이번 진단은 발견을 만들지 못했습니다."),
    "w_finding": ("Finding {i}: {cat} ({status}, severity {sev})", "발견 {i}: {cat} ({status}, 심각도 {sev})"),
    "w_noname": ("This finding names no variable, thread, lock or function, so it cannot be pointed at a place "
                 "in the code. Treat it as an unattributed observation.",
                 "이 발견에는 변수, 스레드, 락, 함수 이름이 없어 코드의 특정 위치를 가리킬 수 없습니다. "
                 "대상이 특정되지 않은 관측으로 보세요."),
    "w_dl_cycle": ("Circular wait among {n} thread(s) and {m} lock(s):", "스레드 {n}개와 락 {m}개가 서로를 기다리는 고리:"),
    "w_dl_edge": ("- {waiter} waits for lock {lock}, which is held by {owner}.",
                  "- {waiter}이(가) 락 {lock}을(를) 기다리고 있고, 이 락은 {owner}이(가) 잡고 있습니다."),
    "w_dl_where": ("- {thr} is blocked inside {fn}, which is defined at {loc}.", "- {thr}은(는) {loc}에 정의된 {fn} 안에서 멈춰 있습니다."),
    "w_dl_where_nofn": ("- {thr} is blocked at {loc}.", "- {thr}은(는) {loc}에서 멈춰 있습니다."),
    "w_dl_at": ("- {thr} is blocked at {loc}{call}{inl}.", "- {thr}은(는) {loc}{call}{inl}에서 멈춰 있습니다."),
    "w_at_call": (" in {x}", " ({x} 호출)"),
    "w_at_inl": (" (in {f}, inlined into {g})", " ({f}, {g}에 인라인됨)"),
    "w_lines_note": ("The source line given for a function is where that function is defined; the exact line of "
                     "the call it is blocked in was not resolved.",
                     "함수에 붙은 소스 줄은 그 함수가 정의된 곳입니다. 멈춰 있는 호출의 정확한 줄은 해석하지 못했습니다."),
    "w_dl_samename": ("The operating system gives all these threads the same name ({name}), so they are told apart "
                      "by the function they run and their thread id.",
                      "이 스레드들은 운영체제상 이름이 모두 같아({name}) 실행 함수와 스레드 ID로 구분했습니다."),
    "w_dl_nocycle": ("The wait-for cycle itself is not in the data available here; only the names collected for "
                     "this finding are listed.",
                     "대기 고리 자체는 지금 받은 데이터에 없습니다. 이 발견에 모인 이름만 나열합니다."),
    "w_locks": ("Locks: {x}", "락: {x}"),
    "w_res": ("Resources: {x}", "자원: {x}"),
    "w_obs": ("Observed: {x}", "관측: {x}"),
    "w_threads": ("Threads: {x}", "스레드: {x}"),
    "w_tids": ("Thread ids: {x}", "스레드 ID: {x}"),
    "w_funcs": ("Functions: {x}", "함수: {x}"),
    "w_locs": ("Source locations: {x}", "소스 위치: {x}"),
    "w_vars": ("Variables: {x}", "변수: {x}"),
    "w_leak": ("Memory held under {path} grows without bound: +{blocks} blocks / +{size} KB in use over {win} s "
               "({rate} KB/s).",
               "{path} 아래에 매달린 메모리가 계속 늘고 있습니다: {win}초 동안 블록 +{blocks}개 / 사용 중 +{size} KB "
               "({rate} KB/s)."),
    "w_leak_nonum": ("Memory growth was attributed to {path}; the growth figures are not in the data available here.",
                     "메모리 증가가 {path}에 귀속되었습니다. 증가량 수치는 지금 받은 데이터에 없습니다."),
    "w_leak_ref": ("The blocks are still referenced from the variable {var}, so they are not lost pointers: "
                   "something keeps adding entries and nothing removes them.",
                   "이 블록들은 변수 {var}에서 계속 참조되고 있어 포인터를 잃어버린 것이 아니라, "
                   "항목이 계속 추가되기만 하고 제거되지 않는 상태입니다."),
    "w_leak_thread": ("The growing blocks are allocated by thread {thr}.", "증가하는 블록은 스레드 {thr}이(가) 할당합니다."),
    # stage 3: the owner is a C++ container decoded from its library fields (extractor.cpp_containers), validated
    "w_cont": ("{var} is a {type}: {size} {unit}{cap} at the last heap walk{grow}.",
               "{var}은(는) {type}입니다: 마지막 힙 조사에서 {unit} {size}개{cap}{grow}."),
    "w_cont_cap": (" (capacity {n})", "(용량 {n})"),
    "w_cont_buckets": (" in {n} buckets", ", 버킷 {n}개"),
    "w_cont_grow": ("; {first} → {last} across {n} heap walks", ", 힙 조사 {n}회 동안 {first} → {last}"),
    "w_cont_unit_el": ("elements", "원소"),
    "w_cont_unit_ch": ("characters", "문자"),
    "w_cont_partial": ("Only {k} of {n} heap walks could decode it ({why}).",
                       "힙 조사 {n}회 중 {k}회만 해독했습니다({why})."),
    "w_cont_fail": ("{var} is a {type}, but its contents could not be decoded ({why}); the owner is shown by its raw "
                    "path only.",
                    "{var}은(는) {type}이지만 내용을 해독하지 못했습니다({why}). 소유자는 원래 경로로만 표시합니다."),
    "w_cont_ptr": ("{var} is a {type}: it points to {addr}, use_count {use}, weak references {weak}.",
                   "{var}은(는) {type}입니다: {addr}을(를) 가리키며 use_count {use}, 약한 참조 {weak}개."),
    "w_spin": ("Thread {thr} (tid {tid}) was runnable in {frac}% of the samples and used {cpu}% of a CPU while "
               "running in {fn} (defined at {loc}).",
               "스레드 {thr} (tid {tid})은(는) 샘플의 {frac}%에서 실행 가능 상태였고 CPU를 {cpu}% 사용하며 "
               "{loc}에 정의된 {fn} 안에서 돌고 있었습니다."),
    "w_spin_at": ("Thread {thr} (tid {tid}) was runnable in {frac}% of the samples and used {cpu}% of a CPU while "
                  "running at {loc}{call}{inl} (in {fn}).",
                  "스레드 {thr} (tid {tid})은(는) 샘플의 {frac}%에서 실행 가능 상태였고 CPU를 {cpu}% 사용하며 "
                  "{fn} 안의 {loc}{call}{inl}에서 돌고 있었습니다."),
    # yield-polling busy wait judged from dispatch counts (judgement_basis schedstat_runnable_fraction_dispatches):
    # the CPU share it received is a property of the host load, not of the thread, so it is not printed
    "w_spin_disp": ("Thread {thr} (tid {tid}) was runnable for {frac}% of the window and was put on a CPU {n} times, "
                    "but never blocked: it gave the CPU back after every turn without waiting for anything, and its "
                    "top frame stayed the same, in {fn} (defined at {loc}).",
                    "스레드 {thr} (tid {tid})은(는) 관측 구간의 {frac}% 동안 실행 가능 상태였고 CPU에 {n}번 올려졌지만 "
                    "한 번도 대기 상태가 되지 않았습니다. 매 차례 아무것도 기다리지 않고 CPU를 반납했으며, "
                    "최상단 프레임은 {loc}에 정의된 {fn}(으)로 계속 같았습니다."),
    "w_spin_disp_at": ("Thread {thr} (tid {tid}) was runnable for {frac}% of the window and was put on a CPU {n} times, "
                       "but never blocked: it gave the CPU back after every turn without waiting for anything, and its "
                       "top frame stayed the same, at {loc}{call}{inl} (in {fn}).",
                       "스레드 {thr} (tid {tid})은(는) 관측 구간의 {frac}% 동안 실행 가능 상태였고 CPU에 {n}번 올려졌지만 "
                       "한 번도 대기 상태가 되지 않았습니다. 매 차례 아무것도 기다리지 않고 CPU를 반납했으며, "
                       "최상단 프레임은 {fn} 안의 {loc}{call}{inl}(으)로 계속 같았습니다."),
    "w_spin_short": ("Thread {thr} (tid {tid}) shows an anomaly in {fn} (defined at {loc}).",
                     "스레드 {thr} (tid {tid})에서 {loc}에 정의된 {fn} 관련 이상이 관측되었습니다."),
    "w_gen_cat": ("Category: {cat}", "범주: {cat}"),
    # --- why
    "y_checks": ("We ran {ran} checks against the live process; {pass_} passed, {fail} failed (a failed check means "
                 "it found the anomaly it looks for), {inc} could not decide. Checks that found it: {ids}.",
                 "실행 중인 프로세스에 검사 {ran}개를 실행했습니다. 통과 {pass_}개, 실패 {fail}개(실패는 검사가 찾던 "
                 "이상을 발견했다는 뜻), 판단 불가 {inc}개입니다. 이상을 발견한 검사: {ids}."),
    "y_checks_none": ("We ran {ran} checks against the live process; {pass_} passed, {fail} failed, {inc} could not "
                      "decide, and none of them produced a finding.",
                      "실행 중인 프로세스에 검사 {ran}개를 실행했습니다. 통과 {pass_}개, 실패 {fail}개, 판단 불가 {inc}개이며 "
                      "발견을 만든 검사는 없었습니다."),
    "y_noruns": ("No check could be run, so there is no observation to reason from.",
                 "실행된 검사가 없어 추론의 바탕이 되는 관측이 없습니다."),
    "y_dl_obs": ("The thread states were sampled {n} times over {win} s; the threads in the cycle stayed blocked in "
                 "the kernel the whole time without using CPU.",
                 "스레드 상태를 {win}초 동안 {n}회 읽었고, 고리에 있는 스레드는 내내 CPU를 쓰지 않고 커널에서 "
                 "대기하고 있었습니다."),
    "y_dl_obs_nonum": ("The threads in the cycle were observed blocked in the kernel, not using CPU.",
                       "고리에 있는 스레드는 CPU를 쓰지 않고 커널에서 대기하는 것으로 관측되었습니다."),
    "y_dl_persist": ("The same cycle was seen in {n} separate observations, so it is not a momentary overlap.",
                     "같은 고리가 서로 다른 {n}번의 관측에서 확인되어 일시적인 겹침이 아닙니다."),
    "y_dl_infer": ("Each thread in the cycle waits for a lock held by the next one, so none of them can ever "
                   "continue: this is a deadlock.",
                   "고리의 각 스레드가 다음 스레드가 잡은 락을 기다리므로 어느 것도 계속 진행할 수 없습니다. "
                   "교착 상태입니다."),
    "y_leak_obs": ("The heap was walked {n} times over {win} s and the memory in use rose on every walk.",
                   "힙을 {win}초 동안 {n}회 훑었고 사용 중인 메모리가 매번 늘었습니다."),
    "y_leak_obs_nonum": ("Memory in use kept rising across the heap walks.", "힙을 훑을 때마다 사용 중인 메모리가 늘었습니다."),
    "y_leak_infer": ("Following the pointers from the program's variables ended at {path}, so that variable is "
                     "what holds the growing memory.",
                     "프로그램 변수에서 포인터를 따라가면 {path}에 이르므로, 늘어나는 메모리를 쥐고 있는 것은 "
                     "이 변수입니다."),
    "y_spin_infer": ("A thread that is runnable almost all the time and stays in one function, with no blocking "
                     "call, is spinning rather than waiting.",
                     "거의 항상 실행 가능 상태이면서 대기 호출 없이 한 함수에 머무는 스레드는 기다리는 것이 아니라 "
                     "공회전(spin)하고 있는 것입니다."),
    "y_generic": ("The finding rests on {n} piece(s) of evidence collected from the process.",
                  "이 발견은 프로세스에서 수집한 증거 {n}건에 근거합니다."),
    "y_evidence": ("{n} piece(s) of evidence support the finding; confidence {conf}%.",
                   "증거 {n}건이 이 발견을 뒷받침하며, 신뢰도는 {conf}%입니다."),
    "y_incon": ("Nothing the checks measured pointed at a cause, and the process could not be examined further, "
                "so no inference is drawn from it.",
                "검사에서 측정된 것 중 원인을 가리키는 것이 없었고 더 이상 살펴볼 수도 없어, 이 결과에서 추론을 "
                "끌어내지 않습니다."),
    # --- certainty
    "k_verdict": ("Verdict: {v} (confidence {conf}%).", "판정: {v} (신뢰도 {conf}%)."),
    "k_conf": ("confirmed: the evidence in hand establishes the problem", "확정: 확보한 증거가 문제를 입증함"),
    "k_prob": ("probable: likely, but not fully proven", "추정: 가능성이 높으나 완전히 입증되지는 않음"),
    "k_degraded": ("degraded: something is off but a cause is not established", "성능 저하: 이상은 있으나 원인은 확정되지 않음"),
    "k_healthy": ("healthy within the checked scope: every baseline check ran and found nothing; outside that "
                  "scope nothing is claimed",
                  "정상(점검한 범위 안에서): 모든 기본 검사가 실행되었고 아무것도 발견하지 못함. 범위 밖은 판단하지 않음"),
    "k_incon": ("could not decide", "판단 불가"),
    "k_abort": ("aborted", "중단됨"),
    "k_fstatus_c": ("confirmed root cause", "확정된 근본 원인"),
    "k_fstatus_p": ("probable cause", "추정 원인"),
    "k_fstatus_i": ("not a fault: degradation", "결함 아님: 성능 저하"),
    "k_notexam": ("What was NOT examined (a check that was not run is not evidence of absence):",
                  "확인하지 못한 것 (실행하지 못한 검사는 문제가 없다는 근거가 아닙니다):"),
    "k_none": ("Nothing was reported as unexamined.", "확인하지 못했다고 보고된 항목은 없습니다."),
    "nc_target_unreachable": ("The remote target could not be reached over SSH ({items}), so nothing was examined.",
                              "원격 대상에 SSH로 접속하지 못해({items}) 아무것도 확인하지 못했습니다."),
    "nc_invalid_target": ("The remote target description is invalid: {items}.", "원격 대상 설명이 올바르지 않습니다: {items}."),
    "nc_missing_debug_image_remote": ("No debug image was given for the remote target ({items}); provide the matching "
                                      "unstripped ELF with DWARF symbols on this machine.",
                                      "원격 대상에 대한 디버그 이미지가 지정되지 않았습니다({items}). 이 컴퓨터에 있는 같은 버전의 "
                                      "심볼 포함(strip 되지 않은) ELF를 제공하세요."),
    "nc_remote_limitation": ("Remote-target limits (not guessed): {items}.", "원격 대상의 제약 (추측하지 않음): {items}."),
    "nc_collector_not_deployed": ("The native collector is not running on the target, so reads use the slower shell path.",
                                  "대상에서 네이티브 수집기를 쓸 수 없어 더 느린 셸 경로로 읽었습니다."),
    "r_unreach": ("the remote target cannot be reached over SSH: {raw}", "원격 대상에 SSH로 접속할 수 없습니다: {raw}"),
    "r_noimg_remote": ("no debug image was given for the remote target", "원격 대상에 대한 디버그 이미지가 지정되지 않았습니다"),
    "nc_target_unreadable": ("The target process could not be read: {items}.", "대상 프로세스를 읽을 수 없었습니다: {items}."),
    "nc_pid_gone": ("the process does not exist", "프로세스가 존재하지 않습니다"),
    "nc_missing_debug_image": ("The debug image was not found ({items}), so nothing was resolved to variable names.",
                               "디버그 이미지를 찾지 못했습니다({items}). 따라서 변수 이름으로 해석하지 못했습니다."),
    "nc_unsupported_on_target": ("Not supported on this target{abi}, so not checked: {items}.",
                                 "이 대상{abi}에서는 지원되지 않아 확인하지 않았습니다: {items}."),
    "nc_check": ("Checks that ran but ended '{st}', so they decided nothing: {items}.",
                 "실행했지만 '{st}'로 끝나 결론을 내지 못한 검사: {items}."),
    "nc_recipes_not_planned": ("{n} other check(s) were not selected for this symptom: {items}.",
                               "이 증상에는 선택되지 않아 실행하지 않은 다른 검사 {n}개: {items}."),
    "nc_baseline_check_not_run": ("Planned checks that never ran because the investigation ended early: {items}.",
                                  "조사가 일찍 끝나 실행되지 못한 계획된 검사: {items}."),
    "nc_budget_exhausted": ("The observation budget ran out, so the observation was cut short.",
                            "관측 예산이 소진되어 관측이 중간에 끊겼습니다."),
    "nc_leak_owner_limited": ("Finding the owner of the growing memory was only partly possible.",
                              "늘어나는 메모리의 소유자를 찾는 일은 일부만 가능했습니다."),
    "nc_unattributed_finding": ("A finding named no variable, thread, lock or function and was therefore not "
                                "confirmed: {items}.",
                                "이름이 지정되지 않은 발견은 확정하지 않았습니다: {items}."),
    "nc_stage_failed": ("A stage of the diagnosis failed: {items}.", "진단의 한 단계가 실패했습니다: {items}."),
    "nc_not_executed": ("The investigation was planned but nothing was executed.", "조사 계획만 세워지고 실행된 것은 없습니다."),
    "nc_unexpected_error": ("The diagnosis failed unexpectedly: {items}.", "진단이 예기치 않게 실패했습니다: {items}."),
    "nc_abi_detection_failed": ("The target's CPU/libc type could not be detected.",
                                "대상의 CPU/libc 종류를 알아내지 못했습니다."),
    "nc_report_not_saved": ("The full report could not be saved to disk.", "전체 보고서를 디스크에 저장하지 못했습니다."),
    "nc_limitation": ("Limitations reported by the engine:", "엔진이 보고한 제한 사항:"),
    "nc_long_wait_not_judged": ("Threads that waited for the whole window outside a lock; whether that wait is "
                                "expected was not judged (an idle wait and a stall look the same from outside): "
                                "{items}.",
                                "구간 내내 락이 아닌 곳에서 대기한 스레드. 이 대기가 정상인지는 판단하지 않았습니다 "
                                "(밖에서는 유휴 대기와 멈춤이 같아 보임): {items}."),
    "nc_other": ("Other: {kind}:", "그 밖의 항목 {kind}:"),
    "nc_orig": (" (engine text: {raw})", " (엔진 원문: {raw})"),
    # --- next steps
    "n_dl2": ("The two locks {a} and {b} are taken in opposite order: {t1} (function defined at {l1}) and {t2} "
              "(function defined at {l2}) each hold one and wait for the other. Open both functions and make the "
              "order of the two lock calls consistent, for example always take {a} before {b} in both, or protect "
              "both with a single lock.",
              "두 락 {a}와 {b}가 서로 반대 순서로 잡히고 있습니다. {t1} (함수 정의 위치 {l1})과 {t2} "
              "(함수 정의 위치 {l2})가 각각 하나를 잡은 채 다른 하나를 기다립니다. 두 함수를 열어 두 락을 잡는 순서를 "
              "일관되게 바꾸세요. 예를 들어 둘 다 {a}를 먼저 {b}를 나중에 잡거나, 락 하나로 둘을 함께 보호하세요."),
    "n_dl2x": ("The two locks {a} and {b} are taken in opposite order: {t1} (blocked at {l1}) and {t2} "
               "(blocked at {l2}) each hold one and wait for the other. Open both places and make the "
               "order of the two lock calls consistent, for example always take {a} before {b} in both, or protect "
               "both with a single lock.",
               "두 락 {a}와 {b}가 서로 반대 순서로 잡히고 있습니다. {t1} ({l1}에서 멈춤)과 {t2} "
               "({l2}에서 멈춤)가 각각 하나를 잡은 채 다른 하나를 기다립니다. 두 위치를 열어 두 락을 잡는 순서를 "
               "일관되게 바꾸세요. 예를 들어 둘 다 {a}를 먼저 {b}를 나중에 잡거나, 락 하나로 둘을 함께 보호하세요."),
    "n_dln": ("The locks {locks} are taken in a circular order by {thrs}. Define one global lock order and make "
              "every code path follow it.",
              "락 {locks}이(가) {thrs}에 의해 고리 모양의 순서로 잡히고 있습니다. 전역 락 순서를 하나 정하고 "
              "모든 코드 경로가 그것을 따르게 하세요."),
    "n_dl_nolocs": ("Look at where these locks are taken: {where}.", "이 락들이 잡히는 위치를 보세요: {where}."),
    "n_dl_names": ("Look at the lock variables {locks} and at the functions {funcs}; the exact lines were not "
                   "available.",
                   "락 변수 {locks}와 함수 {funcs}를 보세요. 정확한 줄 번호는 얻지 못했습니다."),
    "n_dl_stop": ("To see each thread's full call stack, ask for a stack capture; that pauses the process briefly "
                  "and needs your approval.",
                  "스레드별 전체 호출 스택이 필요하면 스택 캡처를 요청하세요. 프로세스가 잠깐 멈추므로 승인이 필요합니다."),
    "n_leak": ("Look at where {var} is appended to and where entries are removed or capped. The tool did not find "
               "the source line of the append, so search the code for writes to {var}. Check that every path that "
               "adds an entry has a matching removal.",
               "{var}에 항목이 추가되는 곳과 제거되거나 상한이 걸리는 곳을 보세요. 도구는 추가하는 코드의 소스 줄을 "
               "찾지 못했으니 {var}에 쓰는 코드를 직접 검색하세요. 항목을 추가하는 모든 경로에 짝이 되는 제거가 있는지 "
               "확인하세요."),
    "n_leak_thr": ("The allocating thread is {thr}; start with its code.", "할당하는 스레드는 {thr}입니다. 이 스레드의 코드부터 보세요."),
    "n_leak_two": ("Take two readings some time apart to confirm the growth continues.",
                   "시간 간격을 두고 두 번 측정해 증가가 계속되는지 확인하세요."),
    "n_spin": ("Look at {fn} (defined at {loc}): the thread {thr} spends its time there without blocking. Check the loop "
               "condition and whether it should wait on a lock, condition variable or timer instead.",
               "{loc}에 정의된 {fn}을(를) 보세요. 스레드 {thr}이(가) 대기하지 않고 그곳에서 시간을 보냅니다. 반복 조건을 "
               "확인하고, 락·조건 변수·타이머로 기다려야 하는 곳은 아닌지 살펴보세요."),
    "n_spin_at": ("Look at {loc} in {fn}: the thread {thr} spends its time there without blocking. Check the loop "
                  "condition and whether it should wait on a lock, condition variable or timer instead.",
                  "{fn} 안의 {loc}을(를) 보세요. 스레드 {thr}이(가) 대기하지 않고 그곳에서 시간을 보냅니다. 반복 조건을 "
                  "확인하고, 락·조건 변수·타이머로 기다려야 하는 곳은 아닌지 살펴보세요."),
    "n_generic_names": ("Start with {names}.", "{names}부터 확인하세요."),
    "n_generic_none": ("No names were attached to the finding. Re-run with a more specific symptom or a debug "
                       "image so the cause can be named.",
                       "발견에 이름이 붙어 있지 않습니다. 더 구체적인 증상을 주거나 디버그 이미지를 제공해 다시 "
                       "실행하면 원인을 지목할 수 있습니다."),
    # stage 2: the symptom text was not understood specifically, so the broad plan was used
    "sym_unclear": ("Note: the symptom was not understood specifically ({why}), so a broad plan was used: every "
                    "baseline check plus one representative check from each domain. To narrow the investigation, "
                    "describe what you observe (for example: it hangs, memory keeps growing) or give the symptom kind.",
                    "참고: 증상을 구체적으로 이해하지 못했습니다({why}). 그래서 넓은 계획을 사용했습니다. 모든 기본 검사와 "
                    "각 영역의 대표 검사 하나씩을 실행합니다. 조사를 좁히려면 관찰한 현상(예: 멈춘다, 메모리가 계속 "
                    "늘어난다)을 적거나 증상 종류를 지정하세요."),
    "sym_why_no_match": ("no known symptom wording was recognised", "알려진 증상 표현을 찾지 못했습니다"),
    "sym_why_weak": ("only weak hints were found", "약한 단서만 있었습니다"),
    "sym_why_conflict": ("the description points to several different problems", "설명이 서로 다른 여러 문제를 가리킵니다"),
    "n_incon_intro": ("A conclusion needs more input. Any of these would help:", "결론을 내려면 입력이 더 필요합니다. 다음 중 하나가 도움이 됩니다:"),
    "n_incon_img": ("Provide the debug image (the unstripped build of the same program version) with the "
                    "--debug-image option.",
                    "디버그 이미지(같은 버전 프로그램의 심볼이 있는 빌드)를 --debug-image 옵션으로 제공하세요."),
    "n_incon_sym": ("Describe the symptom more specifically (for example: it hangs, memory keeps growing, one "
                    "CPU core is at 100%) and run the diagnosis again.",
                    "증상을 더 구체적으로 알려주세요(예: 멈춘다, 메모리가 계속 늘어난다, CPU 코어 하나가 100%다). "
                    "그 뒤 진단을 다시 실행하세요."),
    "n_incon_stop": ("If you approve a short pause of the process, a stopped capture can read what the "
                     "non-stopping capture could not.",
                     "프로세스를 잠시 멈추는 것을 승인하면, 멈추지 않는 수집으로 읽지 못한 것을 멈춘 상태의 "
                     "캡처로 읽을 수 있습니다."),
    "n_incon_pid": ("Check the pid, and that you run this as the same user as the process (or with ptrace "
                    "permission).",
                    "pid가 맞는지, 그리고 프로세스와 같은 사용자(또는 ptrace 권한)로 실행했는지 확인하세요."),
    "n_incon_nc": ("Several items in section 4 were not examined; resolving the ones listed there is the shortest "
                   "way to a conclusion.",
                   "4번 항목에 확인하지 못한 항목이 있습니다. 거기 적힌 것들을 해결하는 것이 결론에 이르는 가장 "
                   "빠른 길입니다."),
    "n_healthy": ("Nothing needs fixing based on these checks. If a symptom persists, describe it more "
                  "specifically and run again; also consider the items in section 4.",
                  "이 검사 결과로는 고칠 것이 없습니다. 증상이 계속되면 더 구체적으로 알려 다시 실행하고 4번 항목도 "
                  "함께 고려하세요."),
    # --- impact
    "i_mode": ("Capture mode: {mode}.", "수집 방식: {mode}."),
    "i_zero": ("The process was not stopped: measured stop time {ms} ms.", "프로세스를 멈추지 않았습니다. 측정된 정지 시간은 {ms} ms입니다."),
    "i_stop": ("The process was paused: measured stop time {ms} ms.", "프로세스가 일시 정지되었습니다. 측정된 정지 시간은 {ms} ms입니다."),
    "i_bytes": ("Bytes read from the process: {b}.", "프로세스에서 읽은 바이트: {b}."),
    "i_wall": ("Wall-clock time of the observation: {ms} ms; samples collected: {s}.",
               "관측에 걸린 실제 시간: {ms} ms, 수집한 샘플: {s}개."),
    "i_budget": ("The observation budget was exhausted.", "관측 예산이 소진되었습니다."),
    "i_none": ("No measurement is available: nothing was collected from the target.",
               "측정값이 없습니다. 대상에서 수집된 것이 없습니다."),
    "i_report": ("Full report: {p}", "전체 보고서: {p}"),
    # --- diagram
    "d_hdr": ("thread --waits--> lock --held by--> thread", "스레드 --기다림--> 락 --잡고 있는 쪽--> 스레드"),
    "d_waits": ("--waits-->", "--기다림-->"),
    "d_held": ("--held by-->", "--잡고 있는 쪽-->"),
    # ------------------------------------------------------------------------------------------ common outline
    # Every report (summary, incident Markdown, incident HTML; every verdict) has these sections in this order; a
    # section with nothing to say is left out and the rest are numbered consecutively (see ``compose``).
    "s_conclusion": ("Conclusion", "결론"),
    "s_findings": ("What was found", "발견된 문제"),
    "s_target": ("Target", "대상"),
    "s_profile": ("Process profile", "프로세스 프로필"),
    "s_not_examined": ("Not examined", "확인하지 못한 것"),
    "s_hypothesis": ("The hypothesis you asked to check", "요청한 가설 검증"),
    "s_next": ("What to do next", "다음에 할 일"),
    "s_scope": ("Checks", "검사"),
    "s_method": ("How the diagnosis was done and what it cost the target", "진단 방법과 대상에 준 영향"),
    "s_repro": ("Reproducibility", "재현 정보"),
    "s_reference": ("Reference", "참고 자료"),
    # conclusion: the verdict in words, then what it means
    "v_line": ("**Verdict: {word}** ({code}). {meaning}", "**판정: {word}** ({code}). {meaning}"),
    "v_CONFIRMED_FAULT": ("confirmed fault", "확인된 결함"),
    "v_PROBABLE_FAULT": ("probable fault", "결함 추정"),
    "v_FAULT": ("probable fault", "결함 추정"),
    "v_DEGRADED": ("degraded, not a fault", "성능 저하 (결함 아님)"),
    "v_HEALTHY": ("healthy within the checked scope", "점검한 범위 안에서 정상"),
    "v_INCONCLUSIVE": ("could not decide", "판단 불가"),
    "v_ABORTED": ("aborted", "중단됨"),
    "vm_CONFIRMED_FAULT": ("The evidence collected establishes the problem.", "확보한 증거가 문제를 입증합니다."),
    "vm_PROBABLE_FAULT": ("The evidence points to a problem but does not fully prove it.",
                          "증거가 문제를 가리키지만 완전히 입증하지는 못합니다."),
    "vm_FAULT": ("The evidence points to a problem but does not fully prove it.",
                 "증거가 문제를 가리키지만 완전히 입증하지는 못합니다."),
    "vm_DEGRADED": ("Something slows the process down, but nothing is broken.",
                    "프로세스를 느리게 하는 것이 있지만 고장 난 것은 없습니다."),
    "vm_HEALTHY": ("Nothing is claimed outside the checked scope.", "점검한 범위 밖에 대해서는 판단하지 않습니다."),
    "vm_INCONCLUSIVE": ("The checks gave no answer; this does not mean the process is fine.",
                        "검사가 답을 내지 못했습니다. 문제가 없다는 뜻이 아닙니다."),
    "vm_ABORTED": ("The diagnosis stopped before it could answer; this does not mean the process is fine.",
                   "진단이 답을 내기 전에 멈췄습니다. 문제가 없다는 뜻이 아닙니다."),
    "c_more2": (" {n} more finding(s) are described under '{sec}'.", " 그 밖의 발견 {n}건은 '{sec}'에 있습니다."),
    "c_healthy_short": ("{who} is healthy within the checked scope: all {n} baseline checks ran to completion and "
                        "found nothing. Not checked: {nc}.",
                        "{who}은(는) 점검한 범위 안에서 정상입니다. 기본 검사 {n}개가 모두 끝까지 실행되었고 아무것도 "
                        "발견하지 못했습니다. 점검하지 못한 것: {nc}."),
    "nc_short_long_wait": ("whether the long wait of {n} thread(s) is expected", "스레드 {n}개의 긴 대기가 정상인지"),
    "nc_short_symptom": ("{n} symptom-specific check(s) that reached no result", "결론을 내지 못한 증상별 추가 검사 {n}개"),
    "nc_short_in_mode": ("{n} check(s) a zero-stop diagnosis cannot answer", "무정지 진단으로는 답할 수 없는 검사 {n}개"),
    "nc_short_outside": ("data races, program-logic errors and other defects no baseline check looks for",
                         "데이터 레이스, 프로그램 논리 오류처럼 기본 검사가 찾지 않는 결함"),
    "c_healthy_noscope2": ("The checks that ran found no problem in {who}; this does not prove the process is fine "
                           "(see '{sec}' for what was not examined).",
                           "{who}에서 실행된 검사로는 문제가 발견되지 않았습니다. 다만 이것이 문제가 없다는 증명은 "
                           "아니며, 확인하지 못한 항목은 '{sec}'에 있습니다."),
    # findings
    "f_head": ("Finding {i}: {label}", "발견 {i}: {label}"),
    "f_certainty": ("**Certainty**: {status}; severity: {sev}.", "**확실성**: {status}, 심각도 {sev}."),
    "f_found_by": ("**Found by**: {checks}.", "**찾은 검사**: {checks}."),
    "f_related": ("**Related checks**: {checks}.", "**관련 검사**: {checks}."),
    "f_records": (" Evidence records: {n}.", " 근거 기록 {n}건."),
    "f_why": ("**Why this conclusion**", "**판단 근거**"),
    # static location candidates (extractor.static_location_candidates): statically derived, never observed
    "f_cands": ("**Location candidates** (static analysis, not observed): {locs}.",
                "**위치 후보**(정적 분석, 관측 아님): {locs}."),
    "f_cands_head": ("Location candidates (static analysis, not observed)", "위치 후보 (정적 분석, 관측 아님)"),
    # object relations (extractor.object_relations): memory object <- owning variable <- thread, each link with how
    "f_rel": ("**Relation**: {chain}.", "**관계**: {chain}."),
    "rel_arrow": (" ← ({how}) ", " ← ({how}) "),
    "rel_ne": ("not established: {why}", "확인되지 않음: {why}"),
    "rel_m_heap_blocks": ("heap blocks +{n}{kb}", "힙 블록 +{n}개{kb}"),
    "rel_m_heap_blocks_class": ("heap blocks of {c} B +{n}{kb}", "{c} B 힙 블록 +{n}개{kb}"),
    "rel_kb": (" (+{kb} KB)", "(+{kb} KB)"),
    "rel_m_heap_block": ("heap block {x}", "힙 블록 {x}"),
    "rel_m_heap_block_free": ("freed heap block {x}", "해제된 힙 블록 {x}"),
    "rel_m_mapping": ("grown mapping {x}{kb}", "늘어난 매핑 {x}{kb}"),
    "rel_m_lock": ("lock {x}", "락 {x}"),
    "rel_m_global_storage": ("storage of {x}", "{x}의 저장 공간"),
    "rel_m_none": ("no memory object", "메모리 객체 없음"),
    "rel_m_unknown": ("memory object", "메모리 객체"),
    "rel_var": ("variable {x}", "변수 {x}"),
    "rel_var_cont": ("variable {x} ({t}, {n} elements)", "변수 {x}({t}, 원소 {n}개)"),
    "rel_var_ne": ("variable", "변수"),
    "rel_thr": ("thread {x}", "스레드 {x}"),
    "rel_thr_ne": ("thread", "스레드"),
    "rel_how_typed_pointer_path": ("observed pointer path", "관측한 포인터 경로"),
    "rel_how_dangling_pointer": ("pointer still holding the freed address", "해제된 주소를 아직 가진 포인터"),
    "rel_how_holds_reference": ("pointer holding its address", "주소를 가진 포인터"),
    "rel_how_pointer_into_mapping": ("pointer into the mapping", "매핑 안을 가리키는 포인터"),
    "rel_how_debug_symbol": ("debug information", "디버그 정보"),
    "rel_how_arena_attribution": ("arena attribution", "아레나 귀속"),
    "rel_how_run_counters": ("per-thread run counters", "스레드별 실행 카운터"),
    "rel_how_lock_owner_field": ("mutex owner field", "뮤텍스 소유자 필드"),
    "rel_how_thread_samples": ("thread samples", "스레드 샘플"),
    "rel_ne_unreachable": ("no reference remains", "참조가 남아 있지 않음"),
    "rel_ne_untraced_use": ("using thread not observable without tracing", "추적 없이는 사용 스레드를 볼 수 없음"),
    "rel_ne_untraced_free": ("free() calls are not traced", "free() 호출은 추적하지 않음"),
    "rel_ne_untraced_write": ("writing thread not observable without tracing", "추적 없이는 쓴 스레드를 볼 수 없음"),
    "rel_ne_mmapped_no_arena": ("mmapped blocks have no arena", "mmap 블록은 아레나가 없음"),
    "rel_ne_arena_shared": ("several threads share the arena", "여러 스레드가 아레나를 공유함"),
    "rel_ne_arena_unattributed": ("arena not tied to one thread", "아레나가 한 스레드에 묶이지 않음"),
    "rel_ne_no_owner_variable": ("no variable holds its address", "주소를 가진 변수를 찾지 못함"),
    "rel_ne_no_path": ("no variable path reaches it", "이르는 변수 경로가 없음"),
    "rel_ne_no_mapping_owner": ("no variable points into it", "가리키는 변수가 없음"),
    "rel_ne_no_single_thread": ("not exactly one thread ran", "실행한 스레드가 하나가 아님"),
    "rel_ne_owner_changed": ("the owner changed between samples", "샘플마다 소유자가 바뀜"),
    "rel_ne_owner_unread": ("owner field not read", "소유자 필드를 읽지 못함"),
    "rel_ne_no_symbol": ("no variable at that address", "그 주소의 변수가 없음"),
    "rel_ne_not_memory": ("about execution, not memory", "실행에 관한 발견이며 메모리 객체가 아님"),
    "rel_ne_other": ("see the result JSON", "결과 JSON 참고"),
    "f_cands_note": ("Chosen from the debug information and the source text, not seen at runtime; they do not "
                     "confirm where the defect happened. Ranked by how directly they relate to the finding.",
                     "디버그 정보와 소스 코드로 고른 후보이며 실행 중에 본 위치가 아닙니다. 결함이 생긴 위치를 확인한 "
                     "것도 아닙니다. 발견과 얼마나 직접 이어지는지에 따라 순위를 매겼습니다."),
    "f_cand_item": ("`{loc}` in `{fn}`: `{stmt}`. Why: {why}.", "`{loc}`(`{fn}`): `{stmt}`. 고른 이유: {why}."),
    "sev_CRITICAL": ("critical", "치명적"), "sev_HIGH": ("high", "높음"), "sev_MEDIUM": ("medium", "중간"),
    "sev_WARNING": ("warning", "경고"), "sev_LOW": ("low", "낮음"), "sev_INFO": ("informational", "참고"),
    # next steps
    "n_asan": ("To catch the faulty access at the moment it happens, rebuild with AddressSanitizer "
               "(`-fsanitize=address -g`) and reproduce the problem in a test environment.",
               "잘못된 접근이 일어나는 순간을 잡으려면 AddressSanitizer(`-fsanitize=address -g`)로 다시 빌드해 시험 "
               "환경에서 문제를 재현해 보세요."),
    "n_healthy2": ("Nothing needs fixing based on these checks. If a symptom persists, describe it more specifically "
                   "and run again, and keep in mind what '{sec}' lists as not examined.",
                   "이 검사 결과로는 고칠 것이 없습니다. 증상이 계속되면 더 구체적으로 알려 다시 실행하고, '{sec}'에 "
                   "적힌 항목도 함께 고려하세요."),
    "n_incon_nc2": ("Several items under '{sec}' were not examined; resolving those is the shortest way to a "
                    "conclusion.",
                    "'{sec}'에 확인하지 못한 항목이 있습니다. 그것들을 해결하는 것이 결론에 이르는 가장 빠른 "
                    "길입니다."),
    # scope (the one definition of "checks": run = found + clean + could not judge; not run is separate)
    "s_counts": ("{run} checks ran: {found} found a problem, {undecided} could not judge and {clean} passed.",
                 "검사 {run}개를 실행했습니다. 이상 발견 {found}개, 판단 불가 {undecided}개, 통과 {clean}개입니다."),
    "s_counts_none": ("No check ran.", "실행된 검사가 없습니다."),
    "s_notrun": (" Another {n} were not run.", " 실행하지 않은 검사가 {n}개 더 있습니다."),
    "s_caveat": ("A check that could not judge, or was not run, is not evidence that the process is fine.",
                 "판단 불가이거나 실행 안 한 검사는 문제가 없다는 근거가 아닙니다."),
    "s_healthy": ("What the healthy verdict covers: the {n} baseline checks ran to completion and found nothing. "
                  "What is listed as could not judge, not run or not examined is outside the verdict.",
                  "정상 판정이 다루는 범위: 기본 검사 {n}개가 끝까지 실행되어 아무것도 발견하지 못했다는 것입니다. "
                  "판단 불가, 실행 안 함, 확인하지 못한 것으로 적힌 항목은 이 판정에 포함되지 않습니다."),
    # the four status words of the design system (docs/ui-redesign/DESIGN_SYSTEM_KO.md), identical in the live UI
    "g_FAIL": ("Found a problem", "이상 발견"),
    "g_INCONCLUSIVE": ("Could not judge", "판단 불가"),
    "g_PASS": ("Passed", "통과"),
    "g_SKIPPED": ("Not run", "실행 안 함"),
    "g_other": ("Also not examined", "그 밖에 확인하지 못한 것"),
    "g_fail_row": ("{name}: looks for {what}; it is the basis of finding {fi}.",
                   "{name}: 이 검사가 찾는 것은 '{what}'이며, 발견 {fi}의 근거입니다."),
    "g_fail_row_nf": ("{name}: looks for {what}.", "{name}: 이 검사가 찾는 것은 '{what}'입니다."),
    "g_baseline": ("Baseline checks ({n})", "기본 검사 ({n}개)"),
    "g_extra": ("Other checks ({n})", "그 밖의 검사 ({n}개)"),
    "g_why_cap": ("needs a capability that is not available here ({cap})", "여기서 쓸 수 없는 기능({cap})이 필요함"),
    "g_why_none": ("the check recorded no reason", "검사가 이유를 기록하지 않음"),
    "g_why_status": ("{st}", "{st}"),
    "g_not_planned": ("not selected for this symptom", "이번 증상에 선택되지 않음"),
    "g_not_in_mode": ("not examined in this mode: a zero-stop diagnosis cannot answer these (they need {cap})",
                      "무정지 진단으로는 답할 수 없어 점검하지 않은 검사 (필요한 것: {cap})"),
    "g_not_executed": ("planned but not executed before the investigation ended", "계획했지만 조사가 끝날 때까지 실행되지 않음"),
    "st_NOT_APPLICABLE": ("the check does not apply to this target", "이 대상에는 적용되지 않는 검사"),
    "st_ERROR": ("the check itself ended with an error", "검사 자체가 오류로 끝남"),
    "st_UNSUPPORTED": ("not supported on this target", "이 대상에서 지원되지 않음"),
    "st_TIMEOUT": ("the check ran out of time", "검사 시간이 초과됨"),
    # target card
    "t_proc": ("Process", "프로세스"), "t_arch": ("Architecture", "아키텍처"), "t_kernel": ("Target kernel", "대상 커널"),
    "t_exe": ("Executable", "실행 파일"), "t_build": ("Build ID", "빌드 ID"), "t_debug": ("Debug info", "디버그 정보"),
    "t_transport": ("Transport", "전송"), "t_unknown": ("unknown", "알 수 없음"), "t_none": ("none", "없음"),
    "t_bid_MATCHED": ("matches the debug info", "디버그 정보와 일치"),
    "t_bid_MISMATCHED": ("does not match the debug info", "디버그 정보와 불일치"),
    "t_bid_UNKNOWN": ("comparison with the debug info not recorded", "디버그 정보와의 비교가 기록되지 않음"),
    "t_local": ("local (this host)", "로컬 (이 호스트)"), "t_ssh": ("SSH to {host}", "SSH ({host})"),
    "t_redetected": (" (re-read at export time, not recorded during the diagnosis)",
                     " (진단 때 기록되지 않아 보고서를 만들 때 다시 읽음)"),
    # the four figures of the tiles (Markdown has no tiles: one line, same place)
    "gl_line": ("**At a glance**: {x}.", "**한눈에 보기**: {x}."),
    "gl_checks": ("{run} checks run", "검사 {run}개 실행"), "gl_notrun": (" (+{n} not run)", " (실행 안 함 {n}개 별도)"),
    "gl_stop": ("target stop time {ms}", "대상 정지 시간 {ms}"), "gl_never": (", never paused", ", 한 번도 멈추지 않음"),
    "gl_bytes": ("data read {b}", "읽은 데이터 {b}"), "gl_dur": ("took {t}", "소요 시간 {t}"),
    # not examined
    "ne_pointer": ("The {u} check(s) that could not judge and the {n} that were not run are listed under '{sec}'.",
                   "판단 불가 검사 {u}개와 실행 안 한 검사 {n}개는 '{sec}'에 있습니다."),
    "m_mode": ("The process was read while it kept running (capture mode {mode}); the stop time is measured, not assumed.",
               "프로세스가 실행되는 동안 읽었습니다 (수집 방식 {mode}). 정지 시간은 가정이 아니라 측정값입니다."),
    "m_mode_stop": ("The process was paused while it was read (capture mode {mode}); the stop time is measured.",
                    "읽는 동안 프로세스가 일시 정지되었습니다 (수집 방식 {mode}). 정지 시간은 측정값입니다."),
    # method and cost
    "m_target": ("Target: {who}{abi}, debug image {img}.", "대상: {who}{abi}, 디버그 이미지 {img}."),
    "m_target_noimg": ("Target: {who}{abi}, no debug image was used.", "대상: {who}{abi}, 디버그 이미지 없음."),
    "m_build": (" Build ID {b}.", " 빌드 ID {b}."),
    "m_zero": ("The process was read while it kept running and was never paused (measured stop time {ms}; capture "
               "mode {mode}).",
               "프로세스가 실행되는 동안 읽었고 한 번도 멈추지 않았습니다 (측정된 정지 시간 {ms}, 수집 방식 {mode})."),
    "m_stop": ("The process was paused for {ms} in total (measured; capture mode {mode}).",
               "프로세스가 모두 {ms} 동안 일시 정지되었습니다 (측정값, 수집 방식 {mode})."),
    "m_time": ("The observation took {obs} and collected {s} samples.", "관측에 {obs}가 걸렸고 샘플 {s}회를 모았습니다."),
    "m_total": (" The whole diagnosis took {tot}.", " 진단 전체에는 {tot}가 걸렸습니다."),
    "m_bytes": ("Data read from the target: {b}.", "대상에서 읽은 데이터: {b}."),
    "m_cpu": ("CPU used by the diagnosis: {ms} (the whole diagnosing process including analysis, so an upper bound of "
              "what reading cost).",
              "진단이 쓴 CPU: {ms} (분석까지 포함한 진단 프로세스 전체이므로 읽기 비용의 상한입니다)."),
    "m_cpu_other": ("CPU used by the diagnosis: {ms} (basis {basis}).", "진단이 쓴 CPU: {ms} (산정 기준 {basis})."),
    "m_target_cpu": ("In the same window the target itself used {ms} of CPU and the machine was {pct}% busy; that is "
                     "the target's own activity, not caused by the diagnosis.",
                     "같은 구간에 대상 자신은 CPU를 {ms} 썼고 시스템 전체 CPU 사용률은 {pct}%였습니다. 이것은 대상 "
                     "자체의 활동이며 진단이 일으킨 것이 아닙니다."),
    "m_collector": ("Collector process on the target: CPU {cpu}, peak memory {rss}.",
                    "대상 쪽 수집 프로세스: CPU {cpu}, 최대 메모리 {rss}."),
    "m_budget": ("The observation budget ran out, so the result is partial ({why}).",
                 "관측 예산이 소진되어 결과가 부분적입니다 ({why})."),
    "m_ids": ("Investigation id {inv}.", "조사 ID {inv}."),
    "m_report": (" Full report: {p}.", " 전체 보고서: {p}."),
    "m_generated": ("Report generated {ts}.", "보고서 생성 시각: {ts}."),
    "m_none": ("Nothing was collected from the target, so there is no measurement.",
               "대상에서 수집된 것이 없어 측정값이 없습니다."),
    # reference
    "r_where": ("Where the detail is", "상세 기록의 위치"),
    "r_where_intro": ("The detailed records (in English) are attached to each part of the HTML report and are in "
                      "the JSON result:",
                      "상세 기록(영문)은 HTML 보고서의 각 부분에 붙어 있고 JSON 결과에도 있습니다:"),
    "p_verdict": ("How the verdict was derived", "판정 근거"),
    "p_finding": ("Finding {i}", "발견 {i}"),
    "p_checks": ("Each check's result", "검사별 결과"),
    "p_scope": ("Check totals and limitations", "검사 집계와 제한 사항"),
    "p_method": ("Target, collection and plan", "대상, 수집, 계획"),
    "p_repro": ("Exact time of every check", "검사별 정확한 시각"),
    "p_line": ("{what}: HTML {anchor}; JSON {keys}.", "{what}: HTML {anchor}, JSON {keys}."),
    "seconds": ("{x} s", "{x}초"),
}

VERDICT_WORD = {
    "CONFIRMED_FAULT": "k_conf", "PROBABLE_FAULT": "k_prob", "FAULT": "k_prob", "DEGRADED": "k_degraded",
    "HEALTHY": "k_healthy", "INCONCLUSIVE": "k_incon", "ABORTED": "k_abort",
}

CATEGORY_LABEL = {
    "DEADLOCK_INDICATORS": ("deadlock", "교착 상태(deadlock)"),
    "MEMORY_LEAK": ("memory leak / unbounded growth", "메모리 누수·무제한 증가"),
    "PROCESS_INSTABILITY": ("misbehaving thread (process instability)", "스레드 이상 동작(프로세스 불안정)"),
    "MEMORY_CORRUPTION": ("memory corruption", "메모리 손상"),
    "INVALID_DOUBLE_FREE": ("invalid or double free", "잘못된 해제·이중 해제"),
    "USE_AFTER_FREE": ("use after free", "해제 후 사용"),
    "STACK_CORRUPTION": ("stack corruption", "스택 손상"),
    "DATA_RACE_INDICATORS": ("data race", "데이터 레이스"),
    "ABNORMAL_VARIABLE_CHANGES": ("abnormal variable changes", "변수 값의 이상 변화"),
    "UNEXPECTED_STATE_TRANSITIONS": ("unexpected state transitions", "예상 밖 상태 전이"),
    "RESOURCE_EXHAUSTION": ("resource exhaustion", "자원 고갈"),
    "FUNCTIONAL_STATE_INCONSISTENCY": ("inconsistent program state", "프로그램 상태 불일치"),
}

# glossary: key -> (term en, def en, term ko, def ko)
GLOSSARY: Dict[str, Tuple[str, str, str, str]] = {
    "deadlock": ("deadlock", "threads wait for each other's locks in a circle, so none can continue.",
                 "교착 상태(deadlock)", "스레드들이 서로가 쥔 락을 원형으로 기다려 아무도 진행하지 못하는 상태."),
    "lock": ("lock (mutex)", "a flag a thread takes so that only one thread uses shared data at a time.",
             "락(뮤텍스)", "공유 데이터를 한 번에 한 스레드만 쓰도록 스레드가 잡는 표식."),
    "waitfor": ("wait-for cycle", "the chain thread -> lock -> owning thread -> lock ... that closes on itself.",
                "대기 고리", "스레드 -> 락 -> 그 락을 쥔 스레드 -> 락 ... 으로 이어져 처음으로 돌아오는 연결."),
    "leak": ("unbounded growth / leak", "memory that is taken and never given back, so the process only grows.",
             "무제한 증가·누수", "가져가기만 하고 돌려주지 않아 프로세스가 계속 커지기만 하는 메모리."),
    "heap": ("heap", "the memory area a program allocates from while it runs (malloc / new).",
             "힙(heap)", "프로그램이 실행 중에 할당받는 메모리 영역(malloc / new)."),
    "path": ("variable path", "a variable followed through its pointers, e.g. head(->next)* means every node "
             "reached by repeatedly following next.",
             "변수 경로", "변수에서 포인터를 따라간 길. 예: head(->next)*는 next를 반복해 따라 닿는 모든 노드."),
    "spin": ("spin", "a thread that keeps running a loop without waiting, using CPU without making progress.",
             "공회전(spin)", "대기하지 않고 반복문을 계속 돌며 진전 없이 CPU만 쓰는 스레드."),
    "runnable": ("runnable fraction", "the share of samples in which the thread was ready to run (not waiting).",
                 "실행 가능 비율", "샘플 중 스레드가 대기하지 않고 실행할 준비가 되어 있던 비율."),
    "zerostop": ("zero-stop", "the process was read while it kept running; it was never paused.",
                 "무중단(zero-stop)", "프로세스가 계속 실행되는 상태에서 읽었고, 한 번도 멈추지 않았다는 뜻."),
    "debug": ("debug info (debug image)", "the build of the program that still carries variable and line information "
              "(DWARF).", "디버그 정보(디버그 이미지)", "변수와 줄 정보(DWARF)가 남아 있는 프로그램 빌드."),
    "verdict": ("confirmed / probable / could not decide", "confirmed = proven by the evidence, probable = likely but "
                "not fully proven, could not decide = the checks gave no answer (this does not mean the process is fine).",
                "확정 / 추정 / 판단 불가", "확정(확인된 결함, 확정된 근본 원인) = 증거로 입증됨, 추정(결함 추정, 추정 원인) "
                "= 가능성이 높으나 완전히 입증되지 않음, 판단 불가 = 검사가 답을 내지 못함(문제가 없다는 뜻이 아님)."),
    # the same line for a HEALTHY result (the healthy term is only defined where the verdict is HEALTHY)
    "verdict_healthy": ("confirmed / probable / healthy / could not decide", "confirmed = proven by the evidence, "
                        "probable = likely but not fully proven, healthy = every baseline check ran to completion and "
                        "found nothing (only within the checked scope; what was not checked is listed), could not "
                        "decide = the checks gave no answer.",
                        "확정 / 추정 / 정상 / 판단 불가", "확정 = 증거로 입증됨, 추정 = 가능성이 높으나 완전히 입증되지 "
                        "않음, 정상 = 모든 기본 검사가 끝까지 실행되어 아무것도 발견하지 못함(점검한 범위 안에서만이며, "
                        "점검하지 못한 것은 따로 적음), 판단 불가 = 검사가 답을 내지 못함."),
}

_STATUS_WORD = {"inconclusive": ("inconclusive", "판단 불가"), "error": ("error", "오류"),
                "skipped": ("skipped", "건너뜀"), "not_executed": ("not executed", "실행 안 됨"),
                "timeout": ("timed out", "시간 초과")}

_RUNTIME_FRAMES = {"start_thread", "thread_start", "clone", "clone3", "__clone", "__clone3", "pthread_mutex_lock",
                   "pthread_mutex_timedlock", "pthread_cond_wait", "pthread_cond_timedwait", "futex_wait"}
_THREAD_ROW_KEYS = ("stalled_lock_waits", "runaway_threads", "long_wait_threads", "thread_summary",
                    "d_state_threads", "zombie_threads", "contended_lock_waits")


class _Ctx:
    def __init__(self, lang: str):
        self.i = 1 if lang == "ko" else 0
        self.lang = lang
        self.terms: List[str] = []
        self.extra: Dict[str, Any] = {}

    def t(self, key: str, **kw: Any) -> str:
        return T[key][self.i].format(**kw)

    def term(self, key: str) -> None:
        if key not in self.terms:
            self.terms.append(key)


def _c(x: Any) -> str:
    """Identifier in a Markdown code span (never translated)."""
    s = str(x).replace("`", "'")
    return f"`{s}`"


def _join(items: List[str]) -> str:
    return ", ".join(items)


def _num(x: Any) -> str:
    if isinstance(x, float) and x == int(x) and abs(x) >= 1000:
        return str(int(x))
    return str(x)


def _who(ctx: _Ctx, target: Dict[str, Any]) -> str:
    name = target.get("process_name")
    pid = target.get("pid")
    proc = _c(name) if name else ctx.t("unknown_proc")
    return f"{proc} (pid {pid})" if pid is not None else proc


# ------------------------------------------------------------------------------------------ data helpers
def _details(f: Dict[str, Any]) -> List[Tuple[str, str]]:
    d = [(str(x.get("kind")), str(x.get("name"))) for x in (f.get("subject_details") or []) if isinstance(x, dict)]
    if d:
        return d
    return [("name", str(s)) for s in (f.get("subjects") or [])]


def _by_kind(f: Dict[str, Any]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for k, n in _details(f):
        if n not in out.setdefault(k, []):
            out[k].append(n)
    return out


def _user_funcs(funcs: List[str]) -> List[str]:
    return [x for x in funcs if x not in _RUNTIME_FRAMES and not x.startswith("__")]


def _checks(report: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(report, dict):
        return []
    sec = report.get("section_d_detailed_inspection_results") or {}
    return [c for c in (sec.get("checks") or []) if isinstance(c, dict)]


def _observations(report: Optional[Dict[str, Any]], recipe_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    out = []
    for c in _checks(report):
        if recipe_ids and c.get("recipe_id") not in recipe_ids:
            continue
        o = c.get("actual_observations")
        if isinstance(o, dict):
            out.append(o)
    return out


def _thread_rows(report: Optional[Dict[str, Any]], recipe_ids: Optional[List[str]] = None) -> Dict[int, Dict[str, Any]]:
    rows: Dict[int, Dict[str, Any]] = {}
    for o in _observations(report, recipe_ids):
        for key in _THREAD_ROW_KEYS:
            for r in (o.get(key) or []):
                if isinstance(r, dict) and isinstance(r.get("tid"), int):
                    cur = rows.setdefault(r["tid"], {})
                    for k, v in r.items():
                        if v not in (None, "") and (k not in cur or key != "thread_summary"):
                            cur[k] = v
    return rows


def _cycle(report: Optional[Dict[str, Any]], recipe_ids: Optional[List[str]] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    for o in _observations(report, recipe_ids) or _observations(report):
        cyc = o.get("deadlock_cycle")
        if o.get("deadlock_detected") and isinstance(cyc, list) and cyc:
            return [e for e in cyc if isinstance(e, dict)], o
    return [], {}


def _thread_label(ctx: _Ctx, tid: Any, rows: Dict[int, Dict[str, Any]], name_hint: Optional[str], same_names: bool) -> str:
    row = rows.get(tid) if isinstance(tid, int) else None
    fn = (row or {}).get("top_function") or (row or {}).get("function")
    name = name_hint or (row or {}).get("name")
    if name and not same_names:
        return f"{_c(name)} (tid {tid})"
    if fn:
        return f"{_c(fn)} (tid {tid})"
    return f"tid {tid}" + (f" ({_c(name)})" if name else "")


def _growth(f: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    path = None
    for o in _observations(report, f.get("recipe_ids")):
        li = o.get("leak_investigation")
        for g in (li or {}).get("growth_owners") or []:
            if isinstance(g, dict) and g.get("variable_path"):
                return {"path": g["variable_path"], "var": g.get("variable"), "blocks": g.get("blocks_delta"),
                        "kb": round(float(g.get("bytes_delta") or 0) / 1024.0),
                        "win": li.get("window_s"), "rate": g.get("rate_kb_per_s"),
                        "thr": g.get("allocating_thread_name"), "tid": g.get("allocating_thread_tid"),
                        "walks": li.get("walks"), "still_ref": True, "container": g.get("container")}
    m = re.search(r"under (\S+): \+(\d+) blocks / \+(\d+(?:\.\d+)?) KB in use over ([\d.]+) s \(([\d.]+) KB/s\)",
                  f.get("description") or "")
    kinds = _by_kind(f)
    if m:
        var = next((v for v in kinds.get("variable", []) if v != m.group(1) and m.group(1).startswith(v)), None)
        return {"path": m.group(1), "var": var, "blocks": m.group(2), "kb": m.group(3), "win": m.group(4),
                "rate": m.group(5), "thr": (kinds.get("thread_name") or [None])[0],
                "tid": (kinds.get("thread") or [None])[0], "walks": None,
                "still_ref": "still referenced" in (f.get("description") or "")}
    if path is None and kinds.get("variable"):
        vs = kinds["variable"]
        p = next((v for v in vs if "->" in v or "*" in v or "[" in v), vs[0])
        return {"path": p, "var": next((v for v in vs if v != p and p.startswith(v)), vs[0] if p != vs[0] else None),
                "blocks": None, "kb": None, "win": None, "rate": None,
                "thr": (kinds.get("thread_name") or [None])[0], "tid": (kinds.get("thread") or [None])[0],
                "walks": None, "still_ref": False}
    return None


# ------------------------------------------------------------------------------------------ per-finding
def _render_deadlock(ctx: _Ctx, f: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Returns {'lines': [...], 'diagram': [...], 'info': {...}} for section 2 / 5 / 3."""
    ctx.term("deadlock"); ctx.term("lock")
    kinds = _by_kind(f)
    cyc, obs = _cycle(report, f.get("recipe_ids"))
    rows = _thread_rows(report, f.get("recipe_ids"))
    lines: List[str] = []
    diagram: List[str] = []
    info: Dict[str, Any] = {"cycle": cyc, "locks": [], "threads": [], "where": [], "where_exact": []}
    if cyc:
        ctx.term("waitfor")
        names = {e.get("waiter_name") for e in cyc} | {e.get("owner_name") for e in cyc}
        same = len(names) <= 1
        locks = []
        for e in cyc:
            if e.get("lock_name") and e["lock_name"] not in locks:
                locks.append(e["lock_name"])
        tids = []
        for e in cyc:
            for k in ("waiter_tid", "owner_tid"):
                if e.get(k) is not None and e[k] not in tids:
                    tids.append(e[k])
        lines.append(ctx.t("w_dl_cycle", n=len(tids), m=len(locks)))
        for e in cyc:
            w = _thread_label(ctx, e.get("waiter_tid"), rows, e.get("waiter_name"), same)
            o = _thread_label(ctx, e.get("owner_tid"), rows, e.get("owner_name"), same)
            lines.append(ctx.t("w_dl_edge", waiter=w, lock=_c(e.get("lock_name") or e.get("lock_address")), owner=o))
            diagram.append(f"{w.replace('`', '')} {T['d_waits'][ctx.i]} {e.get('lock_name') or e.get('lock_address')} "
                           f"{T['d_held'][ctx.i]} {o.replace('`', '')}")
        for tid in tids:
            r = rows.get(tid) or {}
            fn, loc = r.get("top_function") or r.get("function"), r.get("top_source_location")
            lab = _thread_label(ctx, tid, rows, (r.get("name") if not same else None), same)
            if loc and r.get("top_source_line_exact"):
                call, inl = _at_parts(ctx, r, fn)
                lines.append(ctx.t("w_dl_at", thr=lab, loc=_c(loc), call=call, inl=inl))
                info["where"].append((lab, fn, loc, tid))
                info["where_exact"].append(tid)
            elif loc:
                lines.append(ctx.t("w_dl_where" if fn else "w_dl_where_nofn", thr=lab, fn=_c(fn) if fn else "", loc=_c(loc)))
                info["where"].append((lab, fn, loc, tid))
        if len(info["where_exact"]) < len(info["where"]):
            lines.append(ctx.t("w_lines_note"))
        if same and names and next(iter(names)):
            lines.append(ctx.t("w_dl_samename", name=_c(next(iter(names)))))
        info.update(locks=locks, threads=tids)
        info["n_obs"] = obs.get("observation_count")
        info["persistent"] = obs.get("cycle_persistent")
    else:
        lines.append(ctx.t("w_dl_nocycle"))
        locks = kinds.get("lock", [])
        info["locks"] = locks
        info["funcs"] = _user_funcs(kinds.get("function", []))
    if not cyc:
        for key, kk, fmt in (("lock", "w_locks", _c), ("thread_name", "w_threads", _c), ("thread", "w_tids", str),
                             ("function", "w_funcs", _c), ("source_location", "w_locs", _c)):
            vals = kinds.get(key, [])
            if key == "function":
                vals = _user_funcs(vals)
            if vals:
                lines.append("- " + ctx.t(kk, x=_join([fmt(v) for v in vals])))
    ts = _thread_sampling(report, f)
    info["samples"], info["window"] = ts
    return {"lines": lines, "diagram": diagram, "info": info}


def _thread_sampling(report: Optional[Dict[str, Any]], f: Dict[str, Any]) -> Tuple[Any, Any]:
    for o in _observations(report, f.get("recipe_ids")):
        ts = o.get("thread_sampling")
        if isinstance(ts, dict) and ts.get("samples_collected"):
            return ts.get("samples_collected"), ts.get("window_sec")
    return None, None


def _render_leak(ctx: _Ctx, f: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    ctx.term("leak"); ctx.term("heap"); ctx.term("path")
    g = _growth(f, report)
    lines: List[str] = []
    if g is None:
        lines.append(ctx.t("w_noname"))
        return {"lines": lines, "g": None}
    if g["blocks"] is not None:
        lines.append(ctx.t("w_leak", path=_c(g["path"]), blocks=g["blocks"], size=g["kb"], win=g["win"], rate=g["rate"]))
    else:
        lines.append(ctx.t("w_leak_nonum", path=_c(g["path"])))
    if g.get("still_ref") and g.get("var"):
        lines.append(ctx.t("w_leak_ref", var=_c(g["var"])))
    if g.get("thr"):
        lines.append(ctx.t("w_leak_thread", thr=_c(g["thr"]) + (f" (tid {g['tid']})" if g.get("tid") else "")))
    lines.extend(container_lines(ctx, g.get("container")))
    return {"lines": lines, "g": g}


def container_lines(ctx: "_Ctx", c: Any) -> List[str]:
    """The decoded C++ container under a growing owner (leak_attribution growth row ``container``): its size (and
    capacity) and the change across the walks; a container that could not be decoded says so and why."""
    if not isinstance(c, dict) or not c.get("type"):
        return []
    var, typ = _c(c.get("path") or "?"), _c(c["type"])
    if not c.get("decoded"):
        return [ctx.t("w_cont_fail", var=var, type=typ, why=_c(c.get("reason") or "-"))]
    out: List[str] = []
    if c.get("kind") in ("std::shared_ptr", "std::weak_ptr") and c.get("use_count") is not None:
        out.append(ctx.t("w_cont_ptr", var=var, type=typ, addr=_c((c.get("pointee") or {}).get("address") or "null"),
                         use=c.get("use_count"), weak=c.get("weak_count")))
    elif c.get("size_last") is not None:
        cap = ctx.t("w_cont_cap", n=_num(c["capacity"])) if c.get("capacity") is not None else (
            ctx.t("w_cont_buckets", n=_num(c["buckets"])) if c.get("buckets") is not None else "")
        decoded = [x for x in (c.get("size_series") or []) if x is not None]
        grow = ctx.t("w_cont_grow", first=_num(c["size_first"]), last=_num(c["size_last"]), n=len(decoded)) \
            if len(decoded) >= 2 and c.get("size_first") != c.get("size_last") else ""
        unit = ctx.t("w_cont_unit_ch" if c.get("kind") == "std::string" else "w_cont_unit_el")
        out.append(ctx.t("w_cont", var=var, type=typ, size=_num(c["size_last"]), unit=unit, cap=cap, grow=grow))
    if c.get("walks") and c.get("walks_decoded") is not None and c["walks_decoded"] < c["walks"]:
        out.append(ctx.t("w_cont_partial", k=c["walks_decoded"], n=c["walks"],
                         why=_c(str(c.get("partial_reason") or "-").split(": ", 1)[-1])))
    return out


def _render_thread(ctx: _Ctx, f: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    kinds = _by_kind(f)
    rows = _thread_rows(report, f.get("recipe_ids"))
    lines: List[str] = []
    spins: List[Dict[str, Any]] = []
    for o in _observations(report, f.get("recipe_ids")):
        for r in (o.get("runaway_threads") or []):
            if isinstance(r, dict):
                spins.append(r)
    if spins:
        ctx.term("spin"); ctx.term("runnable")
    inexact = False
    for r in spins:
        fn = r.get("top_function") or r.get("function")
        loc = r.get("top_source_location")
        if fn and loc and r.get("runnable_fraction") is not None:
            frac = round(float(r["runnable_fraction"]) * 100)
            cpu = r.get("cpu_share_pct") if r.get("cpu_share_pct") is not None else round(float(r.get("cpu_share") or 0) * 100, 1)
            disp = r.get("cpu_dispatches") if r.get("judgement_basis") == "schedstat_runnable_fraction_dispatches" else None
            k = "w_spin_disp" if isinstance(disp, int) else "w_spin"
            if r.get("top_source_line_exact"):
                call, inl = _at_parts(ctx, r, fn)
                lines.append(ctx.t(k + "_at", thr=_c(r.get("name")), tid=r.get("tid"), frac=frac, cpu=cpu, n=disp,
                                   fn=_c(fn), loc=_c(loc), call=call, inl=inl))
            else:
                lines.append(ctx.t(k, thr=_c(r.get("name")), tid=r.get("tid"), frac=frac, cpu=cpu, n=disp,
                                   fn=_c(fn), loc=_c(loc)))
                inexact = True
    if lines and inexact:
        lines.append(ctx.t("w_lines_note"))
    if not lines:
        for key, kk, fmt in (("thread_name", "w_threads", _c), ("thread", "w_tids", str),
                             ("function", "w_funcs", _c), ("source_location", "w_locs", _c)):
            vals = _user_funcs(kinds.get(key, [])) if key == "function" else kinds.get(key, [])
            if vals:
                lines.append("- " + ctx.t(kk, x=_join([fmt(v) for v in vals])))
    return {"lines": lines, "spins": spins, "rows": rows, "kinds": kinds}


def _cat_word(ctx: _Ctx, cat: str) -> Optional[str]:
    """The plain name of a finding category in the report language, or None when it has none."""
    from .report_registry import category_label
    reg = category_label(cat)
    if reg:
        return reg[ctx.i]
    if cat in CATEGORY_LABEL:
        return CATEGORY_LABEL[cat][ctx.i]
    return None


def _cat_label(ctx: _Ctx, cat: str) -> str:
    """The category name in words with its identifier in code font after it (the identifier alone when unnamed)."""
    word = _cat_word(ctx, cat)
    return f"{word} ({_c(cat)})" if word else _c(cat)


def _status_word(ctx: _Ctx, st: str, severity: Any = None) -> str:
    if str(severity or "").upper() == "INFO" and st in ("CONFIRMED_ROOT_CAUSE", "PROBABLE_CAUSE"):
        return ctx.t("k_fstatus_i")  # an INFO finding is a degradation, not a fault: no "cause" wording
    if st == "CONFIRMED_ROOT_CAUSE":
        return ctx.t("k_fstatus_c")
    if st == "PROBABLE_CAUSE":
        return ctx.t("k_fstatus_p")
    return str(st)


def _call_text(text: Any) -> str:
    """The call expression of a source line (cheap: only a single-statement line holding a call)."""
    t = re.sub(r"//.*$", "", str(text or "")).strip().rstrip(";{ ").strip()
    t = re.sub(r"^return\s+", "", t)
    return t if "(" in t and len(t) <= 80 and not t.startswith(("if", "for", "while", "switch")) else ""


def _at_parts(ctx: "_Ctx", r: Dict[str, Any], fn: Any) -> Tuple[str, str]:
    call = _call_text(r.get("top_source_text"))
    inl = r.get("top_inlined_function")
    return (ctx.t("w_at_call", x=_c(call)) if call else "",
            ctx.t("w_at_inl", f=_c(inl), g=_c(r.get("top_inlined_into") or fn)) if inl else "")


def _loc_text(info: Dict[str, Any], tid: Any) -> Optional[str]:
    for lab, fn, loc, t in info.get("where", []):
        if t == tid:
            return loc
    return None


def _finding_next(ctx: _Ctx, f: Dict[str, Any], rendered: Dict[str, Any]) -> List[str]:
    cat = f.get("category")
    out: List[str] = []
    if cat == "DEADLOCK_INDICATORS":
        info = rendered["info"]
        locks, threads = info.get("locks", []), info.get("threads", [])
        where = info.get("where", [])
        if len(locks) == 2 and len(threads) == 2 and len(where) == 2:
            a, b = locks
            out.append(ctx.t("n_dl2x" if len(info.get("where_exact", [])) == 2 else "n_dl2", a=_c(a), b=_c(b), t1=where[0][0], l1=_c(where[0][2]),
                             t2=where[1][0], l2=_c(where[1][2])))
        elif len(locks) >= 2 and where:
            out.append(ctx.t("n_dln", locks=_join([_c(x) for x in locks]), thrs=_join([w[0] for w in where])))
            out.append(ctx.t("n_dl_nolocs", where=_join([f"{w[0]} {_c(w[2])}" for w in where])))
        elif locks or info.get("funcs"):
            out.append(ctx.t("n_dl_names", locks=_join([_c(x) for x in locks]) or "-",
                             funcs=_join([_c(x) for x in info.get("funcs", [])]) or "-"))
        else:
            out.append(ctx.t("n_generic_none"))
        out.append(ctx.t("n_dl_stop"))
    elif cat == "MEMORY_LEAK":
        g = rendered.get("g")
        if g:
            out.append(ctx.t("n_leak", var=_c(g.get("var") or g["path"])))
            if g.get("thr"):
                out.append(ctx.t("n_leak_thr", thr=_c(g["thr"])))
            out.append(ctx.t("n_leak_two"))
        else:
            out.append(ctx.t("n_generic_none"))
    elif cat == "PROCESS_INSTABILITY" and rendered.get("spins"):
        for r in rendered["spins"]:
            fn, loc = r.get("top_function") or r.get("function"), r.get("top_source_location")
            if fn and loc:
                out.append(ctx.t("n_spin_at" if r.get("top_source_line_exact") else "n_spin",
                                 fn=_c(fn), loc=_c(loc), thr=_c(r.get("name"))))
        if not out:
            out.append(ctx.t("n_generic_none"))
    else:
        kinds = rendered.get("kinds") or _by_kind(f)
        names = [_c(n) for k in ("variable", "function", "source_location", "lock", "thread_name")
                 for n in (_user_funcs(kinds.get(k, [])) if k == "function" else kinds.get(k, []))]
        out.append(ctx.t("n_generic_names", names=_join(names)) if names else ctx.t("n_generic_none"))
    return out


# ------------------------------------------------------------------------------------------ sections
def _incon_reason(ctx: _Ctx, res: Dict[str, Any]) -> str:
    nc = res.get("not_covered") or []
    pid = (res.get("target") or {}).get("pid")
    prio = ("target_unreachable", "invalid_target", "target_unreadable", "missing_debug_image", "stage_failed",
            "unexpected_error", "not_executed")
    for kind in prio:
        for n in nc:
            if n.get("kind") != kind:
                continue
            raw = str(n.get("reason") or "")
            if kind in ("target_unreachable", "invalid_target"):
                return ctx.t("r_unreach", raw=_c(ko_text(raw, ctx.i)))
            if kind == "target_unreadable":
                if "does not exist" in raw or "invalid PID" in raw:
                    return ctx.t("r_nopid", pid=pid)
                return ctx.t("r_unread", raw=_c(ko_text(raw, ctx.i)))
            if kind == "missing_debug_image":
                if (res.get("target") or {}).get("transport") == "ssh":
                    return ctx.t("r_noimg_remote")
                return ctx.t("r_noimg", item=_c(n.get("item")))
            if kind in ("stage_failed", "unexpected_error"):
                return ctx.t("r_stage", item=_c(n.get("item")), raw=_c(ko_text(raw, ctx.i)))
            return ctx.t("r_noexec", raw=_c(ko_text(raw, ctx.i)))
    checks = res.get("checks_run") or []
    if checks:
        dec = sum(1 for c in checks if c.get("status") in ("PASS", "FAIL"))
        return ctx.t("r_nofinding", ran=len(checks), dec=dec, nc=len(nc)) + _baseline_open_reason(ctx, res)
    return ctx.t("r_unspecified")


def _baseline_open_reason(ctx: _Ctx, res: Dict[str, Any]) -> str:
    """Why an INCONCLUSIVE result without findings is not HEALTHY: the first baseline check that could not decide
    and its first limitation (healthy_scope.blocking; docs/HEALTHY_VERDICT.md)."""
    from .healthy_verdict import BASELINE_SCOPE_LABELS
    scope = res.get("healthy_scope") if isinstance(res.get("healthy_scope"), dict) else {}
    for b in scope.get("blocking") or []:
        if not str(b.get("kind") or "").startswith("baseline_check_"):
            continue
        rid = str(b.get("item") or "")
        raw = str(b.get("reason") or "")
        raw = raw.split(": ", 1)[1] if raw.startswith("baseline check ended") and ": " in raw else raw
        raw = raw.split("; ", 1)[0]
        if not raw:
            continue
        what = (BASELINE_SCOPE_LABELS.get(rid) or (rid, rid))[ctx.i]
        return ctx.t("r_baseline_open", what=what, rid=_c(rid), raw=_c(raw))
    return ""


def _healthy_sentence(ctx: _Ctx, who: str, res: Dict[str, Any]) -> str:
    """The HEALTHY conclusion: the claim, its scope, and (in the same sentence) what was not checked, named briefly.
    The full wording of every not-checked item is in the scope section."""
    scope = res.get("healthy_scope") if isinstance(res.get("healthy_scope"), dict) else {}
    if not scope.get("healthy"):
        return ctx.t("c_healthy_noscope2", who=who, sec=ctx.t("s_not_examined"))
    from .healthy_verdict import display_label
    shown: List[str] = []
    for x in scope.get("not_checked") or []:
        kind = x.get("kind")
        items = [s for s in str(x.get("item") or "").split(",") if s]
        if kind == "symptom_checks_without_result":
            shown.append(ctx.t("nc_short_symptom", n=len(items) or 1))
        elif kind == "outside_baseline":
            shown.append(ctx.t("nc_short_outside"))
        elif kind == "unsupported_in_mode":
            shown.append(ctx.t("nc_short_in_mode", n=len(items) or 1))
        else:
            shown.append(display_label(x, bool(ctx.i)))
    return ctx.t("c_healthy_short", who=who, n=len(scope.get("checked") or []), nc="; ".join(shown) or "-")


def _conclusion(ctx: _Ctx, res: Dict[str, Any], renders: List[Dict[str, Any]]) -> str:
    who = _who(ctx, res.get("target") or {})
    v = res.get("verdict")
    if v == "INCONCLUSIVE":
        return ctx.t("c_inconclusive", who=who, why=_incon_reason(ctx, res))
    if v == "ABORTED":
        return ctx.t("c_aborted", who=who, why=_incon_reason(ctx, res))
    findings = res.get("findings") or []
    if v == "HEALTHY" or not findings:
        if v in ("HEALTHY",):
            return _healthy_sentence(ctx, who, res)
        # fault-like verdict without a named finding: do not claim health
        return ctx.t("c_inconclusive", who=who, why=_incon_reason(ctx, res))
    f, r = findings[0], renders[0]
    what = _one_line(ctx, f, r)
    key = {"CONFIRMED_FAULT": "c_fault_conf", "DEGRADED": "c_degraded"}.get(v, "c_fault_prob")
    s = ctx.t(key, who=who, what=what)
    if len(findings) > 1:
        s += ctx.t("c_more2", n=len(findings) - 1, sec=ctx.t("s_findings"))
    return s


def _verdict_line(ctx: _Ctx, v: str) -> str:
    """The verdict in words, its identifier, and one sentence on what it means."""
    v = v if f"v_{v}" in T else "INCONCLUSIVE"
    return ctx.t("v_line", word=ctx.t(f"v_{v}"), code=_c(v), meaning=ctx.t(f"vm_{v}"))


def _one_line(ctx: _Ctx, f: Dict[str, Any], r: Dict[str, Any]) -> str:
    cat = f.get("category")
    en = ctx.i == 0
    if cat == "DEADLOCK_INDICATORS":
        info = r["info"]
        cyc = info.get("cycle") or []
        if cyc:
            parts = []
            names = {e.get("waiter_name") for e in cyc}
            rows = _thread_rows_from(r)
            for e in cyc:
                lab = _thread_label(ctx, e.get("waiter_tid"), rows, e.get("waiter_name"), len(names) <= 1)
                parts.append((lab, _c(e.get("lock_name"))))
            if en:
                return "deadlock: " + "; ".join(f"{a} waits for lock {b}" for a, b in parts)
            return "교착 상태: " + "; ".join(f"{a}이(가) 락 {b}을(를) 기다림" for a, b in parts)
        locks = info.get("locks") or []
        if locks:
            return ("deadlock involving lock(s) " if en else "락 ") + _join([_c(x) for x in locks]) + ("" if en else "이(가) 얽힌 교착 상태")
        return "deadlock" if en else "교착 상태"
    if cat == "MEMORY_LEAK":
        g = r.get("g")
        if g and g.get("blocks") is not None:
            return (f"memory under {_c(g['path'])} grows without bound (+{g['blocks']} blocks / +{g['kb']} KB in {g['win']} s)"
                    if en else f"{_c(g['path'])} 아래 메모리가 계속 늘고 있음 ({g['win']}초 동안 블록 +{g['blocks']}개 / +{g['kb']} KB)")
        if g:
            return (f"memory growth attributed to {_c(g['path'])}" if en else f"메모리 증가가 {_c(g['path'])}에 귀속됨")
    if cat == "PROCESS_INSTABILITY" and r.get("spins"):
        s = r["spins"][0]
        fn, loc = s.get("top_function") or s.get("function"), s.get("top_source_location")
        if fn:
            return (f"thread {_c(s.get('name'))} spins in {_c(fn)}" + (f" at {_c(loc)}" if loc else "") if en
                    else f"스레드 {_c(s.get('name'))}이(가) " + (f"{_c(loc)}의 " if loc else "") + f"{_c(fn)}에서 공회전 중")
    kinds = _by_kind(f)
    names = [_c(n) for k in ("variable", "function", "thread_name", "lock") for n in kinds.get(k, [])][:4]
    lab = _cat_word(ctx, str(cat)) or _c(cat)
    if names:
        return f"{lab} ({_join(names)})"
    return lab + (" (no names attached)" if en else " (이름이 붙지 않음)")


def _thread_rows_from(r: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    return r.get("rows") or {}


# ------------------------------------------------------------------------------------------ check table
# One definition of "checks" for every view (summary, Markdown, HTML hero, HTML check list): a row per recipe the
# diagnosis considered.  ``group`` is FAIL (found a problem), PASS (clean), INCONCLUSIVE (ran but could not judge:
# inconclusive, error, not applicable, unsupported, ...) or SKIPPED (not run).  run = FAIL + PASS + INCONCLUSIVE.
CHECK_GROUPS = ("FAIL", "INCONCLUSIVE", "PASS", "SKIPPED")
_NOT_RUN = ("", "SKIPPED", "NOT_EXECUTED", "NOT_RUN", "NOT_PLANNED")


def check_group(status: Any) -> str:
    s = str(status or "").upper()
    if s in ("PASS", "FAIL"):
        return s
    return "SKIPPED" if s in _NOT_RUN else "INCONCLUSIVE"


def check_rows(res: Dict[str, Any], report: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Every check the diagnosis considered, one row per recipe id, in the order of the detailed report."""
    rows: List[Dict[str, Any]] = []
    seen = set()
    run = [c for c in (res.get("checks_run") or []) if isinstance(c, dict)]
    # the result's own check statuses are what the verdict was computed from; the report adds the detail
    run_status = {str(c.get("recipe_id")): c.get("status") for c in run if c.get("recipe_id")}
    detailed = _checks(report)
    have = {str(c.get("recipe_id")) for c in detailed}
    for c in detailed + [c for c in run if str(c.get("recipe_id")) not in have]:
        rid = str(c.get("recipe_id") or c.get("check_id") or "")
        if not rid or rid in seen:
            continue
        seen.add(rid)
        obs = c.get("actual_observations") if isinstance(c.get("actual_observations"), dict) else {}
        raw = str(run_status.get(rid, c.get("status")) or "").upper()
        rows.append({"rid": rid, "status": check_group(raw), "raw_status": raw, "name": c.get("name"),
                     "domain": c.get("technical_rationale"), "interp": c.get("technical_interpretation"),
                     "limits": [str(x) for x in (c.get("limitations") or [])] + [str(x) for x in (c.get("missing_evidence") or [])],
                     "dur": c.get("duration_seconds", c.get("duration_s")), "check_id": c.get("check_id"),
                     "required": c.get("is_required"), "n_ev": len(c.get("supporting_evidence_ids") or []),
                     "cap": obs.get("missing_capability"), "err": c.get("error_details"), "planned": True})
    for n in res.get("not_covered") or []:
        kind = str(n.get("kind") or "") if isinstance(n, dict) else ""
        rid = str(n.get("item") or "") if kind.startswith("check_") else ""
        if rid and rid not in seen:     # a check reported only as "ran but ended <status>"
            seen.add(rid)
            raw = kind[6:].upper()
            rows.append({"rid": rid, "status": check_group(raw), "raw_status": raw, "planned": True, "limits": []})
    for n in res.get("not_covered") or []:
        if isinstance(n, dict) and n.get("kind") == "unsupported_in_mode":
            for rid in str(n.get("item") or "").split(","):
                rid = rid.strip()
                if rid and rid not in seen:
                    seen.add(rid)
                    rows.append({"rid": rid, "status": "SKIPPED", "raw_status": "NOT_IN_MODE", "planned": False,
                                 "mode_cap": str(n.get("capability") or ""), "limits": []})
    for n in res.get("not_covered") or []:
        if isinstance(n, dict) and n.get("kind") == "recipes_not_planned":
            for rid in str(n.get("item") or "").split(","):
                rid = rid.strip()
                if rid and rid not in seen:
                    seen.add(rid)
                    rows.append({"rid": rid, "status": "SKIPPED", "raw_status": "NOT_PLANNED", "planned": False,
                                 "limits": []})
    return rows


def check_counts(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    """run / found / clean / undecided / not_run: the counts every view shows."""
    n = {g: sum(1 for r in rows if r["status"] == g) for g in CHECK_GROUPS}
    return {"run": n["FAIL"] + n["PASS"] + n["INCONCLUSIVE"], "found": n["FAIL"], "clean": n["PASS"],
            "undecided": n["INCONCLUSIVE"], "not_run": n["SKIPPED"]}


def recipe_meta(rid: str) -> Optional[Tuple[str, str, str, str, str]]:
    """(domain, name en, name ko, looks-for en, looks-for ko) of a check, from its registration or the built-in table."""
    from .report_visuals import _recipe_meta
    return _recipe_meta(rid)


def check_name(rid: str, i: int, fallback: Any = None) -> str:
    meta = recipe_meta(rid)
    if meta:
        return meta[1 + i]
    return str(fallback or rid)


def check_label(rid: str, i: int, fallback: Any = None) -> str:
    """A check named in words with its id in code font after it: ``힙 메타데이터 무결성 (`RECIPE_...`)``."""
    name = check_name(rid, i, None)
    return f"{name} ({_c(rid)})" if name != str(rid) else _c(rid)


def _undecided_reason(ctx: _Ctx, r: Dict[str, Any], reasons: Dict[str, List[str]]) -> str:
    if r.get("raw_status") == "NOT_IN_MODE":
        from .diagnostic_recipes import CAPABILITY_DESCRIPTIONS
        cap = CAPABILITY_DESCRIPTIONS.get(r.get("mode_cap") or "", (r.get("mode_cap") or "?",) * 2)[ctx.i]
        return ctx.t("g_not_in_mode", cap=cap)
    if not r.get("planned", True):
        return ctx.t("g_not_planned")
    if r["status"] == "SKIPPED":
        interp = str(r.get("interp") or "")
        if interp and interp != "Check executed":
            return ko_text(interp, ctx.i).rstrip(".")
        return ctx.t("g_not_executed")
    if r.get("cap"):
        return ctx.t("g_why_cap", cap=_c(r["cap"]))
    texts = [ko_text(x, ctx.i) for x in reasons.get(r["rid"], []) + r.get("limits", [])]
    if r.get("err"):
        texts.append(ko_text(str(r["err"]), ctx.i))
    if texts:
        return "; ".join(dict.fromkeys(texts))
    raw = r.get("raw_status") or ""
    if raw and raw != "INCONCLUSIVE" and f"st_{raw}" in T:
        return ctx.t("g_why_status", st=ctx.t(f"st_{raw}"))
    return ctx.t("g_why_none")


def _by_domain(ctx: _Ctx, rows: List[Dict[str, Any]]) -> List[str]:
    """Compact grouped list: one line per domain, checks named in words with the id after each."""
    from .report_visuals import _DOMAIN_ORDER, _L
    groups: Dict[str, List[str]] = {}
    for r in rows:
        dom = (recipe_meta(r["rid"]) or ("OTHER",))[0]
        groups.setdefault(dom if dom in _DOMAIN_ORDER else "OTHER", []).append(check_label(r["rid"], ctx.i, r.get("name")))
    return [f"- {_L['dom_' + d][ctx.i]}: {_join(groups[d])}" for d in _DOMAIN_ORDER if d in groups]


# ------------------------------------------------------------------------------------------ sections
def _finding_blocks(ctx: _Ctx, res: Dict[str, Any], renders: List[Dict[str, Any]], report: Optional[Dict[str, Any]],
                    rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per finding: heading, the facts line (certainty, severity, which check found it), the registered or generic
    text (unchanged), the wait-for diagram, and the category-specific observation and inference lines."""
    status_of = {r["rid"]: r["status"] for r in rows}
    out = []
    for i, (f, r) in enumerate(zip(res.get("findings") or [], renders), 1):
        sev = str(f.get("severity") or "").upper()
        sev_w = ctx.t(f"sev_{sev}") if f"sev_{sev}" in T else (_c(sev) if sev else "-")
        facts = [ctx.t("f_certainty", status=_status_word(ctx, str(f.get("status")), f.get("severity")), sev=sev_w)]
        rids = [str(x) for x in (f.get("recipe_ids") or [])]
        found = [x for x in rids if status_of.get(x) == "FAIL"]
        ev = len(f.get("evidence_ids") or [])
        if found or rids:
            line = ctx.t("f_found_by" if found else "f_related",
                         checks=_join([check_label(x, ctx.i) for x in (found or rids)]))
            facts.append(line + (ctx.t("f_records", n=ev) if ev else ""))
        body: List[str] = []
        if not (f.get("subjects") or f.get("subject_details")):
            body.append(ctx.t("w_noname"))
        if (f.get("subjects") or f.get("subject_details")) or r.get("registered"):
            body.extend(r["lines"])
        for chain in relation_lines(ctx, f)[:3]:
            facts.append(ctx.t("f_rel", chain=chain))
        cands = location_candidate_lines(ctx, f)
        if cands:
            facts.append(ctx.t("f_cands", locs=_join([f"`{c['location']}`" for c in
                                                      (f.get("location_candidates") or {}).get("candidates")])))
        diagram = []
        if r.get("diagram"):
            diagram = [f"**{ctx.t('h2_wait')}**", "```", ctx.t("d_hdr")] + list(r["diagram"]) + ["```"]
        out.append({"i": i, "heading": ctx.t("f_head", i=i, label=_cat_label(ctx, str(f.get("category")))),
                    "facts": facts, "body": body, "diagram": diagram, "why": _finding_why(ctx, f, r),
                    "cands": cands})
    return out


def relation_lines(ctx: _Ctx, f: Dict[str, Any]) -> List[str]:
    """``findings[].object_relations`` as one chain line each: memory object <- (how) variable <- (how) thread; a link
    that is not established says so and why (extractor.object_relations)."""
    rel = f.get("object_relations") if isinstance(f.get("object_relations"), dict) else {}
    out = []
    for ch in rel.get("chains") or []:
        nodes = {n.get("role"): n for n in ch.get("nodes") or [] if isinstance(n, dict)}
        links = {x.get("target"): x for x in ch.get("links") or [] if isinstance(x, dict)}
        m, v, th = nodes.get("memory_object") or {}, nodes.get("variable") or {}, nodes.get("thread") or {}
        if not m:
            continue
        parts = [_rel_memory(ctx, m)]
        for node, label in ((v, _rel_var(ctx, v)), (th, _rel_thread(ctx, th))):
            ln = links.get(node.get("id")) or {}
            if ln.get("established") and node.get("established", True):
                key = "rel_how_" + str(ln.get("how"))
                parts.append(ctx.t("rel_arrow", how=ctx.t(key) if key in T else _c(ln.get("how"))) + label)
            else:
                rk = "rel_ne_" + str(ln.get("reason"))
                parts.append(ctx.t("rel_arrow", how=ctx.t("rel_ne", why=ctx.t(rk if rk in T else "rel_ne_other")))
                             + label)
        out.append("".join(parts))
    return out


def _rel_memory(ctx: _Ctx, m: Dict[str, Any]) -> str:
    a = m.get("attrs") or {}
    kind = m.get("kind")
    kb = ctx.t("rel_kb", kb=round(float(a["bytes_delta"]) / 1024.0)) if a.get("bytes_delta") else ""
    if kind == "heap_blocks":
        if a.get("chunk_size"):
            return ctx.t("rel_m_heap_blocks_class", c=a["chunk_size"], n=a.get("blocks_delta") or "?", kb=kb)
        return ctx.t("rel_m_heap_blocks", n=a.get("blocks_delta") or "?", kb=kb)
    if kind == "heap_block":
        return ctx.t("rel_m_heap_block_free" if str(a.get("state") or "").startswith("free") else "rel_m_heap_block",
                     x=_c(m.get("name") or "?"))
    if kind == "mapping":
        return ctx.t("rel_m_mapping", x=_c(m.get("name")) if m.get("name") else "",
                     kb=ctx.t("rel_kb", kb=a["added_kb"]) if a.get("added_kb") else "").replace("  ", " ")
    if kind in ("lock", "global_storage"):
        return ctx.t("rel_m_" + kind, x=_c(m.get("name") or "?"))
    return ctx.t("rel_m_none" if kind == "none" else "rel_m_unknown")


def _rel_var(ctx: _Ctx, v: Dict[str, Any]) -> str:
    if not v.get("established", True) or not v.get("name"):
        return ctx.t("rel_var_ne")
    c = (v.get("attrs") or {}).get("container")
    if isinstance(c, dict) and c.get("type") and c.get("size_last") is not None:
        return ctx.t("rel_var_cont", x=_c(v["name"]), t=_c(c["type"]), n=_num(c["size_last"]))
    return ctx.t("rel_var", x=_c(v["name"]))


def _rel_thread(ctx: _Ctx, t: Dict[str, Any]) -> str:
    if not t.get("established", True):
        return ctx.t("rel_thr_ne")
    tid = (t.get("attrs") or {}).get("tid")
    if t.get("name"):
        return ctx.t("rel_thr", x=_c(t["name"]) + (f" (tid {tid})" if tid is not None else ""))
    return ctx.t("rel_thr", x=f"tid {tid}" if tid is not None else "?")


def location_candidate_lines(ctx: _Ctx, f: Dict[str, Any]) -> List[str]:
    """The finding's static location candidates as numbered list items (Markdown, report language); [] when the
    finding has none.  They are candidates, never the confirmed location: the heading and note say so."""
    lc = f.get("location_candidates") if isinstance(f.get("location_candidates"), dict) else {}
    out = []
    for c in lc.get("candidates") or []:
        if not isinstance(c, dict) or not c.get("location"):
            continue
        why = c.get("reason_ko") if ctx.i == 1 and c.get("reason_ko") else c.get("reason")
        stmt = str(c.get("statement") or "").replace("`", "'")
        out.append(ctx.t("f_cand_item", loc=c["location"], fn=c.get("function") or "?", stmt=stmt, why=why or "-"))
    return out


def _finding_why(ctx: _Ctx, f: Dict[str, Any], r: Dict[str, Any]) -> List[str]:
    """What was observed and what was inferred from it, for the categories the frame knows (else nothing: a
    registered text already says it)."""
    cat = f.get("category")
    out: List[str] = []
    if cat == "DEADLOCK_INDICATORS" and r.get("info"):
        info = r["info"]
        if info.get("samples") and info.get("window"):
            out.append(ctx.t("y_dl_obs", n=info["samples"], win=info["window"]))
        else:
            out.append(ctx.t("y_dl_obs_nonum"))
        if info.get("persistent") and info.get("n_obs"):
            out.append(ctx.t("y_dl_persist", n=info["n_obs"]))
        out.append(ctx.t("y_dl_infer"))
    elif cat == "MEMORY_LEAK" and r.get("g"):
        g = r["g"]
        if g.get("walks") and g.get("win"):
            out.append(ctx.t("y_leak_obs", n=g["walks"], win=g["win"]))
        else:
            out.append(ctx.t("y_leak_obs_nonum"))
        out.append(ctx.t("y_leak_infer", path=_c(g["path"])))
    elif cat == "PROCESS_INSTABILITY" and r.get("spins"):
        out.append(ctx.t("y_spin_infer"))
    return out


def _section2(ctx: _Ctx, blocks: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for b in blocks:
        out += [f"### {b['heading']}", ""] + [f"- {x}" for x in b["facts"]] + [""]
        if b["body"]:
            out += b["body"] + [""]
        if b["diagram"]:
            out += b["diagram"] + [""]
        if b["why"]:
            out += [ctx.t("f_why"), ""] + [f"{n}. {x}" for n, x in enumerate(b["why"], 1)] + [""]
        if b.get("cands"):
            out += [f"**{ctx.t('f_cands_head')}**", "", ctx.t("f_cands_note"), ""] + [
                f"{n}. {x}" for n, x in enumerate(b["cands"], 1)] + [""]
        if b.get("competing_lines"):
            out += b["competing_lines"] + [""]
    while out and out[-1] == "":
        out.pop()
    return out


def _pointer(ctx: _Ctx, what: str, anchor: str, keys: List[str]) -> str:
    return "- " + ctx.t("p_line", what=what, anchor=_c(anchor), keys=", ".join(_c(k) for k in keys))


def _where_lines(ctx: _Ctx, blocks: List[Dict[str, Any]], repro: bool = False) -> List[str]:
    """Per part of the report, where its detailed records are: the anchor of the collapsed block in the HTML report
    and the keys of the JSON result (the Markdown report carries no detail by default)."""
    out = [ctx.t("r_where_intro"), "",
           _pointer(ctx, ctx.t("p_verdict"), "#verdict-detail",
                    ["verdict", "healthy_scope", "report.section_a_executive_summary", "report.section_i_final_conclusions"])]
    for b in blocks:
        out.append(_pointer(ctx, ctx.t("p_finding", i=b["i"]), f"#finding-{b['i']}-detail",
                            [f"findings[{b['i'] - 1}]", "report.section_e_findings_and_root_cause"]))
    out += [_pointer(ctx, ctx.t("p_checks"), "#check-<RECIPE_ID>-detail",
                     ["checks_run", "report.section_d_detailed_inspection_results.checks[]"]),
            _pointer(ctx, ctx.t("p_scope"), "#scope-detail", ["not_covered", "report.section_h_limitations_and_unverified"]),
            _pointer(ctx, ctx.t("p_method"), "#method-detail",
                     ["target", "collection_impact", "report.section_b_target_context",
                      "report.section_c_diagnostic_strategy", "report.section_g_evidence_and_provenance"])]
    if repro:
        out.append(_pointer(ctx, ctx.t("p_repro"), "#reproducibility-detail",
                            ["reproducibility", "report.section_j_reproducibility"]))
    return out


def _not_examined_lines(ctx: _Ctx, res: Dict[str, Any]) -> List[str]:
    """not_covered items that are not about one check (those are in the check groups), in plain words."""
    nc = [n for n in (res.get("not_covered") or []) if isinstance(n, dict)
          and not str(n.get("kind")).startswith("check_")
          and n.get("kind") not in ("recipes_not_planned", "unsupported_in_mode")]
    out: List[str] = []
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for n in nc:
        groups.setdefault(str(n.get("kind")), []).append(n)
    for kind, items in groups.items():
        names = [check_label(str(n.get("item")), ctx.i) if str(n.get("item") or "").startswith("RECIPE_")
                 else _c(n.get("item")) for n in items]
        raws = [str(n.get("reason") or "") for n in items if n.get("reason")]
        if kind == "target_unreadable":
            gone = any("does not exist" in r or "invalid PID" in r for r in raws)
            line = ctx.t("nc_target_unreadable", items=ctx.t("nc_pid_gone") if gone else _join([_c(ko_text(r, ctx.i)) for r in raws]))
        elif kind == "missing_debug_image":
            line = ctx.t("nc_missing_debug_image_remote" if (res.get("target") or {}).get("transport") == "ssh"
                         else "nc_missing_debug_image", items=_join(names))
        elif kind in ("target_unreachable", "invalid_target"):
            line = ctx.t(f"nc_{kind}", items=_join([_c(ko_text(r, ctx.i)) for r in raws] or names))
        elif kind == "remote_limitation":
            line = ctx.t("nc_remote_limitation", items="; ".join(_c(ko_text(r, ctx.i)) for r in raws) or _join(names))
        elif kind == "unsupported_on_target":
            line = ctx.t("nc_unsupported_on_target", abi=_abi_text(res), items=_join(names))
        elif kind == "long_wait_not_judged":
            line = ctx.t("nc_long_wait_not_judged", items=_join(names))
        elif kind == "baseline_check_not_run":
            line = ctx.t("nc_baseline_check_not_run", items=_join(names))
        elif kind in ("unattributed_finding", "stage_failed", "unexpected_error"):
            line = ctx.t(f"nc_{kind}", items=_join(names))
        elif kind == "unsupported_in_mode":
            continue        # listed with its checks under "Not run", with the capability they need
        elif kind == "limitation":
            line = ctx.t("nc_limitation") + " " + "; ".join(_c(ko_text(r, ctx.i)) for r in raws)
        elif f"nc_{kind}" in T:
            line = ctx.t(f"nc_{kind}")
            if kind in ("budget_exhausted", "leak_owner_limited", "abi_detection_failed", "report_not_saved",
                        "not_executed") and raws:
                line += ctx.t("nc_orig", raw=_c(ko_text(raws[0], ctx.i)))
        else:
            line = ctx.t("nc_other", kind=_c(kind)) + " " + _join(names)
        out.append(f"- {line}")
    scope = res.get("healthy_scope") if isinstance(res.get("healthy_scope"), dict) else {}
    if res.get("verdict") == "HEALTHY" and scope.get("healthy"):
        # what the HEALTHY verdict does not cover and is not listed elsewhere (docs/HEALTHY_VERDICT.md)
        from .healthy_verdict import display_label
        for x in scope.get("not_checked") or []:
            if x.get("kind") not in ("long_wait_not_judged", "symptom_checks_without_result", "unsupported_in_mode") \
                    and x.get("kind") not in groups:
                out.append(f"- {display_label(x, bool(ctx.i))}")
    return out


def _scope_head(ctx: _Ctx, res: Dict[str, Any], rows: List[Dict[str, Any]]) -> List[str]:
    """The counts sentence (the one place the check totals are stated) and, for HEALTHY, what the verdict covers."""
    cnt = check_counts(rows)
    head = ctx.t("s_counts", **cnt) if cnt["run"] else ctx.t("s_counts_none")
    if cnt["not_run"]:
        head += ctx.t("s_notrun", n=cnt["not_run"])
    out = [head + " " + ctx.t("s_caveat")]
    scope = res.get("healthy_scope") if isinstance(res.get("healthy_scope"), dict) else {}
    if res.get("verdict") == "HEALTHY" and scope.get("healthy"):
        out.append(ctx.t("s_healthy", n=len(scope.get("checked") or [])))
    return out


def _section4(ctx: _Ctx, res: Dict[str, Any], rows: List[Dict[str, Any]]) -> List[str]:
    """What was checked: the counts once, then the checks grouped by outcome (named in words, id after), then what
    else was not examined.  'Not checked' is never presented as 'fine'."""
    out: List[str] = []
    for x in _scope_head(ctx, res, rows):
        out += [x, ""]
    out.pop()
    scope = res.get("healthy_scope") if isinstance(res.get("healthy_scope"), dict) else {}
    baseline = [str(x.get("recipe_id")) for x in scope.get("checked") or []]
    linked: Dict[str, int] = {}
    for i, f in enumerate(res.get("findings") or [], 1):
        for rid in f.get("recipe_ids") or []:
            linked.setdefault(str(rid), i)
    reasons: Dict[str, List[str]] = {}
    for n in res.get("not_covered") or []:
        if isinstance(n, dict) and str(n.get("kind")).startswith("check_") \
                and str(n.get("reason") or "") not in ("", "Check executed"):
            reasons.setdefault(str(n.get("item")), []).append(str(n["reason"]))
    for g in CHECK_GROUPS:
        grp = [r for r in rows if r["status"] == g]
        if not grp:
            continue
        out += ["", f"### {ctx.t('g_' + g)} ({len(grp)})", ""]
        if g == "FAIL":
            for r in grp:
                meta = recipe_meta(r["rid"])
                what = meta[3 + ctx.i] if meta else ""
                name = check_label(r["rid"], ctx.i, r.get("name"))
                if r["rid"] in linked:
                    out.append("- " + ctx.t("g_fail_row", name=name, what=what or "-", fi=linked[r["rid"]]))
                else:
                    out.append("- " + ctx.t("g_fail_row_nf", name=name, what=what or "-"))
        elif g in ("INCONCLUSIVE", "SKIPPED"):
            by_reason: Dict[str, List[str]] = {}
            for r in grp:
                by_reason.setdefault(_undecided_reason(ctx, r, reasons), []).append(check_label(r["rid"], ctx.i, r.get("name")))
            if g == "SKIPPED":
                first = True
                for why in by_reason:
                    sub = [r for r in grp if _undecided_reason(ctx, r, reasons) == why]
                    out += ([] if first else [""]) + [f"{why[:1].upper()}{why[1:]}:" if ctx.i == 0 else f"{why}:"]
                    out += _by_domain(ctx, sub)
                    first = False
            else:
                for why, names in by_reason.items():
                    out.append(f"- {_join(names)}: {why}")
        else:  # PASS
            if baseline and res.get("verdict") == "HEALTHY":
                base = [r for r in grp if r["rid"] in baseline]
                extra = [r for r in grp if r["rid"] not in baseline]
                out.append(f"{ctx.t('g_baseline', n=len(base))}:")
                out += _by_domain(ctx, base)
                if extra:
                    out += ["", f"{ctx.t('g_extra', n=len(extra))}:"] + _by_domain(ctx, extra)
            else:
                out += _by_domain(ctx, grp)
    return out


def _section_not_examined(ctx: _Ctx, res: Dict[str, Any], rows: List[Dict[str, Any]]) -> List[str]:
    """What could not be examined beyond the checks themselves; the undecided / not-run checks stay in the check
    section and are only pointed to here (said once)."""
    other = _not_examined_lines(ctx, res)
    if not other:
        return []
    cnt = check_counts(rows)
    out: List[str] = []
    if cnt["undecided"] or cnt["not_run"]:
        out += [ctx.t("ne_pointer", u=cnt["undecided"], n=cnt["not_run"], sec=ctx.t("s_scope")), ""]
    return out + other


def _section_target(ctx: _Ctx, res: Dict[str, Any], report: Optional[Dict[str, Any]],
                    repro: Optional[Dict[str, Any]]) -> List[str]:
    """The target card: what was diagnosed (identity stated once; the method section does not repeat it)."""
    t = res.get("target") or {}
    sec_b = (report or {}).get("section_b_target_context") or {}
    repro = repro or {}
    unk = ctx.t("t_unknown")
    sfx = ctx.t("t_redetected") if repro.get("target_source") == "export_time_detection" else ""
    out: List[str] = []
    name = t.get("process_name") or sec_b.get("target_process_name")
    out.append(f"- {ctx.t('t_proc')}: " + (f"{_c(name)} " if name else "") + f"(pid {t.get('pid') or sec_b.get('pid')})")
    abi = t.get("abi") if isinstance(t.get("abi"), dict) else {}
    arch = repro.get("target_arch") or (abi.get("architecture") if abi.get("status") == "DETECTED" else None)
    libc = repro.get("target_libc") or (abi.get("libc") if abi.get("status") == "DETECTED" else None)
    out.append(f"- {ctx.t('t_arch')}: {_c(arch or unk)}" + (f" · {_c(libc)}" if libc else "") + (sfx if arch else ""))
    out.append(f"- {ctx.t('t_kernel')}: {_c(repro.get('target_kernel') or unk)}" + (sfx if repro.get("target_kernel") else ""))
    exe = sec_b.get("binary_path")
    if exe:
        out.append(f"- {ctx.t('t_exe')}: {_c(exe)}")
    bid_rows = repro.get("build_id_checks") or []
    bid = (bid_rows[0] if len(bid_rows) == 1 else {}) or {}
    build = (sec_b.get("build_id") or bid.get("process_build_id") or (ctx.extra or {}).get("build_id"))
    status = str(bid.get("status") or "UNKNOWN")
    out.append(f"- {ctx.t('t_build')}: {_c(build or unk)} ({ctx.t('t_bid_' + (status if 't_bid_' + status in T else 'UNKNOWN'))})")
    img = t.get("debug_image") or sec_b.get("companion_elf")
    out.append(f"- {ctx.t('t_debug')}: " + (_c(img) if img else ctx.t("t_none")))
    if t.get("transport") == "ssh" or t.get("host") or t.get("remote_host"):
        out.append(f"- {ctx.t('t_transport')}: " + ctx.t("t_ssh", host=_c(t.get("host") or t.get("remote_host") or "?")))
    else:
        out.append(f"- {ctx.t('t_transport')}: " + ctx.t("t_local"))
    return out


def glance_parts(ctx: _Ctx, res: Dict[str, Any], rows: List[Dict[str, Any]]) -> List[Tuple[str, str, str]]:
    """The four figures of the tiles: (key, value, note) for checks, target stop time, data read, duration."""
    cnt = check_counts(rows)
    ci = res.get("collection_impact") if isinstance(res.get("collection_impact"), dict) else {}
    out: List[Tuple[str, str, str]] = []
    if rows:
        out.append(("checks", str(cnt["run"]), ""))
    if isinstance(ci.get("measured_stop_ms"), (int, float)):
        out.append(("stop", fmt_ms(ci["measured_stop_ms"], ctx.i),
                    "never" if float(ci["measured_stop_ms"]) == 0 and ci.get("zero_stop") else ""))
    if isinstance(ci.get("bytes_read"), (int, float)):
        out.append(("bytes", fmt_bytes(ci["bytes_read"]), ""))
    if isinstance(res.get("duration_s"), (int, float)):
        out.append(("duration", fmt_ms(float(res["duration_s"]) * 1000.0, ctx.i), ""))
    return out


def _glance_line(ctx: _Ctx, res: Dict[str, Any], rows: List[Dict[str, Any]]) -> List[str]:
    cnt = check_counts(rows)
    parts = []
    for key, val, note in glance_parts(ctx, res, rows):
        if key == "checks":
            parts.append(ctx.t("gl_checks", run=val) + (ctx.t("gl_notrun", n=cnt["not_run"]) if cnt["not_run"] else ""))
        elif key == "stop":
            parts.append(ctx.t("gl_stop", ms=val) + (ctx.t("gl_never") if note else ""))
        elif key == "bytes":
            parts.append(ctx.t("gl_bytes", b=val))
        else:
            parts.append(ctx.t("gl_dur", t=val))
    return [ctx.t("gl_line", x=" · ".join(parts))] if parts else []


def _abi_text(res: Dict[str, Any]) -> str:
    abi = (res.get("target") or {}).get("abi")
    if isinstance(abi, dict) and abi.get("architecture"):
        return f" ({abi['architecture']}/{abi.get('libc') or '?'})"
    return ""


def _section5(ctx: _Ctx, res: Dict[str, Any], renders: List[Dict[str, Any]]) -> List[str]:
    v = res.get("verdict")
    findings = res.get("findings") or []
    out: List[str] = []
    if v in ("INCONCLUSIVE", "ABORTED") or (not findings and v != "HEALTHY"):
        kinds = {n.get("kind") for n in (res.get("not_covered") or [])}
        out.append(ctx.t("n_incon_intro"))
        if "target_unreadable" in kinds:
            out.append("- " + ctx.t("n_incon_pid"))
        if "missing_debug_image" in kinds or v == "INCONCLUSIVE":
            out.append("- " + ctx.t("n_incon_img"))
        out.append("- " + ctx.t("n_incon_sym"))
        if "target_unreadable" not in kinds:
            out.append("- " + ctx.t("n_incon_stop"))
            if len(res.get("not_covered") or []) > 1:
                out.append("- " + ctx.t("n_incon_nc2", sec=ctx.t("s_not_examined")))
        return out
    if v == "HEALTHY" and not findings:
        return [ctx.t("n_healthy2", sec=ctx.t("s_not_examined"))]
    for i, (f, r) in enumerate(zip(findings, renders), 1):
        steps = list(r.get("next") or []) if r.get("registered") else []   # a registered text may give its own steps
        steps += [s for s in _finding_next(ctx, f, r) if s not in steps]
        if str(f.get("category")) in _ASAN_CATEGORIES and str(f.get("severity") or "").upper() != "INFO":
            steps.append(ctx.t("n_asan"))
        if len(findings) > 1:
            out += ["" if out else "", f"**{ctx.t('f_head', i=i, label=_cat_word(ctx, str(f.get('category'))) or _c(f.get('category')))}**"]
        out.extend(f"{n}. {s}" for n, s in enumerate(steps, 1))
    while out and out[0] == "":
        out.pop(0)
    return out


# memory-safety findings: the engine's one category-specific remediation worth keeping (its other checklist items
# are generic and stay in the JSON ``remediation_checklist``)
_ASAN_CATEGORIES = ("MEMORY_CORRUPTION", "USE_AFTER_FREE", "INVALID_DOUBLE_FREE", "STACK_CORRUPTION")


def fmt_ms(ms: Any, i: int) -> str:
    """A duration in sensible units: whole milliseconds below one second, seconds with one decimal above."""
    try:
        v = float(ms)
    except (TypeError, ValueError):
        return "-"
    if v < 1000:
        return f"{v:.0f} ms"
    return T["seconds"][i].format(x=f"{v / 1000.0:.1f}")


def fmt_bytes(n: Any) -> str:
    """A byte count in B / KB / MB (1 KB = 1024 bytes)."""
    try:
        v = float(n)
    except (TypeError, ValueError):
        return "-"
    if v < 1024:
        return f"{int(v)} B"
    if v < 1024 * 1024:
        return f"{v / 1024:.0f} KB"
    return f"{v / 1048576:.1f} MB"


def _section6(ctx: _Ctx, res: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> List[str]:
    """How the diagnosis was done and what it cost, beyond what the target card and the four figures say: the
    zero-stop statement, the observation, the CPU it used, ids and time of the report."""
    extra = extra or {}
    out: List[str] = []
    ci = res.get("collection_impact") or {}
    if not ci or ci.get("capture_mode") is None and ci.get("bytes_read") is None:
        out.append(ctx.t("m_none"))
    else:
        ctx.term("zerostop")
        out.append(ctx.t("m_mode" if ci.get("zero_stop") else "m_mode_stop", mode=_c(ci.get("capture_mode") or "-")))
        if ci.get("wall_clock_ms") is not None:
            out.append(ctx.t("m_time", obs=fmt_ms(ci.get("wall_clock_ms"), ctx.i), s=_num(ci.get("samples_collected"))))
        if ci.get("impact_measured"):
            if ci.get("attributable_cpu_ms") is not None:
                basis = ci.get("attributable_basis")
                out.append(ctx.t("m_cpu", ms=fmt_ms(ci["attributable_cpu_ms"], ctx.i)) if basis == "diagnosing_process_cpu"
                           else ctx.t("m_cpu_other", ms=fmt_ms(ci["attributable_cpu_ms"], ctx.i), basis=_c(basis)))
            if ci.get("target_cpu_ms_during_window") is not None and ci.get("system_cpu_busy_fraction") is not None:
                out.append(ctx.t("m_target_cpu", ms=fmt_ms(ci["target_cpu_ms_during_window"], ctx.i),
                                 pct=round(float(ci["system_cpu_busy_fraction"]) * 100)))
            if ci.get("collector_cpu_ms") is not None or ci.get("collector_max_rss_kb") is not None:
                rss = ci.get("collector_max_rss_kb")
                out.append(ctx.t("m_collector", cpu=fmt_ms(ci.get("collector_cpu_ms"), ctx.i),
                                 rss=fmt_bytes(float(rss) * 1024) if rss is not None else "-"))
        if ci.get("budget_exhausted"):
            out.append(ctx.t("m_budget", why=_c(ci.get("budget_exhaustion_reason") or "-")))
    ids = ""
    if res.get("investigation_id"):
        ids = ctx.t("m_ids", inv=_c(res["investigation_id"]))
    if res.get("report_path"):
        ids = (ids + ctx.t("m_report", p=_c(res["report_path"]))).strip()
    if ids:
        out.append(ids)
    if extra.get("generated"):
        out.append(ctx.t("m_generated", ts=extra["generated"]))
    return [f"- {x}" for x in out]


def _glossary(ctx: _Ctx, res: Dict[str, Any]) -> List[str]:
    if (res.get("target") or {}).get("debug_image"):
        ctx.term("debug")
    out = []
    for k in ctx.terms:
        te, de, tk, dk = GLOSSARY[k]
        out.append(f"- **{tk if ctx.i else te}**: {dk if ctx.i else de}")
    return out


def _registered_text(ctx: _Ctx, f: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The summary lines a recipe definition file registered for this category (report_registry), if any."""
    from .report_registry import finding_text
    fn = finding_text(f.get("category"))
    if fn is None:
        return None
    try:
        r = fn(ctx, f, report)
    except Exception:  # noqa: BLE001 - a registered renderer must not break the summary; fall back to the generic one
        return None
    if not isinstance(r, dict) or not isinstance(r.get("lines"), list) or not r["lines"]:
        return None
    r.setdefault("kinds", _by_kind(f))
    r["registered"] = True
    return r


def _symptom_note(ctx: _Ctx, res: Dict[str, Any]) -> List[str]:
    """The one-line statement that a broad plan was used because the symptom was not understood specifically."""
    si = res.get("symptom_interpretation") or {}
    if not isinstance(si, dict) or si.get("understood", True):
        return []
    why = {"no_match": "sym_why_no_match", "weak_evidence": "sym_why_weak",
           "conflicting_classes": "sym_why_conflict"}.get(str(si.get("reason")), "sym_why_no_match")
    return [ctx.t("sym_unclear", why=ctx.t(why))]


def _render_findings(ctx: _Ctx, findings: List[Dict[str, Any]], report: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    renders: List[Dict[str, Any]] = []
    for f in findings:
        cat = f.get("category")
        custom = _registered_text(ctx, f, report)
        if custom is not None:
            r = custom
        elif cat == "DEADLOCK_INDICATORS":
            r = _render_deadlock(ctx, f, report)
            r["rows"] = _thread_rows(report, f.get("recipe_ids"))
        elif cat == "MEMORY_LEAK":
            r = _render_leak(ctx, f, report)
        elif cat == "PROCESS_INSTABILITY":
            r = _render_thread(ctx, f, report)
        else:
            kinds = _by_kind(f)
            lines = []
            for key, kk, fmt in (("variable", "w_vars", _c), ("thread_name", "w_threads", _c), ("thread", "w_tids", str),
                                 ("function", "w_funcs", _c), ("source_location", "w_locs", _c), ("lock", "w_locks", _c),
                                 ("resource", "w_res", _c)):
                vals = _user_funcs(kinds.get(key, [])) if key == "function" else kinds.get(key, [])
                if vals:
                    lines.append("- " + ctx.t(kk, x=_join([fmt(v) for v in vals])))
            for obs in (f.get("observed") or [])[:3]:
                lines.append("- " + ctx.t("w_obs", x=ko_text(obs, ctx.i)))
            r = {"lines": lines, "kinds": kinds}
        renders.append(r)
    return renders


# The card order of the design system (docs/ui-redesign/DESIGN_SYSTEM_KO.md), shared by the live UI and the report:
# verdict -> tiles -> target -> findings -> checks -> not examined -> next steps, then the report-only reference
# material.  "tiles" has no heading (the Markdown shows its four figures as one line at the end of the conclusion);
# every other key is a section.  The live UI's tests compare their card order against this constant.
REPORT_SECTION_ORDER = ("conclusion", "tiles", "target", "profile", "findings", "checks", "not_examined", "next",
                        "hypothesis", "method", "reproducibility", "reference")
SECTION_ORDER = tuple(k for k in REPORT_SECTION_ORDER if k != "tiles")
_SECTION_TITLE = {"conclusion": "s_conclusion", "target": "s_target", "profile": "s_profile", "findings": "s_findings",
                  "checks": "s_scope", "not_examined": "s_not_examined", "next": "s_next",
                  "hypothesis": "s_hypothesis", "method": "s_method", "reproducibility": "s_repro",
                  "reference": "s_reference"}


def _story_parts(ctx: _Ctx, res: Dict[str, Any], report: Optional[Dict[str, Any]], rows: List[Dict[str, Any]],
                 renders: List[Dict[str, Any]], blocks: List[Dict[str, Any]], verdict: str) -> Dict[str, Any]:
    """The competing causes of each finding and the time-ordered course of the diagnosis (``report_story``): the
    causes are attached to their finding block (``competing`` data, ``competing_lines`` Markdown), the timeline is
    returned for the end of the checks section.  Never raises: a report without them is still a report."""
    from . import report_story as rs
    out: Dict[str, Any] = {"competing": [], "timeline": None, "timeline_lines": []}
    try:
        out["competing"] = rs.competing_causes(ctx.lang, res, report, rows)
        for item in out["competing"]:
            b = blocks[item["finding"] - 1]
            b["competing"] = item
            b["competing_lines"] = rs.competing_markdown(ctx.lang, item)
        v = verdict if f"v_{verdict}" in T else "INCONCLUSIVE"
        out["timeline"] = rs.build_timeline(ctx.lang, res, report, rows, renders, ctx.t(f"v_{v}"), v)
        out["timeline_lines"] = [""] + rs.timeline_markdown(ctx.lang, out["timeline"]) if out["timeline"] else []
    except Exception:  # noqa: BLE001 - rendering only; the verdict and the rest of the report do not depend on it
        out["competing"], out["timeline"], out["timeline_lines"] = out["competing"], None, []
    return out


def profile_of(res: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The process profile of a result: built from its report (the same data the checks left), else the one the
    result carries (a result saved without its report)."""
    from .process_profile import build_process_profile
    prof = build_process_profile(res, report) if report else {}
    if not prof.get("available") and isinstance(res.get("process_profile"), dict):
        return res["process_profile"]
    return prof


def compose(result: Dict[str, Any], report: Optional[Dict[str, Any]] = None, lang: str = "en", *,
            pointers: bool = False, method_extra: Optional[Dict[str, Any]] = None,
            extra_sections: Optional[Dict[str, List[str]]] = None,
            repro: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The common outline of every report, as data: ``sections`` is a list of ``{key, title, lines}`` in the order
    of ``SECTION_ORDER`` (sections with nothing to say are left out); ``blocks`` are the per-finding parts, ``rows``
    and ``counts`` the one check table.  Markdown and HTML are both rendered from this.

    ``extra_sections`` supplies the incident-report-only parts (``hypothesis``, ``reproducibility``) as Markdown lines.
    """
    if lang not in SUPPORTED_LANGS:
        raise ValueError(f"lang must be one of {SUPPORTED_LANGS}, got {lang!r}")
    res = dict(result or {})
    report = report if isinstance(report, dict) else (res.get("report") if isinstance(res.get("report"), dict) else None)
    ctx = _Ctx(lang)
    ctx.extra = dict(method_extra or {})
    if repro is None:
        try:
            from .reproducibility import build_reproducibility
            repro = build_reproducibility(report or {}, res).to_dict()
        except Exception:  # noqa: BLE001 - the target card then shows what the result itself carries
            repro = {}
    findings = [f for f in (res.get("findings") or []) if isinstance(f, dict)]
    res["findings"] = findings
    from .profile_render import profile_lines
    profile = profile_of(res, report)
    renders = _render_findings(ctx, findings, report)
    rows = check_rows(res, report)
    verdict = str(res.get("verdict") or "INCONCLUSIVE")
    ctx.term("verdict_healthy" if verdict == "HEALTHY" else "verdict")
    concl = [_verdict_line(ctx, verdict), "", _conclusion(ctx, res, renders)]
    sym = _symptom_note(ctx, res)
    if sym:
        concl += [""] + sym
    glance = _glance_line(ctx, res, rows)
    blocks = _finding_blocks(ctx, res, renders, report, rows)
    story = _story_parts(ctx, res, report, rows, renders, blocks, verdict)
    extra_sections = extra_sections or {}
    body: Dict[str, List[str]] = {
        "conclusion": concl + ([""] + glance if glance else []),
        "target": _section_target(ctx, res, report, repro),
        "profile": profile_lines(profile, lang),
        "findings": _section2(ctx, blocks) if blocks else [],
        "checks": _section4(ctx, res, rows) + story["timeline_lines"],
        "not_examined": _section_not_examined(ctx, res, rows),
        "next": _section5(ctx, res, renders),
        "hypothesis": list(extra_sections.get("hypothesis") or []),
        "method": _section6(ctx, res, method_extra),
        "reproducibility": list(extra_sections.get("reproducibility") or []),
    }
    ref: List[str] = []
    g = _glossary(ctx, res)
    if g:
        ref += [f"### {ctx.t('hg')}", ""] + g
    if pointers:
        ref += ([""] if ref else []) + [f"### {ctx.t('r_where')}", ""] + _where_lines(
            ctx, blocks, bool(extra_sections.get("reproducibility")))
    body["reference"] = ref
    sections = [{"key": k, "title": ctx.t(_SECTION_TITLE[k]), "lines": body[k]} for k in SECTION_ORDER if body.get(k)]
    for n, s in enumerate(sections, 1):
        s["number"] = n
        s["heading"] = f"{n}. {s['title']}"
    return {"lang": lang, "ctx": ctx, "res": res, "report": report, "renders": renders, "blocks": blocks, "rows": rows,
            "counts": check_counts(rows), "verdict": verdict, "verdict_line": concl[0], "conclusion": concl[2],
            "symptom_note": sym, "glossary": g, "sections": sections, "glance": glance_parts(ctx, res, rows),
            "repro": repro, "profile": profile, "competing": story["competing"], "timeline": story["timeline"],
            "scope_head": _scope_head(ctx, res, rows), "not_examined": _not_examined_lines(ctx, res)}


def sections_markdown(comp: Dict[str, Any], level: int = 2) -> List[str]:
    """The numbered sections of a composition as Markdown lines (``##`` sections, ``###`` parts inside)."""
    out: List[str] = []
    for s in comp["sections"]:
        out += ["#" * level + " " + s["heading"], ""] + s["lines"] + [""]
    return out


def render_human_report(result: Dict[str, Any], report: Optional[Dict[str, Any]] = None, lang: str = "en") -> str:
    """Render the human summary (Markdown) of a ``DiagnoseResult`` dict.  ``lang`` is ``"en"`` or ``"ko"``.

    It is the common outline (``compose``) under a one-line title; the incident report uses the same sections."""
    comp = compose(result, report, lang)
    res = comp["res"]
    ctx = comp["ctx"]
    t = res.get("target") or {}
    title = ctx.t("title", proc=_c(t["process_name"]) if t.get("process_name") else ctx.t("unknown_proc"),
                  pid=t.get("pid"))
    lines = [f"# {title}", ""] + sections_markdown(comp)
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"


def diagnose_with_summary(pid: int, debug_image: Optional[str] = None, symptom: Optional[str] = None,
                          time_limit_s: Optional[float] = None, engine: Any = None, lang: str = "en",
                          corpus_dir: Optional[str] = None, target: Any = None,
                          adapter: Any = None, symptom_fields: Any = None,
                          keep_report: bool = False) -> Tuple[Dict[str, Any], str]:
    """Run ``diagnose`` once and return ``(result_dict_without_inline_report, human_summary_markdown)``.

    The inline full report is requested only to give the summary its names and numbers; it is dropped from the
    returned dict so the result keeps its documented shape.
    """
    from .expert_diagnostic_engine import diagnose
    kw: Dict[str, Any] = {"engine": engine} if engine is not None else {"corpus_dir": corpus_dir}
    if target is not None:
        kw["target"] = target
    if adapter is not None:
        kw["adapter"] = adapter
    if symptom_fields is not None:
        kw["symptom_fields"] = symptom_fields
    res = diagnose(pid, debug_image=debug_image, symptom=symptom, time_limit_s=time_limit_s,
                   include_report=True, **kw)
    d = res.to_dict()
    summary = render_human_report(d, d.get("report"), lang=lang)
    if not keep_report:     # keep_report=True: the caller renders the report / the UI view from the same result
        d["report"] = None
    return d, summary


# ------------------------------------------------------------------------------------- Markdown -> HTML
_INLINE_RE = re.compile(r"`([^`]+)`|\*\*([^*]+)\*\*")


def _inline_html(text: str) -> str:
    import html as _h
    out, pos = [], 0
    for m in _INLINE_RE.finditer(text):
        out.append(_h.escape(text[pos:m.start()]))
        out.append(f"<code>{_h.escape(m.group(1))}</code>" if m.group(1) is not None
                   else f"<strong>{_h.escape(m.group(2))}</strong>")
        pos = m.end()
    out.append(_h.escape(text[pos:]))
    return "".join(out)


def markdown_to_html(md: str, heading_offset: int = 0) -> str:
    """Dependency-free converter for the subset the human summary uses: ``#`` headings, paragraphs, ``-`` bullet
    lists, ``1.`` numbered lists, ``| a | b |`` tables (first row is the header, the ``:---`` row is skipped), inline
    code, bold and fenced code blocks.  Everything is HTML-escaped."""
    import html as _h
    out: List[str] = []
    para: List[str] = []
    lst: Optional[str] = None
    fence: Optional[List[str]] = None
    table: List[List[str]] = []

    def cells(row: str) -> List[str]:
        return [c.strip() for c in row.strip().strip("|").split(" | ")]

    def flush_table():
        if table:
            head, body = table[0], [r for r in table[1:] if not all(re.fullmatch(r":?-{3,}:?", c) for c in r)]
            out.append('<div class="dsv-scroll"><table class="dsv-tbl"><thead><tr>'
                       + "".join(f"<th>{_inline_html(c)}</th>" for c in head) + "</tr></thead><tbody>"
                       + "".join("<tr>" + "".join(f"<td>{_inline_html(c)}</td>" for c in r) + "</tr>" for r in body)
                       + "</tbody></table></div>")
            table.clear()

    def flush_para():
        if para:
            out.append("<p>" + "<br>".join(_inline_html(x) for x in para) + "</p>")
            para.clear()

    def close_list():
        nonlocal lst
        if lst:
            out.append(f"</{lst}>")
            lst = None

    for raw in (md or "").splitlines():
        line = raw.rstrip()
        if fence is None and line.strip().startswith("|") and line.strip().endswith("|"):
            flush_para()
            close_list()
            table.append(cells(line))
            continue
        flush_table()
        if fence is not None:
            if line.strip().startswith("```"):
                out.append("<pre><code>" + _h.escape("\n".join(fence)) + "</code></pre>")
                fence = None
            else:
                fence.append(line)
            continue
        if line.strip().startswith("```"):
            flush_para()
            close_list()
            fence = []
            continue
        if not line.strip():
            flush_para()
            close_list()
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            flush_para()
            close_list()
            lvl = min(6, len(m.group(1)) + heading_offset)
            out.append(f"<h{lvl}>{_inline_html(m.group(2))}</h{lvl}>")
            continue
        m = re.match(r"^\s*[-*]\s+(.*)$", line)
        n = re.match(r"^\s*\d+\.\s+(.*)$", line)
        if m or n:
            flush_para()
            kind = "ul" if m else "ol"
            if lst != kind:
                close_list()
                out.append(f"<{kind}>")
                lst = kind
            out.append("<li>" + _inline_html((m or n).group(1)) + "</li>")
            continue
        close_list()
        para.append(line.strip())
    if fence is not None:
        out.append("<pre><code>" + _h.escape("\n".join(fence)) + "</code></pre>")
    flush_table()
    flush_para()
    close_list()
    return "\n".join(out)


# ---------------------------------------------------------------------------------------------- engine text, Korean
# The engine writes its evidence / interpretation / limitation sentences in English, and some verdict rules read those
# strings, so they are never reworded where they are created.  The Korean report translates them here, at render time,
# the same way double_free renders the walker's list names (``_LIST_KO``): a table of full-match patterns, one per
# sentence shape, with the numbers and identifiers captured and copied.  A sentence that matches no pattern is shown
# unchanged (never guessed); tests/test_korean_report_language.py fails when a representative report still shows one.
# Long sentences are written by the engine as fragments joined with "; "; each fragment is matched on its own.
_KN = r"([+-]?\d+)"
_KF = r"([+-]?[\d.]+)"


def _split_top(s: str, sep: str = "; ") -> List[str]:
    """Split ``s`` at ``sep`` outside parentheses."""
    out, depth, start, k = [], 0, 0, 0
    while k < len(s):
        ch = s[k]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and s.startswith(sep, k):
            out.append(s[start:k])
            start = k + len(sep)
            k += len(sep) - 1
        k += 1
    out.append(s[start:])
    return out


def _ko_free_list(name: str) -> str:
    """The free-list name the heap walker wrote, in Korean when it is one of the known shapes."""
    try:
        from .recipe_plugins.double_free import _list_name
    except Exception:  # noqa: BLE001 - the plugin package is optional for rendering
        return name
    m = re.match(r"^(.*), entry (\d+) of (\d+)$", name)
    base, tail = (m.group(1), ", 항목 %s (전체 %s개)" % (m.group(2), m.group(3))) if m else (name, "")
    return _list_name(base, 1) + tail


def _ko_where(s: str) -> str:
    """The ``where`` part of the double-free sentence: lists joined by ' and on '."""
    outp = []
    for part in s.split(" and on "):
        m = re.match(r"^(.*) twice \(entries (\d+) and (\d+): the list returns to it\)$", part)
        if m:
            outp.append("%s에 두 번 (항목 %s과 %s: 목록이 이 블록으로 되돌아옴)" % (_ko_free_list(m.group(1)), m.group(2), m.group(3)))
            continue
        m = re.match(r"^(.*) \(entry (\d+)\)$", part)
        if m:
            outp.append("%s에 (항목 %s)" % (_ko_free_list(m.group(1)), m.group(2)))
            continue
        m = re.match(r"^(.*?) \((next chunk's PREV_INUSE.*)\)$", part)
        if m:
            try:
                from .recipe_plugins.double_free import _evidence_text
                outp.append("%s에 (%s)" % (_ko_free_list(m.group(1)), _evidence_text(m.group(2), 1)))
                continue
            except Exception:  # noqa: BLE001
                pass
        outp.append(part)
    return " 그리고 ".join(outp)


def _ko_damage_reason(s: str) -> str:
    parts = []
    for p in _split_top(s):
        for rx, tpl in (
                (r"invalid chunk size (0x[0-9a-f]+)", "올바르지 않은 청크 크기 {0}"),
                (r"top chunk size (0x[0-9a-f]+) runs (\d+) bytes past the end of its heap segment",
                 "top 청크 크기 {0}이(가) 힙 세그먼트 끝을 {1}바이트 넘어감"),
                (r"IS_MMAPPED flag set on the top chunk", "top 청크에 IS_MMAPPED 플래그가 켜져 있음"),
                (r"runs past segment end", "세그먼트 끝을 넘어감"), (r"IS_MMAPPED set", "IS_MMAPPED가 켜져 있음"),
                (r"chunk header beyond segment", "청크 헤더가 세그먼트 밖에 있음")):
            m = re.fullmatch(rx, p)
            if m:
                parts.append(tpl.format(*m.groups()))
                break
        else:
            parts.append(p)
    return "; ".join(parts)


def _ko_write_basis(s: str) -> str:
    parts = []
    for p in _split_top(s):
        m = re.fullmatch(r"repeated byte (0x[0-9a-fA-F]+) written over the size field and beyond", p)
        if re.fullmatch(r"repeated byte 0x[0-9a-fA-F]+", p):
            parts.append(p.replace("repeated byte", "반복되는 바이트"))
        elif m:
            parts.append("반복되는 바이트 %s이(가) size 필드와 그 뒤까지 덮어씀" % m.group(1))
        elif p == "printable text written over the size field and beyond":
            parts.append("출력 가능한 문자가 size 필드와 그 뒤까지 덮어씀")
        elif p == "the buffer's last usable bytes hold the same pattern":
            parts.append("버퍼의 마지막 사용 가능 바이트도 같은 패턴임")
        else:
            parts.append(p)
    return "; ".join(parts)


def _ko_write_evidence(s: str) -> str:
    m = re.fullmatch(r"payload beyond the allocator metadata changed in (\d+) of (\d+) re-reads \((\d+) distinct contents\) "
                     r"while the chunk stayed free on the same list", s)
    if m:
        return "할당자 관리 정보 뒤의 내용이 다시 읽은 %s번 중 %s번 바뀜 (서로 다른 내용 %s가지). 그동안 블록은 같은 해제 목록에 있었음" % (
            m.group(2), m.group(1), m.group(3))
    m = re.fullmatch(r"allocator metadata of the free chunk overwritten \((.*)\), stable across (\S+) re-reads", s)
    if m:
        return "해제된 청크의 할당자 관리 정보가 덮어쓰임 (%s), %s번 다시 읽어도 같음" % (_ko_damage_reason(m.group(1)), m.group(2))
    return s


_LONG_WAIT_KO = "오래 기다림을 관측했으나 정상 여부는 판단할 수 없음"

# (full-match pattern, Korean template with {0}.. for the groups, or a function of the match)
_KO_ENGINE: List[Tuple["re.Pattern[str]", Any]] = [(re.compile(p, re.S), t) for p, t in (
    # --- remediation steps of the detailed report (section I), fixed engine wording
    (r"Audit pointer dereference bounds and verify memory mapping permissions before dereference\.",
     "포인터를 역참조하기 전에 경계를 점검하고 메모리 매핑 권한을 확인하세요."),
    (r"Enable AddressSanitizer \(ASan\) during build: `-fsanitize=address -g`\.",
     "빌드할 때 AddressSanitizer(ASan)를 켜세요: `-fsanitize=address -g`."),
    (r"Remediate verified fault invariant violations immediately\.", "확인된 결함의 불변식 위반을 즉시 고치세요."),
    (r"Review code locations identified in source correlation\.", "소스 대응에서 찾은 코드 위치를 검토하세요."),
    (r"Execute discriminating recipes to isolate probable causes\.", "가능성 높은 원인을 가려내기 위해 구분용 검사를 실행하세요."),
    (r"Acquire additional independent authoritative runtime observations for definitive confirmation\.",
     "확정하려면 독립적이고 신뢰할 수 있는 실행 중 관측을 더 확보하세요."),
    (r"Enforce strict global lock acquisition ordering hierarchy across all threads\.", "모든 스레드가 엄격한 전역 락 획득 순서를 따르게 하세요."),
    (r"Consider replacing nested mutexes with lock-free structures or fine-grained atomics\.",
     "중첩된 뮤텍스를 락 없는 구조나 세분화된 원자 연산으로 바꾸는 것을 고려하세요."),
    (r"Acquire additional targeted runtime observations for unverified domains\.", "확인되지 않은 영역에 대해 목적에 맞는 실행 중 관측을 더 확보하세요."),
    (r"Inspect reported limitations to resolve missing capabilities or irregular sampling\.",
     "보고된 제한 사항을 살펴 부족한 기능이나 불규칙한 샘플링을 해결하세요."),
    (r"Review state transition logic and enforce assertions for valid enum state transitions\.",
     "상태 전이 로직을 검토하고 올바른 enum 상태 전이에 대한 단언을 강제하세요."),
    (r"Investigation inconclusive due to insufficient evidence or collection failures", "증거가 부족하거나 수집에 실패해 조사가 판단 불가로 끝났습니다"),
    (r"verify target permissions, debug symbols, and process accessibility before re-running\.",
     "다시 실행하기 전에 대상 권한, 디버그 심볼, 프로세스 접근 가능 여부를 확인하세요."),
    # --- outcomes of the checks
    (r"Check executed", "검사를 실행함"),
    (r"Check was not executed before investigation concluded\.", "조사가 끝날 때까지 실행되지 않은 검사입니다."),
    (r"Check was skipped after earlier discriminating step resolved scope\.", "앞선 판별 단계에서 범위가 좁혀져 건너뛴 검사입니다."),
    (r"baseline check not executed: investigation ended with (\S+) \(step status (\S+)\)",
     "기본 검사가 실행되지 않음: 조사가 {0} 상태로 끝남 (단계 상태 {1})"),
    (r"EXCEEDED_WALL_CLOCK: elapsed " + _KF + r"ms >= max " + _KF + r"ms", "경과 시간 한도 초과 (EXCEEDED_WALL_CLOCK): 경과 {0}ms >= 상한 {1}ms"),
    (r"All threads in normal state", "모든 스레드가 정상 상태"),
    (r"Lock ownership verified clean", "락 소유 관계에 이상이 없음을 확인"),
    (r"Suspicious/circular mutex ownership detected", "의심스럽거나 고리를 이루는 뮤텍스 소유 관계를 발견"),
    (r"Wait-for graph is complete and acyclic", "대기 관계 그래프가 완전하며 고리가 없음"),
    (r"Cycle verified persistent across threads", "스레드 사이의 대기 고리가 계속 유지됨을 확인"),
    (r"Threads are blocked on mutex, but complete lock graph contains zero circular wait cycles\.",
     "스레드들이 뮤텍스에서 멈춰 있지만, 전체 락 그래프에 순환 대기 고리는 없습니다."),
    (r"Zero blocked threads observed", "멈춘 스레드가 관측되지 않음"),
    (r"Blocked threads: " + _KN, "멈춘 스레드 {0}개"),
    (r"Thread state anomaly observed", "스레드 상태 이상을 관측함"),
    (r"no lock wait without owner progress in the sampling window", "샘플링 구간에서 소유자가 진행하지 않는데 락을 기다리는 스레드는 없음"),
    (_KN + r" mutex\(es\) inspected in " + _KN + r" samples: every locked one is owned by a live thread",
     "뮤텍스 {0}개를 샘플 {1}회에서 검사: 잠긴 뮤텍스는 모두 살아 있는 스레드가 소유함"),
    (_KN + r" mutex\(es\) inspected in " + _KN + r" samples: no thread waits for a mutex it owns itself",
     "뮤텍스 {0}개를 샘플 {1}회에서 검사: 자기가 소유한 뮤텍스를 기다리는 스레드는 없음"),
    (_KN + r" samples over " + _KF + r" s: no mutex had " + _KN + r" or more threads waiting in more than " + _KN + r" ?% of them",
     "{1}초 동안 샘플 {0}회: 스레드 {2}개 이상이 기다린 샘플이 {3}%를 넘는 뮤텍스는 없음"),
    (r"Heap stable \(delta=" + _KN + r" bytes\)", "힙 크기가 안정적임 (변화량 {0}바이트)"),
    # --- threads
    (r"Thread '(.*)' \(tid (\d+)\) stayed in (.+?) for the whole " + _KF + r"s window with no CPU time and no context "
     r"switch: long wait observed, cannot determine whether expected\.?",
     "스레드 '{0}' (tid {1})이(가) {3}초 구간 내내 {2}에서 머물렀고 CPU 시간도 문맥 전환도 없었음: " + _LONG_WAIT_KO),
    (r"long wait observed, cannot determine whether expected", _LONG_WAIT_KO),
    (r"waited in (.+?) for the whole " + _KF + r" s window: an idle wait and a stall look the same from outside, so whether "
     r"this wait is expected was not judged",
     "{1}초 구간 내내 {0}에서 기다림: 밖에서는 유휴 대기와 멈춤이 같아 보여 이 대기가 정상인지는 판단하지 않음"),
    (r"Thread '(.*)' \(tid (\d+)\) was runnable (\S+) of the " + _KF + r"s window and received (\S+) of a CPU( \(machine contended\))?, "
     r"with no voluntary context switch, no read/write syscall, and the same top frame `(.*)` in most samples \((\S+)\): "
     r"CPU monopoly without observable progress\.?",
     lambda m: "스레드 '%s' (tid %s)이(가) %s초 구간의 %s 동안 실행 가능 상태였고 CPU를 %s 받음%s. 자발적 문맥 전환과 읽기/쓰기 시스템 콜이 없었고 "
               "대부분의 샘플(%s)에서 같은 최상위 프레임 `%s`에 있었음: 진행 없이 CPU를 독점"
               % (m.group(1), m.group(2), m.group(4), m.group(3), m.group(5), " (머신이 경합 중)" if m.group(6) else "", m.group(8), m.group(7))),
    (r"Thread '(.*)' \(tid (\d+)\) stayed a zombie for the whole window\.", "스레드 '{0}' (tid {1})이(가) 구간 내내 좀비 상태였음."),
    (r"Thread '(.*)' \(tid (\d+)\) stayed in uninterruptible sleep \(D\) for " + _KF + r"s\.",
     "스레드 '{0}' (tid {1})이(가) {2}초 동안 중단 불가 대기(D) 상태였음."),
    (r"thread '(.*)' \(tid (\d+)\) waits for mutex '(.*)', which it holds itself \(same wait in (\d+) samples\)( at (.+))?",
     lambda m: "스레드 '%s' (tid %s)이(가) 자기가 잡고 있는 뮤텍스 '%s'을(를) 기다림 (샘플 %s회 동안 같은 대기)%s"
               % (m.group(1), m.group(2), m.group(3), m.group(4), (" - 위치 " + m.group(6)) if m.group(6) else "")),
    (r"mutex '(.*)' is locked by tid (\d+), which is not a thread of the process \(no /proc/(\d+)\), in (\d+) samples",
     "뮤텍스 '{0}'을(를) tid {1}이(가) 잡고 있는데, 이 tid는 프로세스의 스레드가 아님 (/proc/{2} 없음), 샘플 {3}회 동안 같음"),
    (r"(\d+) thread\(s\) wait for it: (.*)", "스레드 {0}개가 이 뮤텍스를 기다림: {1}"),
    (r"mutex '(.*)' is queued on but its owner is not a thread of the process",
     "뮤텍스 '{0}'을(를) 기다리는 스레드가 있으나 그 소유자는 프로세스의 스레드가 아님"),
    (r"mutex '(.*)': >= (\d+) threads waiting in (\d+) of (\d+) samples \(up to (\d+), mean ([\d.]+)\)",
     "뮤텍스 '{0}': 샘플 {3}회 중 {2}회에서 스레드 {1}개 이상이 기다림 (최대 {4}개, 평균 {5}개)"),
    (r"the owner changed between samples \((\d+) different owners\)", "샘플 사이에 소유자가 바뀜 (서로 다른 소유자 {0}명)"),
    (_KN + r" samples over " + _KF + r" s, one lock inspection each", "{1}초 동안 샘플 {0}회, 샘플마다 락을 한 번씩 검사"),
    # --- resources
    (r"open fds (.+?) over " + _KF + r" s \((\S+), (\S+)/s\)(?:, limit (\d+))?",
     lambda m: "열린 fd %s, %s초 동안 (%s, %s/초)%s" % (m.group(1), m.group(2), m.group(3), m.group(4), (", 한도 " + m.group(5)) if m.group(5) else "")),
    (r"threads (.+?) over " + _KF + r" s \((\S+), (\S+)/s\)", "스레드 수 {0}, {1}초 동안 ({2}, {3}/초)"),
    # --- heap
    (r"heap metadata intact: " + _KN + r" chunks walked, top chunk\(s\), free lists and bin links consistent",
     "힙 메타데이터에 이상 없음: 청크 {0}개를 훑었고 top 청크, 해제 목록, bin 연결이 모두 일관됨"),
    (_KN + r" inconsistent read\(s\) changed between re-reads \(target mutating the heap\), not evidence",
     "다시 읽는 사이 값이 바뀐 읽기 {0}건 (대상이 힙을 바꾸는 중)은 증거로 쓰지 않음"),
    (r"every free list walked completely and no block is listed twice: " + _KN + r" tcache bin lists \(" + _KN
     + r" tcache structs\) and " + _KN + r" fastbin lists, " + _KN + r" entries",
     "모든 해제 목록을 끝까지 따라갔고 두 번 올라 있는 블록은 없음: tcache bin 목록 {0}개 (tcache 구조체 {1}개), fastbin 목록 {2}개, 항목 {3}개"),
    (_KN + r" transient repeat\(s\) did not hold on re-read \(not evidence\)", "다시 읽었을 때 유지되지 않은 일시적 반복 {0}건 (증거 아님)"),
    (r"no typed pointer refers to a free chunk and no free chunk was written: " + _KN + r" free chunks tracked, " + _KN
     + r" payloads hashed over " + _KF + r" s \(" + _KN + r" re-reads\)",
     "해제된 청크를 가리키는 타입 있는 포인터도 쓰기가 일어난 해제 청크도 없음: 해제 청크 {0}개 추적, {2}초 동안 내용 {1}개 해시 (다시 읽기 {3}회)"),
    (r"use-after-free: " + _KN + r" of " + _KN + r" free chunks tracked \(cap " + _KN
     + r" chunks\): the others were not checked for dangling references or writes",
     "해제 후 사용: 해제 청크 {1}개 중 {0}개만 추적함 (상한 {2}개). 나머지는 매달린 참조와 쓰기를 확인하지 않음"),
    (r"use-after-free: payload of " + _KN + r" free chunk\(s\) not hashed \(caps: " + _KN + r" chunks, " + _KN
     + r" bytes\): writes into them were not checked",
     "해제 후 사용: 해제 청크 {0}개의 내용은 해시하지 않음 (상한: 청크 {1}개, {2}바이트). 이들에 대한 쓰기는 확인하지 않음"),
    (r"use-after-free: fewer than " + _KN + r" re-reads of the free chunks could be made", "해제 후 사용: 해제 청크를 {0}번 미만만 다시 읽을 수 있었음"),
    (r"(heap|top) chunk header damaged at (0x[0-9a-f]+) \((.*)\), stable across (\d+) re-reads",
     lambda m: "%s 청크 헤더가 손상됨 (위치 %s, %s), %s번 다시 읽어도 같음"
               % ("힙" if m.group(1) == "heap" else "top", m.group(2), _ko_damage_reason(m.group(3)), m.group(4))),
    (r"overflowing buffer: (\S+) \(block (0x[0-9a-f]+), usable " + _KN + r" bytes\)", "넘친 버퍼: {0} (블록 {1}, 사용 가능 {2}바이트)"),
    (r"overflowing buffer: owner unknown \((.*)\)",
     lambda m: "넘친 버퍼: 소유자를 알 수 없음 (%s)" % ("소유자를 찾지 못함" if m.group(1) == "no owner found" else m.group(1))),
    (r"the write reached " + _KN + r" bytes past its usable end \((.*)\)",
     lambda m: "쓰기는 사용 가능 끝을 %s바이트 넘어감 (%s)" % (m.group(1), _ko_write_basis(m.group(2)))),
    (r"damaged block belongs to (\S+)", "손상된 블록은 {0}의 것"),
    (r"damaged: top chunk of arena (\d+) \(unallocated, no owner\)", "손상된 곳: 아레나 {0}의 top 청크 (미할당, 소유자 없음)"),
    # --- use after free
    (r"dangling pointer: (\S+) points to freed chunk (0x[0-9a-f]+) \(size (\d+), (.*)\), stable over " + _KF + r" s",
     lambda m: "매달린 포인터: %s이(가) 해제된 청크 %s (크기 %s, %s)를 가리킴, %s초 동안 같은 상태"
               % (m.group(1), m.group(2), m.group(3), _ko_free_list(m.group(4)), m.group(5))),
    (r"no write into it was observed \(candidate: a use is not proven\)", "쓰기는 관측되지 않음 (후보: 실제 사용은 입증되지 않음)"),
    (r"use after free: (\S+) still points to freed chunk (0x[0-9a-f]+) \(size (\d+), (.*?)\) and the chunk was written while free \((.*)\)",
     lambda m: "해제 후 사용: %s이(가) 해제된 청크 %s (크기 %s, %s)를 아직 가리키고, 청크가 해제된 동안 쓰임 (%s)"
               % (m.group(1), m.group(2), m.group(3), _ko_free_list(m.group(4)), _ko_write_evidence(m.group(5)))),
    (r"use after free: (\S+) still points to freed chunk (0x[0-9a-f]+) and the chunk's free-list metadata was written while free \((.*)\)",
     lambda m: "해제 후 사용: %s이(가) 해제된 청크 %s를 아직 가리키고, 청크의 해제 목록 관리 정보가 해제된 동안 쓰임 (%s)"
               % (m.group(1), m.group(2), _ko_damage_reason(m.group(3)))),
    (r"freed chunk (0x[0-9a-f]+) \(size (\d+), (.*?)\) was written while free \((.*)\)",
     lambda m: "해제된 청크 %s (크기 %s, %s)가 해제된 동안 쓰임 (%s)"
               % (m.group(1), m.group(2), _ko_free_list(m.group(3)), _ko_write_evidence(m.group(4)))),
    (r"owner unknown: no reference remains", "소유자를 알 수 없음: 남아 있는 참조가 없음"),
    # --- double free
    (r"block (0x[0-9a-f]+) \(chunk (0x[0-9a-f]+), size (\d+)\) is listed as free (.*), stable across (\d+) re-reads: it was freed twice",
     lambda m: "블록 %s (청크 %s, 크기 %s)이 해제된 블록으로 %s 올라 있고, %s번 다시 읽어도 같음: 두 번 해제되었음"
               % (m.group(1), m.group(2), m.group(3), _ko_where(m.group(4)[3:] if m.group(4).startswith("on ") else m.group(4)), m.group(5))),
    (r"its tcache count is (\d+) but the list holds (\d+) distinct blocks", "tcache 카운트는 {0}인데 목록에는 서로 다른 블록이 {1}개 있음"),
    (r"two later allocations of this size can both receive address (0x[0-9a-f]+): two owners would then share one block",
     "이후 같은 크기의 할당 두 번이 모두 주소 {0}을(를) 받을 수 있음: 그러면 두 소유자가 한 블록을 나눠 쓰게 됨"),
    (r"still referenced by (.*) \(the pointer that was freed twice, or a copy of it\)", "아직 {0}이(가) 이 블록을 가리킴 (두 번 해제된 포인터이거나 그 사본)"),
    (r"owner unknown \((.*)\)",
     lambda m: "소유자를 알 수 없음 (%s)" % ("남아 있는 참조 없음" if m.group(1).startswith("no reference remains") else m.group(1))),
    (r"which code called free\(\) twice is not observable \(free calls are not traced\)",
     "어느 코드가 free()를 두 번 불렀는지는 관측할 수 없음 (free 호출은 추적하지 않음)"),
    # --- memory growth
    (r"no growth trend \(RSS " + _KN + r" KB over " + _KF + r" s, " + _KN + r" samples\): heap walks not needed",
     "증가 추세 없음 (RSS {0} KB, {1}초 동안 샘플 {2}개): 힙 순회는 필요 없음"),
    (r"only " + _KN + r" usable heap walk\(s\)", "쓸 수 있는 힙 순회가 {0}회뿐임"),
    (_KN + r" are needed to establish a trend", "추세를 판단하려면 {0}회가 필요함"),
    (r"heap walk " + _KN + r": (\S+) observation budget exhausted during (heap walk|reachability): (\S+): current " + _KN
     + r"B \+ reserved " + _KN + r"B \+ estimated " + _KN + r"B > max " + _KN + r"B",
     lambda m: "힙 순회 %s: %s 관측 예산이 %s 도중 소진됨: %s: 현재 %sB + 예약 %sB + 추정 %sB > 상한 %sB"
               % (m.group(1), m.group(2), "힙 순회" if m.group(3) == "heap walk" else "도달 가능성 분석", *m.groups()[3:])),
    (r"growth observed, not established as a leak: RSS " + _KN + r" KB but in-use heap " + _KN
     + r" KB over the walks \(fragmentation, file / anonymous mappings outside malloc, or allocator caching\)",
     "증가는 관측했으나 누수로 확정되지 않음: RSS는 {0} KB이지만 순회 동안 사용 중인 힙은 {1} KB "
     "(단편화, malloc 밖의 파일·익명 매핑, 또는 할당자 캐싱일 수 있음)"),
    (r"in-use heap grew \+" + _KN + r" KB \(\+" + _KN + r" blocks\) across " + _KN + r" heap walks over " + _KF + r" s, without a drop",
     "사용 중인 힙이 힙 순회 {2}회, {3}초에 걸쳐 +{0} KB (블록 +{1}개) 늘었고 줄어든 적이 없음"),
    (_KN + r" in-use blocks of size class " + _KN + r" B \(usable " + _KN + r" B\) with no reachable path, \+" + _KN + r" \(\+" + _KN
     + r" KB\) over " + _KF + r" s",
     "도달 가능한 경로가 없는 크기 등급 {1} B (사용 가능 {2} B)의 사용 중 블록 {0}개, {5}초 동안 +{3}개 (+{4} KB)"),
    (r"allocated in arena (\d+), whose only attached thread is (.+) \(tid (\d+)\)", "아레나 {0}에서 할당됨, 이 아레나에 붙은 스레드는 {1} (tid {2}) 하나뿐"),
    (r"the only DWARF type of the executable that fits this size class is (.+)", "이 크기 등급에 맞는 실행 파일의 DWARF 타입은 {0} 하나뿐"),
    (r"(memory grows|no growth) outside malloc: anonymous memory outside malloc " + _KN + r" KB over " + _KF
     + r" s \(per step ([+\-\d/]+) KB\), RSS " + _KN + r" KB, malloc heap mappings " + _KN + r" KB",
     lambda m: "%s: malloc 밖의 익명 메모리 %s KB, %s초 동안 (단계별 %s KB), RSS %s KB, malloc 힙 매핑 %s KB"
               % ("malloc 밖에서 메모리가 늘고 있음" if m.group(1) == "memory grows" else "malloc 밖에서 증가 없음",
                  m.group(2), m.group(3), m.group(4), m.group(5), m.group(6))),
    (r"grown or new anonymous mappings: " + _KN + r" \(" + _KN + r" newly appeared\)", "늘었거나 새로 생긴 익명 매핑: {0}개 (새로 나타난 것 {1}개)"),
    (r"largest (0x[0-9a-f]+-0x[0-9a-f]+) " + _KN + r" KB \(" + _KN + r" KB\)", "가장 큰 매핑 {0}, {1} KB ({2} KB)"),
    (_KN + r" pointer\(s\) in static variable (\S+) point into the new mappings", "정적 변수 {1}의 포인터 {0}개가 새 매핑을 가리킴"),
    (r"heap in-use " + _KN + r" KB across " + _KN + r" heap walks", "힙 순회 {1}회 동안 사용 중인 힙 {0} KB"),
    (r"memory held by the heap but not in use: arenas hold " + _KF + r" MiB from the system: " + _KF + r" MiB in use, " + _KF
     + r" MiB free in " + _KN + r" free chunks \(" + _KN + r" ?%\), top (.+)",
     "힙이 쥐고 있지만 쓰지 않는 메모리: 아레나가 시스템에서 {0} MiB를 받았고 {1} MiB 사용 중, {2} MiB는 해제 청크 {3}개에 있음 ({4}%), top {5}"),
    (r"heap mappings and RSS flat over " + _KF + r" s \(" + _KN + r" samples\)", "{0}초 동안 힙 매핑과 RSS가 변하지 않음 (샘플 {1}개)"),
    (r"most free memory in arena (\d+) \((\S+)\): " + _KF + r" MiB free in " + _KN + r" chunks, largest free chunk (.+)",
     "해제 메모리 대부분은 아레나 {0} ({1})에 있음: 청크 {3}개에 {2} MiB, 가장 큰 해제 청크 {4}"),
    (r"observation budget exhausted during (heap walk|reachability): (.*)",
     lambda m: "%s 도중 관측 예산이 소진됨: %s" % ("힙 순회" if m.group(1) == "heap walk" else "도달 가능성 분석", m.group(2))),
)]
_KO_PREFIX = re.compile(r"^Runtime anomaly in (\S+): observed (\d+) corroborating indicators\.(?: (.*))?$", re.S)


def _ko_fragment(frag: str) -> str:
    core = frag.strip()
    for rx, tpl in _KO_ENGINE:
        m = rx.fullmatch(core)
        if m:
            out = tpl(m) if callable(tpl) else tpl.format(*m.groups())
            return frag.replace(core, out, 1)
    return frag


def ko_text(s: Any, i: int) -> str:
    """The engine's English evidence / interpretation sentence ``s`` in Korean when ``i`` is 1; unmatched text is unchanged."""
    s = str(s)
    if i != 1 or not s.strip():
        return s
    m = _KO_PREFIX.match(s)
    if m:
        return ("%s 범주의 실행 중 이상: 보조 지표 %s개를 관측함." % (m.group(1), m.group(2))
                + (" " + ko_text(m.group(3), i) if m.group(3) else ""))
    return "; ".join(_ko_fragment(p) for p in _split_top(s))


def conclusion_sentence(summary_md: str) -> str:
    """The conclusion of a report (section 1 without its leading verdict line and detail pointer), on one line;
    "" when absent."""
    m = re.search(r"^## 1\.[^\n]*\n+(.*?)(?:\n+## |\Z)", summary_md or "", re.S | re.M)
    if not m:
        return ""
    paras = [p for p in re.split(r"\n\s*\n", m.group(1).strip()) if p.strip()]
    if len(paras) > 1 and paras[0].startswith("**"):
        paras = paras[1:]                       # the verdict line ("**Verdict: ...**"); the hero shows it as a badge
    paras = [p for p in paras if not p.startswith("_")]   # a pointer to the detailed records
    return " ".join(" ".join(paras).split())
