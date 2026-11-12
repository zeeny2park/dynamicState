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
    "r_nofinding": ("{ran} check(s) ran, {dec} of them decided, and none produced a finding that names a cause; "
                    "{nc} item(s) could not be examined",
                    "검사 {ran}개가 실행되어 그중 {dec}개가 결론을 냈지만 원인을 가리키는 발견은 없었고, "
                    "{nc}개 항목은 확인하지 못했습니다"),
    "r_unspecified": ("the engine gave no further reason", "엔진이 더 이상의 이유를 알려주지 않았습니다"),
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
    "w_spin": ("Thread {thr} (tid {tid}) was runnable in {frac}% of the samples and used {cpu}% of a CPU while "
               "running in {fn} (defined at {loc}).",
               "스레드 {thr} (tid {tid})은(는) 샘플의 {frac}%에서 실행 가능 상태였고 CPU를 {cpu}% 사용하며 "
               "{loc}에 정의된 {fn} 안에서 돌고 있었습니다."),
    "w_spin_at": ("Thread {thr} (tid {tid}) was runnable in {frac}% of the samples and used {cpu}% of a CPU while "
                  "running at {loc}{call}{inl} (in {fn}).",
                  "스레드 {thr} (tid {tid})은(는) 샘플의 {frac}%에서 실행 가능 상태였고 CPU를 {cpu}% 사용하며 "
                  "{fn} 안의 {loc}{call}{inl}에서 돌고 있었습니다."),
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
    "debug": ("debug image", "the build of the program that still carries variable and line information (DWARF).",
              "디버그 이미지", "변수와 줄 정보(DWARF)가 남아 있는 프로그램 빌드."),
    "verdict": ("confirmed / probable / could not decide", "confirmed = proven by evidence, probable = likely but "
                "not proven, could not decide = the checks gave no answer (this is not 'healthy').",
                "확정 / 추정 / 판단 불가", "확정 = 증거로 입증됨, 추정 = 가능성 높으나 미입증, 판단 불가 = 검사가 답을 "
                "주지 못함(건강하다는 뜻이 아님)."),
    # the same line for a HEALTHY result (the healthy term is only defined where the verdict is HEALTHY)
    "verdict_healthy": ("confirmed / probable / healthy / could not decide", "confirmed = proven by evidence, "
                        "probable = likely but not proven, healthy = every baseline check ran to completion and found "
                        "nothing (only within the checked scope; what was not checked is listed), could not decide = "
                        "the checks gave no answer.",
                        "확정 / 추정 / 정상 / 판단 불가", "확정 = 증거로 입증됨, 추정 = 가능성 높으나 미입증, 정상 = 모든 "
                        "기본 검사가 끝까지 실행되어 아무것도 발견하지 못함(점검한 범위 안에서만이며, 점검하지 못한 "
                        "것은 따로 적음), 판단 불가 = 검사가 답을 주지 못함."),
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
                        "walks": li.get("walks"), "still_ref": True}
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
    return {"lines": lines, "g": g}


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
            if r.get("top_source_line_exact"):
                call, inl = _at_parts(ctx, r, fn)
                lines.append(ctx.t("w_spin_at", thr=_c(r.get("name")), tid=r.get("tid"), frac=frac, cpu=cpu,
                                   fn=_c(fn), loc=_c(loc), call=call, inl=inl))
            else:
                lines.append(ctx.t("w_spin", thr=_c(r.get("name")), tid=r.get("tid"), frac=frac, cpu=cpu, fn=_c(fn), loc=_c(loc)))
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


def _cat_label(ctx: _Ctx, cat: str) -> str:
    if cat in CATEGORY_LABEL:
        return CATEGORY_LABEL[cat][ctx.i] + f" [{cat}]"
    return _c(cat)


def _status_word(ctx: _Ctx, st: str) -> str:
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
                return ctx.t("r_unreach", raw=_c(raw))
            if kind == "target_unreadable":
                if "does not exist" in raw or "invalid PID" in raw:
                    return ctx.t("r_nopid", pid=pid)
                return ctx.t("r_unread", raw=_c(raw))
            if kind == "missing_debug_image":
                if (res.get("target") or {}).get("transport") == "ssh":
                    return ctx.t("r_noimg_remote")
                return ctx.t("r_noimg", item=_c(n.get("item")))
            if kind in ("stage_failed", "unexpected_error"):
                return ctx.t("r_stage", item=_c(n.get("item")), raw=_c(raw))
            return ctx.t("r_noexec", raw=_c(raw))
    checks = res.get("checks_run") or []
    if checks:
        dec = sum(1 for c in checks if c.get("status") in ("PASS", "FAIL"))
        return ctx.t("r_nofinding", ran=len(checks), dec=dec, nc=len(nc))
    return ctx.t("r_unspecified")


def _healthy_sentence(ctx: _Ctx, who: str, res: Dict[str, Any]) -> str:
    scope = res.get("healthy_scope") if isinstance(res.get("healthy_scope"), dict) else {}
    if not scope.get("healthy"):
        return ctx.t("c_healthy_noscope", who=who)
    labels = [str(x.get("label_ko" if ctx.i else "label") or x.get("item")) for x in scope.get("not_checked") or []]
    shown = "; ".join(labels[:3]) or "-"
    if len(labels) > 3:
        shown += ctx.t("c_healthy_more", n=len(labels) - 3)
    return ctx.t("c_healthy", who=who, n=len(scope.get("checked") or []), nc=shown)


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
        s += ctx.t("c_more", n=len(findings) - 1)
    return s


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
    lab = _cat_label(ctx, str(cat))
    if names:
        return f"{lab} ({_join(names)})"
    return lab + (" (no names attached)" if en else " (이름이 붙지 않음)")


def _thread_rows_from(r: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    return r.get("rows") or {}


def _section2(ctx: _Ctx, res: Dict[str, Any], renders: List[Dict[str, Any]]) -> List[str]:
    findings = res.get("findings") or []
    out: List[str] = []
    if not findings:
        out.append(ctx.t("w_none"))
        return out
    for i, (f, r) in enumerate(zip(findings, renders), 1):
        out.append("**" + ctx.t("w_finding", i=i, cat=_cat_label(ctx, str(f.get("category"))),
                                status=_status_word(ctx, str(f.get("status"))), sev=f.get("severity")) + "**")
        if not (f.get("subjects") or f.get("subject_details")):
            out.append(ctx.t("w_noname"))
            continue
        out.extend(r["lines"])
        if r.get("diagram"):
            out.append("")
            out.append(f"**{ctx.t('h2_wait')}**")
            out.append("```")
            out.append(ctx.t("d_hdr"))
            out.extend(r["diagram"])
            out.append("```")
        out.append("")
    while out and out[-1] == "":
        out.pop()
    return out


def _check_counts(res: Dict[str, Any]) -> Tuple[int, int, int, int]:
    ch = res.get("checks_run") or []
    p = sum(1 for c in ch if c.get("status") == "PASS")
    fl = sum(1 for c in ch if c.get("status") == "FAIL")
    return len(ch), p, fl, len(ch) - p - fl


def _section3(ctx: _Ctx, res: Dict[str, Any], renders: List[Dict[str, Any]], report: Optional[Dict[str, Any]]) -> List[str]:
    ran, p, fl, inc = _check_counts(res)
    findings = res.get("findings") or []
    out: List[str] = []
    if ran == 0:
        out.append(ctx.t("y_noruns"))
        return [f"1. {x}" for x in out]
    if not findings:
        out.append(ctx.t("y_checks_none", ran=ran, pass_=p, fail=fl, inc=inc))
        if res.get("verdict") in ("INCONCLUSIVE", "ABORTED"):
            out.append(ctx.t("y_incon"))
        return [f"{i}. {x}" for i, x in enumerate(out, 1)]
    f, r = findings[0], renders[0]
    ids = _join([_c(x) for x in (f.get("recipe_ids") or [])]) or "-"
    out.append(ctx.t("y_checks", ran=ran, pass_=p, fail=fl, inc=inc, ids=ids))
    cat = f.get("category")
    if cat == "DEADLOCK_INDICATORS":
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
    else:
        out.append(ctx.t("y_generic", n=len(f.get("evidence_ids") or [])))
    if f.get("evidence_ids"):
        out.append(ctx.t("y_evidence", n=len(f["evidence_ids"]), conf=round(float(res.get("confidence") or 0) * 100)))
    return [f"{i}. {x}" for i, x in enumerate(out[:5], 1)]


def _abi_text(res: Dict[str, Any]) -> str:
    abi = (res.get("target") or {}).get("abi")
    if isinstance(abi, dict) and abi.get("architecture"):
        return f" ({abi['architecture']}/{abi.get('libc') or '?'})"
    return ""


def _section4(ctx: _Ctx, res: Dict[str, Any]) -> List[str]:
    v = str(res.get("verdict"))
    conf = round(float(res.get("confidence") or 0) * 100)
    out = [ctx.t("k_verdict", v=f"{v} - {ctx.t(VERDICT_WORD.get(v, 'k_incon'))}", conf=conf)]
    ctx.term("verdict_healthy" if v == "HEALTHY" else "verdict")
    for f in res.get("findings") or []:
        out.append(f"- {_cat_label(ctx, str(f.get('category')))}: {_status_word(ctx, str(f.get('status')))}")
    scope = res.get("healthy_scope") if isinstance(res.get("healthy_scope"), dict) else {}
    if v == "HEALTHY" and scope.get("healthy") and scope.get("checked"):
        out += ["", ctx.t("k_checked")]
        out += [f"- {x.get('what_ko' if ctx.i else 'what')} ({_c(x.get('recipe_id'))})" for x in scope["checked"]]
    nc = res.get("not_covered") or []
    if not nc:
        out.append(ctx.t("k_none"))
        return out
    out.append("")
    out.append(ctx.t("k_notexam"))
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for n in nc:
        groups.setdefault(str(n.get("kind")), []).append(n)
    for kind, items in groups.items():
        names = [_c(n.get("item")) for n in items]
        raws = [str(n.get("reason") or "") for n in items if n.get("reason")]
        if kind == "target_unreadable":
            gone = any("does not exist" in r or "invalid PID" in r for r in raws)
            line = ctx.t("nc_target_unreadable", items=ctx.t("nc_pid_gone") if gone else _join([_c(r) for r in raws]))
        elif kind == "missing_debug_image":
            line = ctx.t("nc_missing_debug_image_remote" if (res.get("target") or {}).get("transport") == "ssh"
                         else "nc_missing_debug_image", items=_join(names))
        elif kind in ("target_unreachable", "invalid_target"):
            line = ctx.t(f"nc_{kind}", items=_join([_c(r) for r in raws] or names))
        elif kind == "remote_limitation":
            line = ctx.t("nc_remote_limitation", items="; ".join(_c(r) for r in raws) or _join(names))
        elif kind == "unsupported_on_target":
            line = ctx.t("nc_unsupported_on_target", abi=_abi_text(res), items=_join(names))
        elif kind.startswith("check_"):
            line = ctx.t("nc_check", st=_STATUS_WORD.get(kind[6:], (kind[6:],) * 2)[ctx.i], items=_join(names))
        elif kind == "recipes_not_planned":
            ids = [x for n in items for x in str(n.get("item")).split(",") if x]
            line = ctx.t("nc_recipes_not_planned", n=len(ids), items=_join([_c(x) for x in ids]))
        elif kind == "long_wait_not_judged":
            line = ctx.t("nc_long_wait_not_judged", items=_join(names))
        elif kind == "baseline_check_not_run":
            line = ctx.t("nc_baseline_check_not_run", items=_join(names))
        elif kind in ("unattributed_finding", "stage_failed", "unexpected_error"):
            line = ctx.t(f"nc_{kind}", items=_join(names))
        elif kind == "limitation":
            line = ctx.t("nc_limitation") + " " + "; ".join(_c(r) for r in raws)
        elif kind in T and f"nc_{kind}" in T:
            line = ctx.t(f"nc_{kind}")
        elif f"nc_{kind}" in T:
            line = ctx.t(f"nc_{kind}")
        else:
            line = ctx.t("nc_other", kind=_c(kind)) + " " + _join(names)
        if (f"nc_{kind}" in T and kind in ("budget_exhausted", "leak_owner_limited", "abi_detection_failed",
                                          "report_not_saved", "not_executed")) and raws:
            line += ctx.t("nc_orig", raw=_c(raws[0]))
        elif kind in ("unsupported_on_target",) or kind.startswith("check_"):
            pass
        out.append(f"- {line}")
    return out


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
                out.append("- " + ctx.t("n_incon_nc"))
        return out
    if v == "HEALTHY" and not findings:
        return [ctx.t("n_healthy")]
    for i, (f, r) in enumerate(zip(findings, renders), 1):
        steps = _finding_next(ctx, f, r)
        if len(findings) > 1:
            out.append(f"**{_cat_label(ctx, str(f.get('category')))}**")
        out.extend(f"{n}. {s}" for n, s in enumerate(steps, 1))
    return out


def _section6(ctx: _Ctx, res: Dict[str, Any]) -> List[str]:
    ci = res.get("collection_impact") or {}
    if not ci or ci.get("capture_mode") is None and ci.get("bytes_read") is None:
        out = [ctx.t("i_none")]
    else:
        ctx.term("zerostop")
        out = [ctx.t("i_mode", mode=_c(ci.get("capture_mode")))]
        ms = ci.get("measured_stop_ms")
        out.append(ctx.t("i_zero" if ci.get("zero_stop") else "i_stop", ms=_num(ms)))
        out.append(ctx.t("i_bytes", b=_num(ci.get("bytes_read"))))
        out.append(ctx.t("i_wall", ms=_num(ci.get("wall_clock_ms")), s=_num(ci.get("samples_collected"))))
        if ci.get("budget_exhausted"):
            out.append(ctx.t("i_budget"))
    if res.get("report_path"):
        out.append(ctx.t("i_report", p=_c(res["report_path"])))
    return [f"- {x}" for x in out]


def _glossary(ctx: _Ctx, res: Dict[str, Any]) -> List[str]:
    if (res.get("target") or {}).get("debug_image"):
        ctx.term("debug")
    out = []
    for k in ctx.terms:
        te, de, tk, dk = GLOSSARY[k]
        out.append(f"- **{tk if ctx.i else te}**: {dk if ctx.i else de}")
    return out


def render_human_report(result: Dict[str, Any], report: Optional[Dict[str, Any]] = None, lang: str = "en") -> str:
    """Render the human summary (Markdown) of a ``DiagnoseResult`` dict.  ``lang`` is ``"en"`` or ``"ko"``."""
    if lang not in SUPPORTED_LANGS:
        raise ValueError(f"lang must be one of {SUPPORTED_LANGS}, got {lang!r}")
    res = dict(result or {})
    report = report if isinstance(report, dict) else (res.get("report") if isinstance(res.get("report"), dict) else None)
    ctx = _Ctx(lang)
    findings = [f for f in (res.get("findings") or []) if isinstance(f, dict)]
    res["findings"] = findings
    renders: List[Dict[str, Any]] = []
    for f in findings:
        cat = f.get("category")
        if cat == "DEADLOCK_INDICATORS":
            r = _render_deadlock(ctx, f, report)
            r["rows"] = _thread_rows(report, f.get("recipe_ids"))
        elif cat == "MEMORY_LEAK":
            r = _render_leak(ctx, f, report)
        elif cat == "PROCESS_INSTABILITY":
            r = _render_thread(ctx, f, report)
        else:
            kinds = _by_kind(f)
            lines = [ctx.t("w_gen_cat", cat=_cat_label(ctx, str(cat)))]
            for key, kk, fmt in (("variable", "w_vars", _c), ("thread_name", "w_threads", _c), ("thread", "w_tids", str),
                                 ("function", "w_funcs", _c), ("source_location", "w_locs", _c), ("lock", "w_locks", _c),
                                 ("resource", "w_res", _c)):
                vals = _user_funcs(kinds.get(key, [])) if key == "function" else kinds.get(key, [])
                if vals:
                    lines.append("- " + ctx.t(kk, x=_join([fmt(v) for v in vals])))
            for obs in (f.get("observed") or [])[:3]:
                lines.append("- " + ctx.t("w_obs", x=str(obs)))
            r = {"lines": lines, "kinds": kinds}
        renders.append(r)

    concl = _conclusion(ctx, res, renders)
    parts = [f"# {ctx.t('title', proc=(_c(res.get('target', {}).get('process_name')) if (res.get('target') or {}).get('process_name') else ctx.t('unknown_proc')), pid=(res.get('target') or {}).get('pid'))}",
             "", f"## {ctx.t('h1')}", "", concl, "",
             f"## {ctx.t('h2')}", ""]
    parts += _section2(ctx, res, renders)
    parts += ["", f"## {ctx.t('h3')}", ""] + _section3(ctx, res, renders, report)
    parts += ["", f"## {ctx.t('h4')}", ""] + _section4(ctx, res)
    parts += ["", f"## {ctx.t('h5')}", ""] + _section5(ctx, res, renders)
    parts += ["", f"## {ctx.t('h6')}", ""] + _section6(ctx, res)
    g = _glossary(ctx, res)
    if g:
        parts += ["", f"## {ctx.t('hg')}", ""] + g
    return "\n".join(parts) + "\n"


def diagnose_with_summary(pid: int, debug_image: Optional[str] = None, symptom: Optional[str] = None,
                          time_limit_s: Optional[float] = None, engine: Any = None, lang: str = "en",
                          corpus_dir: Optional[str] = None, target: Any = None,
                          adapter: Any = None) -> Tuple[Dict[str, Any], str]:
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
    res = diagnose(pid, debug_image=debug_image, symptom=symptom, time_limit_s=time_limit_s,
                   include_report=True, **kw)
    d = res.to_dict()
    summary = render_human_report(d, d.get("report"), lang=lang)
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
    lists, ``1.`` numbered lists, inline code, bold and fenced code blocks.  Everything is HTML-escaped."""
    import html as _h
    out: List[str] = []
    para: List[str] = []
    lst: Optional[str] = None
    fence: Optional[List[str]] = None

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
    flush_para()
    close_list()
    return "\n".join(out)


def conclusion_sentence(summary_md: str) -> str:
    """The text of section 1 (the conclusion) of a human summary, on one line; "" when absent."""
    m = re.search(r"^## 1\.[^\n]*\n+(.*?)(?:\n+## |\Z)", summary_md or "", re.S | re.M)
    return " ".join(m.group(1).split()) if m else ""
