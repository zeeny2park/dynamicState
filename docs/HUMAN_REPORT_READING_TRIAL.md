# IMP-012 reading trial (human readers, not automated)

Purpose: check that an engineer who did not work on the project can say, from the human summary alone, what is wrong
and where to look. The automated tests only prove the names are in the text; this trial proves a person can use them.

## Setup (facilitator)
1. Pick 2 to 3 engineers who have never used dynamicState and did not see the fixture sources. Korean readers get the
   Korean summary, others the English one (same targets, `--lang ko` / `--lang en`).
2. Build and start the targets (one terminal each), from the repo root:
   - A, deadlock: `gcc -g -O0 -pthread tests/fixtures/real_runtime/proc_thread_circular_deadlock.c -o /tmp/trial_a && /tmp/trial_a &`
   - B, leak: `gcc -g -O0 -pthread tests/fixtures/real_runtime/proc_leak_append_list.c -o /tmp/trial_b && /tmp/trial_b &`
   - C, spinning thread: `gcc -g -O0 -pthread tests/fixtures/real_runtime/proc_thread_spin_work_block.c -o /tmp/trial_c && /tmp/trial_c s &`
   - D, idle/unknown (control): `gcc -g -O0 -pthread tests/fixtures/real_runtime/proc_scenario_a_healthy.c -o /tmp/trial_d && /tmp/trial_d &`
3. Produce one summary per target and save only the summary (never the JSON, the fixture source or this document's
   answer key):
   `python3 -m extractor.cli diagnose -p <PID> -d /tmp/trial_X --lang ko > summary_X.md`
   For B add `--symptom "memory usage keeps growing"`.
4. Kill the targets afterwards.

## Script for each reader (10 minutes per target, think aloud)
Give the reader only `summary_X.md`. Ask, in this order, and write down the answers verbatim:
1. "What is wrong with this process? Answer in one sentence."
2. "Where in the code would you look first? Name the variable, function or file."
3. "How sure is the report, and what did it not check?"
4. "Did the tool stop or slow the process? By how much?"
5. "Is there a word or sentence you did not understand?" (note the exact text)
6. Target D only: "Is this process healthy?" (correct answer: the report does not say so; it lists what was not examined).

Do not help, explain terms, or point at sections. Time the answer to question 1 and 2.

## Answer key (facilitator only)
| Target | Problem | Names the reader must produce | Pass |
|---|---|---|---|
| A | circular wait between two threads | locks `g_mutex_a`, `g_mutex_b`; functions `worker_1`, `worker_2`; file `proc_thread_circular_deadlock.c` | names both locks and both functions, says the lock order must be made consistent |
| B | list grows without bound | `g_pending_items` (path `g_pending_items(->next)*`), thread `producer` | names the variable and says entries are added and never removed |
| C | thread spins | thread `spin_hang`, function `spin_thread` | names the thread and function, says it uses CPU without waiting |
| D | no finding or inconclusive | none | reader does not claim the process is proven healthy; can say what was not examined |

## Scoring and acceptance
- Question 1 and 2 correct (names match the key) for A, B, C: score 1 per target per reader.
- Question 3: reader mentions at least one item from section 4 and the confirmed/probable/could-not-decide level.
- Question 4: reader quotes a measured stop time and bytes read from section 6.
- Acceptance: every reader gets A and B right, and at least 2 of 3 readers get C right; no reader calls D healthy.
- Record per reader: language, scores, time to answer 1 and 2, every unclear word or sentence (question 5). Unclear
  wording is turned into a change to the templates in `extractor/human_report.py` (or a glossary entry) and the trial
  is repeated on the changed targets with a different reader.

## Record template
| Reader | Lang | A | B | C | D | Q3 | Q4 | Unclear text |
|---|---|---|---|---|---|---|---|---|
