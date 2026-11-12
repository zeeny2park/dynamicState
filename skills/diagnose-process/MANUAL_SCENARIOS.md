# Manual check: does a fresh agent follow the skill?

The roadmap acceptance for IMP-023 ("a new agent session, MCP only, says 'diagnose PID N' and the agent calls
`runtime_diagnose_process` and summarizes the report") needs a real agent session and cannot be automated in this
repository. Run these three scenarios by hand and record the tool-call order and the final message.

Setup: connect an agent to the dynamicState MCP server only (`dynamic-state-mcp`, see README), with the skill
text available as the server instructions (it is) and optionally installed as a skill (copy `skills/diagnose-process/`).
Build the fixtures first:

    gcc -g -O0 -pthread -o /tmp/deadlock_pipeline benchmarks/diagnosis_accuracy/targets/deadlock_pipeline.c
    gcc -g -O0 -pthread -o /tmp/ok_idle_server benchmarks/diagnosis_accuracy/targets/ok_idle_server.c
    # deadlock_pipeline = deadlock target, ok_idle_server = healthy target (each prints READY when in steady state)

## 1. Deadlock fixture
Start a `deadlock` target from `benchmarks/diagnosis_accuracy/targets/`, wait for its `READY` line. Prompt: "Diagnose PID <pid>."
Pass if: the first tool call is `runtime_diagnose_process` (no questions asked, no other tool first); the final message
names the locks and threads, says the verdict and confidence, lists what was not examined, says the process was not stopped.
Fail if: the agent asks for symbols it does not need, or calls many tools before `diagnose`.

## 2. Healthy fixture
Start a `healthy` target. Prompt: "Is PID <pid> healthy?"
Pass if: `diagnose` is called once; if the verdict is HEALTHY the message says "healthy within the checked scope"
and names what was not checked (`healthy_scope.not_checked`); if the verdict is INCONCLUSIVE the agent does NOT say
"no problem" / "healthy" and says it could not tell and why.

## 3. Missing debug ELF
Strip a copy of a target (`strip -s -o /tmp/app.stripped <elf>`), run it, prompt: "Diagnose PID <pid>."
Pass if: the agent asks the user for the unstripped / debug build of the same program (or reports INCONCLUSIVE with
`missing_debug_image`/no DWARF as the cause and then asks), and never guesses a path or reports the process as fine.
Also try a nonexistent `debug_image` path: the result must be INCONCLUSIVE with `missing_debug_image` in `not_covered`.
