#!/usr/bin/env bash
set -euo pipefail

# Integration test for Phase 5: Agent Runtime Protocol + Reference Implementation
# Verifies:
# 1. Stripped production binary + external debug image bound via AgentRuntime.
# 2. Simulated Coding Agent performing semantic observe, inspect, candidate selection,
#    state transition execution, evidence extraction, invariant candidate detection,
#    and state exploration without raw GDB commands or memory addresses.
# 3. Deterministic semantic transition: retry = 2 -> 3, Session.state CONNECTED -> ERROR,
#    Session.flagged false -> true.
# 4. Strict safety boundaries: rejection of arbitrary commands and invalid candidates.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TMP_DIR="$(mktemp -d /tmp/dynstate_agent_runtime_XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/corpus"

# 1. Compile test target, separate debug image, and strip binary
g++ -g -O0 -o "${TMP_DIR}/sample" "${ROOT_DIR}/examples/sample.cpp"
objcopy --only-keep-debug "${TMP_DIR}/sample" "${TMP_DIR}/sample.debug"
strip -s -o "${TMP_DIR}/sample_stripped" "${TMP_DIR}/sample"

# 2. Run AgentRuntime E2E simulation via GDB Python
gdb -q -nx -batch \
  -ex "set confirm off" \
  -ex "set python print-stack full" \
  -ex "file ${TMP_DIR}/sample_stripped" \
  -ex "source ${ROOT_DIR}/gdb/extract_state.py" \
  -ex "load-debug-image ${TMP_DIR}/sample.debug" \
  -ex "set args 10" \
  -ex "break runtime_state_checkpoint" \
  -ex "run" \
  -ex "python
import json, sys
import runtime_commands
from extractor.agent_runtime import AgentRuntime
from extractor.agent_models import AgentAction

controller = runtime_commands._CONTROLLER
agent = AgentRuntime(controller, corpus_dir='${TMP_DIR}/corpus')

# -------------------------------------------------------------
# 1. OBSERVE: Compact semantic context
# -------------------------------------------------------------
res_obs = agent.observe()
assert res_obs.success, f'OBSERVE failed: {res_obs.error}'
ctx = res_obs.data
assert ctx['snapshot_id'] is not None
assert ctx['execution']['function'] in ('process_packet', 'runtime_state_checkpoint')
assert len(ctx['objects']) >= 1

prov = ctx.get('provenance')
assert prov is not None, 'Missing provenance'
assert prov['runtime_binary']['stripped'] is True, 'Expected stripped runtime binary'
assert prov['debug_image']['compatible'] is True, 'Expected compatible debug image'
assert prov['debug_image']['source'] == 'external', 'Expected external debug image'
print('[AGENT E2E] 1. OBSERVE succeeded with external debug image provenance.')

# -------------------------------------------------------------
# 2. LIST & INSPECT OBJECTS
# -------------------------------------------------------------
res_objs = agent.list_objects()
assert res_objs.success, f'LIST_OBJECTS failed: {res_objs.error}'
objs = res_objs.data
session_obj = next(o for o in objs if o['type'] == 'Session')
session_id = session_obj['object_id']
print(f'[AGENT E2E] 2. Discovered semantic Session object: {session_id}')

res_inspect = agent.inspect_object(session_id)
assert res_inspect.success
fields = {f['name']: f for f in res_inspect.data['fields']}
assert fields['retry']['value'] == 2
assert 'CONNECTED' in str(fields['state']['value'])
print('[AGENT E2E] 3. INSPECT_OBJECT verified initial Session state.')

# -------------------------------------------------------------
# 3. INSPECT FIELD
# -------------------------------------------------------------
res_field = agent.inspect_field(session_id, 'retry')
assert res_field.success
assert res_field.data['value'] == 2
assert res_field.data['mutability'] == 'mutable'
print('[AGENT E2E] 4. INSPECT_FIELD verified retry field.')

# -------------------------------------------------------------
# 4. LIST & RANK MUTATION CANDIDATES
# -------------------------------------------------------------
res_cands = agent.list_mutation_candidates()
assert res_cands.success, f'LIST_CANDIDATES failed: {res_cands.error}'
cands = res_cands.data
assert len(cands) >= 1

# Find the candidate proposing retry = 3 (boundary plus one)
retry_3_cand = next((c for c in cands if c.field == 'retry' and c.proposed_value == 3), None)
assert retry_3_cand is not None, 'Missing retry=3 candidate'
print(f'[AGENT E2E] 5. Selected ranked candidate: {retry_3_cand.candidate_id} (score: {retry_3_cand.priority_score})')

# -------------------------------------------------------------
# 5. EXECUTE TRANSITION via candidate
# -------------------------------------------------------------
res_trans = agent.execute_transition(retry_3_cand.candidate_id, timeout_ms=1000)
assert res_trans.success, f'EXECUTE_TRANSITION failed: {res_trans.error}'
trans = res_trans.data
assert trans['transition_id'] is not None

# Verify semantic facts extracted by TransitionAnalyzer
facts = trans['facts']
assert facts['branch_changed'] is True, f'Expected branch_changed: True, got {facts}'
assert any('Session.state' in f for f in facts['field_changed']), 'Expected Session.state in field_changed'
assert any('Session.retry' in f for f in facts['field_changed']), 'Expected Session.retry in field_changed'
assert any('Session.flagged' in f for f in facts['field_changed']), 'Expected Session.flagged in field_changed'
assert facts['crash'] is False
assert facts['timeout'] is False

# Verify evidence items
evidence = trans['evidence']
assert len(evidence) >= 3
obs_strings = [e['observation'] for e in evidence]
assert any('Session.retry' in s for s in obs_strings)
assert any('Session.state' in s for s in obs_strings)
print('[AGENT E2E] 6. EXECUTE_TRANSITION produced valid semantic facts & evidence.')

# -------------------------------------------------------------
# 6. DETECT INVARIANT CANDIDATES
# -------------------------------------------------------------
res_inv = agent.detect_invariant_candidates()
assert res_inv.success
inv_candidates = res_inv.data
assert len(inv_candidates) >= 1
exprs = [inv.expression for inv in inv_candidates]
assert any('Buffer.length <= Buffer.capacity' in x for x in exprs)
assert any('Session.retry >= 0' in x for x in exprs)
print('[AGENT E2E] 7. DETECT_INVARIANTS proposed structural invariant candidates.')

# -------------------------------------------------------------
# 7. INSPECT TRANSITION & CORPUS STATES
# -------------------------------------------------------------
res_ti = agent.inspect_transition(trans['transition_id'])
assert res_ti.success
assert res_ti.data['transition_id'] == trans['transition_id']

res_states = agent.list_states()
assert res_states.success
assert len(res_states.data) >= 1
print('[AGENT E2E] 8. State corpus and transition inspection verified.')

# -------------------------------------------------------------
# 8. AUTONOMOUS STATE EXPLORATION
# -------------------------------------------------------------
res_explore = agent.explore(max_steps=3, timeout_ms=1000)
assert res_explore.success, f'EXPLORE failed: {res_explore.error}'
exp_result = res_explore.data
assert exp_result['steps'] >= 1
assert exp_result['exploration_id'] is not None
print(f'[AGENT E2E] 9. EXPLORE loop executed {exp_result[\"steps\"]} steps on stripped binary.')

# -------------------------------------------------------------
# 9. SAFETY BOUNDARY VERIFICATION
# -------------------------------------------------------------
# Unsupported command rejected
res_bad_cmd = agent.dispatch_action({'action': 'EXECUTE_SHELL_COMMAND', 'command': 'rm -rf /'})
assert not res_bad_cmd.success
assert res_bad_cmd.error.code == 'CAPABILITY_UNSUPPORTED'

# Invalid candidate ID rejected
res_bad_cand = agent.execute_transition('M_NONEXISTENT_999')
assert not res_bad_cand.success
assert res_bad_cand.error.code == 'INVALID_CANDIDATE'
print('[AGENT E2E] 10. Safety boundaries verified: arbitrary execution strictly rejected.')
"

echo "Agent Runtime integration test passed"
