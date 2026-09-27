#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "$0")/.." && pwd)
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT

g++ -g -O0 -o "$build_dir/sample" "$root_dir/examples/sample.cpp"

# Test Phase 3 workflow inside real GDB 15.1
gdb -q -nx -batch "$build_dir/sample" \
  -ex "source $root_dir/gdb/extract_state.py" \
  -ex 'break runtime_state_checkpoint' -ex run \
  -ex "snapshot-state A --output $build_dir/A.json" \
  -ex 'mutate-state --object obj_0001 --field retry --value 3' \
  -ex 'mutate-state --object obj_0001 --field retry --value hello' \
  -ex 'mutate-state --object obj_0001 --field priority --value 999' \
  -ex 'mutate-state --object obj_0001 --field invalid_field --value 1' \
  -ex 'continue-state --timeout-ms 1000' \
  -ex "snapshot-state B --output $build_dir/B.json" \
  -ex "diff-state A B --output $build_dir/diff.json" \
  -ex 'mutate-state --path Session.state --value SessionState::CONNECTED' \
  -ex 'mutate-state --path Session.flagged --value false' \
  -ex 'mutate-state --object obj_0002 --field data --value null' \
  -ex 'mutate-state Session.retry 3' \
  -ex "diff-state --before $build_dir/A.json --after $build_dir/B.json" \
  -ex 'continue-state' > "$build_dir/transcript.txt"

# Standalone CLI diff test
python3 -m extractor.state_diff --before "$build_dir/A.json" --after "$build_dir/B.json" --output "$build_dir/cli_diff.json" > /dev/null

python3 - "$build_dir/A.json" "$build_dir/B.json" "$build_dir/diff.json" "$build_dir/cli_diff.json" "$build_dir/transcript.txt" <<'PY'
import json, sys
a, b, diff, cli_diff = (json.load(open(path)) for path in sys.argv[1:5])
text = open(sys.argv[5]).read()

def session(snapshot):
    return next(o for o in snapshot['persistent']['objects'] if o['type'] == 'Session')

fields_a = {f['name']: f for f in session(a)['fields']}
fields_b = {f['name']: f for f in session(b)['fields']}

# 1. Verify schema version 0.3
assert a['schema_version'] == b['schema_version'] == '0.3'

# 2. Verify performance metrics in snapshot
assert all(name in a['persistent']['statistics']['performance'] for name in ('snapshot_ms', 'serialization_ms', 'traversal_ms', 'root_discovery_ms'))

# 3. Verify State Transition: retry 2 -> 3, state CONNECTED -> ERROR
assert fields_a['retry']['value'] == 2 and fields_b['retry']['value'] == 3
assert fields_a['state']['value'].endswith('CONNECTED') and fields_b['state']['value'].endswith('ERROR')
assert fields_b['flagged']['value'] == 1

# 4. Verify object graph remains valid & expected object count
assert b['persistent']['statistics']['object_count'] == 4
assert len(b['persistent']['objects']) == 4

# 5. Verify cycle remains detected
assert b['persistent']['statistics']['cycles_detected'] >= 1

# 6. Verify Semantic Diff changes
changes = {(c.get('path'), c['kind']) for c in diff['changes']}
assert ('Session.retry', 'value_change') in changes
assert ('Session.state', 'value_change') in changes
assert diff['summary']['value_changes'] >= 3

# 7. Verify CLI diff matches GDB diff
assert cli_diff['summary']['value_changes'] == diff['summary']['value_changes']

# 8. Verify error codes in transcript
assert 'TYPE_CONVERSION_ERROR' in text and 'RANGE_ERROR' in text and 'FIELD_NOT_FOUND' in text
assert text.count('"success": true') >= 5

# 9. Verify clean process exit
assert '"status": "EXITED"' in text

print('Phase 3 GDB integration test passed')
PY
