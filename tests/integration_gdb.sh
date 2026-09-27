#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "$0")/.." && pwd)
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
g++ -g -O0 -o "$build_dir/sample" "$root_dir/examples/sample.cpp"
gdb -q -nx -batch "$build_dir/sample" \
  -ex "source $root_dir/gdb/extract_state.py" \
  -ex 'break runtime_state_checkpoint' -ex run -ex 'extract-state --max-depth 8' > "$build_dir/state.txt"
python3 - "$build_dir/state.txt" <<'PY'
import json, sys
text = open(sys.argv[1]).read()
snapshot = json.loads(text[text.index('{'):])
frame = next(f for t in snapshot['execution']['threads'] for f in t['frames'] if f['function'] == 'process_packet')
assert frame['arguments']['session']['type'].replace(' ', '') == 'Session*'
assert any(o['type'] == 'Session' for o in snapshot['objects'])
assert snapshot['schema_version'] == '0.2'
persistent = snapshot['persistent']
assert any(root['name'] == 'global_session' and root['source'] == 'global' for root in persistent['roots'])
assert any(root['name'] == 'file_session' and root['source'] == 'global' for root in persistent['roots'])
assert any(root['name'] == 'Manager::instance' and root['source'] == 'global' for root in persistent['roots'])
assert persistent['statistics']['object_count'] == len(persistent['objects'])
assert persistent['statistics']['heap_objects'] >= 2
assert persistent['statistics']['cycles_detected'] >= 1
assert frame['locals']['local_session']['object_ref'] == frame['arguments']['session']['object_ref']
assert all(name in persistent['statistics']['performance'] for name in ('root_discovery_ms', 'traversal_ms', 'serialization_ms', 'total_ms', 'objects_per_second'))
print('GDB integration test passed')
PY
