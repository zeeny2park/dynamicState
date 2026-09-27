#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "$0")/.." && pwd)
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT

# 1. Build sample binary with DWARF debug symbols
g++ -g -O0 -o "$build_dir/sample" "$root_dir/examples/sample.cpp"

# 2. Run GDB Exploration Loop: breakpoint -> snapshot -> candidates -> transitions -> corpus
gdb -q -nx -batch "$build_dir/sample" \
  -ex "source $root_dir/gdb/extract_state.py" \
  -ex 'break runtime_state_checkpoint' \
  -ex 'set args 10' \
  -ex run \
  -ex "explore-state --steps 4 --corpus-dir $build_dir/corpus" > "$build_dir/transcript.txt"

# 3. Deterministic verification of State Corpus, Hashing, Interestingness, and Deduplication
python3 - "$build_dir/corpus" "$build_dir/transcript.txt" <<'PY'
import json, os, sys
from extractor.state_corpus import StateCorpus

corpus_dir = sys.argv[1]
transcript = open(sys.argv[2]).read()

corpus = StateCorpus(corpus_dir)

# 1. Verify index.json structure
index_path = os.path.join(corpus_dir, "index.json")
assert os.path.isfile(index_path), "index.json not created"
index = json.load(open(index_path))

assert index.get("schema_version") == "0.4"
assert len(index["states"]) >= 2, f"Expected at least 2 states, got {len(index['states'])}"
assert len(index["transitions"]) >= 3, f"Expected at least 3 transitions, got {len(index['transitions'])}"
assert len(index["hash_to_state"]) == len(index["states"])

# 2. Verify state directories and artifacts
for state_id, meta in index["states"].items():
    state_dir = os.path.join(corpus_dir, "states", state_id)
    assert os.path.isdir(state_dir), f"State directory missing: {state_dir}"
    assert os.path.isfile(os.path.join(state_dir, "snapshot.json"))
    assert os.path.isfile(os.path.join(state_dir, "metadata.json"))

    snap = json.load(open(os.path.join(state_dir, "snapshot.json")))
    assert snap.get("schema_version") == "0.3"
    assert "persistent" in snap and "objects" in snap["persistent"]

# 3. Verify transition artifacts
for tid in index["transitions"]:
    t_file = os.path.join(corpus_dir, "transitions", f"{tid}.json")
    assert os.path.isfile(t_file), f"Transition file missing: {t_file}"
    t_data = json.load(open(t_file))
    assert t_data.get("schema_version") == "0.3"
    trans = t_data.get("transition", t_data)
    assert trans["transition_id"] == tid

# 4. Verify Deduplication
seed_snap = corpus.get("state_000001")
assert seed_snap is not None
state_id, is_new = corpus.add(seed_snap)
assert is_new is False, "Identical snapshot should be deduplicated"
assert state_id == "state_000001"

print("Exploration integration test passed")
PY
