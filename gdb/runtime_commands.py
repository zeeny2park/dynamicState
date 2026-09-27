"""Phase 3 GDB command adapters; semantic logic lives in extractor/."""

import json
import shlex

import gdb

from extractor.runtime_controller import GdbRuntimeController
from extractor.snapshot import load_snapshot


_CONTROLLER = GdbRuntimeController(gdb)


def _options(arg):
    tokens, result, index = shlex.split(arg), {}, 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("--"):
            result.setdefault("_", []).append(token)
            index += 1
            continue
        index += 1
        if index == len(tokens):
            raise gdb.GdbError("{} requires a value".format(token))
        result[token[2:].replace("-", "_")] = tokens[index]
        index += 1
    return result


class SnapshotStateCommand(gdb.Command):
    def __init__(self):
        super(SnapshotStateCommand, self).__init__("snapshot-state", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        opts = _options(arg)
        identifier = (opts.get("_") or [None])[0]
        try:
            state = _CONTROLLER.snapshot(identifier, opts.get("output"),
                                         int(opts["max_depth"]) if "max_depth" in opts else None,
                                         opts.get("globals", "true") != "false")
            print(json.dumps(state.to_dict()["snapshot"], ensure_ascii=False))
        except Exception as exc:
            raise gdb.GdbError("snapshot-state failed: {}".format(exc))


class MutateStateCommand(gdb.Command):
    def __init__(self):
        super(MutateStateCommand, self).__init__("mutate-state", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        opts = _options(arg)
        obj = opts.get("object")
        field = opts.get("field")
        val = opts.get("value")
        path = opts.get("path")
        pos = opts.get("_", [])
        if not path and not obj and not field:
            if len(pos) == 2:
                path = pos[0]
                val = pos[1]
            elif len(pos) >= 3:
                obj = pos[0]
                field = pos[1]
                val = pos[2]
        elif obj and field and val is None and pos:
            val = pos[0]
        elif path and val is None and pos:
            val = pos[0]
        result = _CONTROLLER.mutate(object_id=obj, field_path=field, value=val, path=path)
        print(json.dumps(result.to_dict(), ensure_ascii=False))


class ContinueStateCommand(gdb.Command):
    def __init__(self):
        super(ContinueStateCommand, self).__init__("continue-state", gdb.COMMAND_RUNNING)

    def invoke(self, arg, from_tty):
        opts = _options(arg)
        pos = opts.get("_", [])
        timeout_str = opts.get("timeout_ms") or (pos[0] if pos else "1000")
        try:
            timeout = int(timeout_str)
        except ValueError:
            timeout = 1000
        print(json.dumps(_CONTROLLER.continue_execution(timeout).to_dict(), ensure_ascii=False))


class DiffStateCommand(gdb.Command):
    def __init__(self):
        super(DiffStateCommand, self).__init__("diff-state", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        import os
        opts = _options(arg)
        names = opts.get("_", [])
        before = _CONTROLLER.snapshots.get(names[0]) if names else None
        after = _CONTROLLER.snapshots.get(names[1]) if len(names) > 1 else None
        if before is None and names and os.path.isfile(names[0]):
            before = load_snapshot(names[0])
        if after is None and len(names) > 1 and os.path.isfile(names[1]):
            after = load_snapshot(names[1])
        before = before or (load_snapshot(opts["before"]) if "before" in opts else None)
        after = after or (load_snapshot(opts["after"]) if "after" in opts else None)
        if before is None or after is None:
            raise gdb.GdbError("diff-state requires two snapshot IDs or --before/--after paths")
        result = _CONTROLLER.diff(before, after).to_dict()
        if "output" in opts:
            with open(opts["output"], "w", encoding="utf-8") as handle:
                json.dump(result, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
        print(json.dumps(result, ensure_ascii=False))


class TransitionStateCommand(gdb.Command):
    """Execute high-level state transition: snapshot -> mutate -> continue -> snapshot -> diff."""
    def __init__(self):
        super(TransitionStateCommand, self).__init__("transition-state", gdb.COMMAND_RUNNING)

    def invoke(self, arg, from_tty):
        opts = _options(arg)
        obj = opts.get("object")
        field = opts.get("field")
        val = opts.get("value")
        path = opts.get("path")
        pos = opts.get("_", [])
        if not path and not obj and not field:
            if len(pos) == 2:
                path = pos[0]
                val = pos[1]
            elif len(pos) >= 3:
                obj = pos[0]
                field = pos[1]
                val = pos[2]
        elif obj and field and val is None and pos:
            val = pos[0]
        elif path and val is None and pos:
            val = pos[0]

        timeout_str = opts.get("timeout_ms", "1000")
        try:
            timeout_ms = int(timeout_str)
        except ValueError:
            timeout_ms = 1000

        output = opts.get("output") or opts.get("transition_output")
        transition_id = opts.get("id") or opts.get("transition_id")
        parent_id = opts.get("parent") or opts.get("parent_snapshot")
        child_id = opts.get("child") or opts.get("child_snapshot")
        snapshots_dir = opts.get("snapshots_dir")
        parent_output = opts.get("parent_output")
        child_output = opts.get("child_output")

        try:
            transition = _CONTROLLER.execute_transition(
                object_id=obj,
                field_path=field,
                value=val,
                path=path,
                timeout_ms=timeout_ms,
                transition_id=transition_id,
                output=output,
                parent_snapshot_id=parent_id,
                child_snapshot_id=child_id,
                snapshots_dir=snapshots_dir,
                parent_output=parent_output,
                child_output=child_output
            )
            print(json.dumps(transition.to_dict(), ensure_ascii=False))
        except Exception as exc:
            raise gdb.GdbError("transition-state failed: {}".format(exc))


class ExploreStateCommand(gdb.Command):
    """Run systematic state exploration loop."""
    def __init__(self):
        super(ExploreStateCommand, self).__init__("explore-state", gdb.COMMAND_RUNNING)

    def invoke(self, arg, from_tty):
        opts = _options(arg)
        steps = int(opts.get("steps", 10))
        timeout_ms = int(opts.get("timeout_ms", 1000))
        corpus_dir = opts.get("corpus_dir", "corpus")
        try:
            result = _CONTROLLER.explore(max_steps=steps, timeout_ms=timeout_ms, corpus_dir=corpus_dir)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        except Exception as exc:
            raise gdb.GdbError("explore-state failed: {}".format(exc))


class CorpusListCommand(gdb.Command):
    """List states in runtime state corpus."""
    def __init__(self):
        super(CorpusListCommand, self).__init__("corpus-list", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        from extractor.state_corpus import StateCorpus
        opts = _options(arg)
        corpus_dir = opts.get("corpus_dir", "corpus")
        corpus = StateCorpus(corpus_dir)
        print(json.dumps(corpus.list(), indent=2, ensure_ascii=False))


class CorpusShowCommand(gdb.Command):
    """Show details of a state in runtime state corpus."""
    def __init__(self):
        super(CorpusShowCommand, self).__init__("corpus-show", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        from extractor.state_corpus import StateCorpus
        opts = _options(arg)
        pos = opts.get("_", [])
        if not pos:
            raise gdb.GdbError("corpus-show requires state_id (e.g. state_000001)")
        state_id = pos[0]
        corpus_dir = opts.get("corpus_dir", "corpus")
        corpus = StateCorpus(corpus_dir)
        state_data = corpus.get(state_id)
        if state_data is None:
            raise gdb.GdbError("state not found in corpus: {}".format(state_id))
        print(json.dumps(state_data, indent=2, ensure_ascii=False))


class ProposeMutationsCommand(gdb.Command):
    """Propose mutation candidates for a snapshot."""
    def __init__(self):
        super(ProposeMutationsCommand, self).__init__("propose-mutations", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        opts = _options(arg)
        pos = opts.get("_", [])
        snap_id = pos[0] if pos else None
        snap = _CONTROLLER.snapshots.get(snap_id) if snap_id else None
        cands = _CONTROLLER.propose_mutations(snap)
        print(json.dumps([c.to_dict() for c in cands], indent=2, ensure_ascii=False))


SnapshotStateCommand()
MutateStateCommand()
ContinueStateCommand()
DiffStateCommand()
TransitionStateCommand()
ExploreStateCommand()
CorpusListCommand()
CorpusShowCommand()
ProposeMutationsCommand()
