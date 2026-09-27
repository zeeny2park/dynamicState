"""Load with: source gdb/extract_state.py"""

import os
import shlex
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_GDB_DIR = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
if _GDB_DIR not in sys.path:
    sys.path.insert(0, _GDB_DIR)

import gdb
from extractor.extract_state import snapshot
from extractor.serializer import to_json
import runtime_commands  # Registers snapshot-state, mutate-state, continue-state, diff-state.


class ExtractStateCommand(gdb.Command):
    """Print the DWARF-aware runtime state snapshot as JSON."""
    def __init__(self):
        super(ExtractStateCommand, self).__init__("extract-state", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        try:
            options = self._parse_options(arg)
        except ValueError as exc:
            raise gdb.GdbError(str(exc))
        try:
            start = time.monotonic()
            state = snapshot(gdb, max_depth=options["max_depth"],
                             include_globals=options["include_globals"])
            observed_ms = (time.monotonic() - start) * 1000
            serialization_start = time.monotonic()
            payload = to_json(state)
            serialization_ms = (time.monotonic() - serialization_start) * 1000
            state.persistent.statistics["performance"].update(
                serialization_ms=round(serialization_ms, 3),
                total_ms=round(observed_ms + serialization_ms, 3))
            payload = to_json(state)
            if options["output"]:
                with open(options["output"], "w", encoding="utf-8") as output:
                    output.write(payload + "\n")
            else:
                print(payload)
        except Exception as exc:
            raise gdb.GdbError("extract-state failed: {}".format(exc))

    @staticmethod
    def _parse_options(arg):
        tokens = shlex.split(arg)
        result = {"max_depth": None, "include_globals": True, "output": None}
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token == "--include-globals":
                result["include_globals"] = True
            elif token == "--no-globals":
                result["include_globals"] = False
            elif token in ("--max-depth", "--output"):
                index += 1
                if index == len(tokens):
                    raise ValueError("{} requires a value".format(token))
                if token == "--max-depth":
                    try:
                        value = int(tokens[index])
                    except ValueError:
                        raise ValueError("--max-depth must be a positive integer")
                    if value < 1:
                        raise ValueError("--max-depth must be a positive integer")
                    result["max_depth"] = value
                else:
                    result["output"] = tokens[index]
            else:
                raise ValueError("unknown option: {}".format(token))
            index += 1
        return result


ExtractStateCommand()
