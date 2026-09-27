"""Stable JSON serialization for RuntimeState."""

import json


def to_json(runtime_state, indent=2):
    return json.dumps(runtime_state.to_dict(), indent=indent, sort_keys=False, ensure_ascii=False, default=str)
