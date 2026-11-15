"""Tests for Process Explainer Input Immutability and Grounding (US-EXPLAIN-001 / FR-EXPLAIN-001)."""

import copy
import json
import pytest
from extractor.process_explainer import explain_process_behavior


def test_explain_process_behavior_preserves_input_immutability():
    """Verify input report dictionary is not mutated in any way."""
    original_report = {
        "verdict": "HEALTHY",
        "process_name": "test_app",
        "pid": 1234,
        "target": {"process_name": "test_app", "pid": 1234},
        "report": {
            "section_b_target_context": {
                "target": {"process_name": "test_app", "pid": 1234}
            },
            "threads": {
                "rows": [
                    {
                        "thread_id": 1234,
                        "name": "worker",
                        "state": "running",
                        "role": "worker",
                    }
                ]
            },
            "evidence_ledger": [
                {"evidence_id": "ev_001", "observation": "All threads responsive"}
            ],
        },
    }

    report_clone = copy.deepcopy(original_report)
    res = explain_process_behavior(report_dict=original_report, language="en")

    assert res["success"] is True
    # Verify exact equality of original_report and its untouched pre-execution clone
    assert original_report == report_clone


def test_referenced_evidence_ids_in_explanation_are_valid():
    """Verify explanation output includes validated referenced evidence IDs."""
    report = {
        "verdict": "HEALTHY",
        "process_name": "test_app",
        "pid": 1234,
        "report": {
            "threads": {"rows": [{"name": "main", "state": "running"}]},
            "evidence_ledger": [
                {"evidence_id": "ev_101", "observation": "Memory healthy"},
                {"evidence_id": "ev_102", "observation": "No deadlocks"},
            ],
        },
    }

    res = explain_process_behavior(report_dict=report, language="en")
    assert res["success"] is True
    assert "referenced_evidence_ids" in res
    assert isinstance(res["referenced_evidence_ids"], list)
    # Any referenced ID must be in the original ledger
    valid_ids = {"ev_101", "ev_102"}
    for eid in res["referenced_evidence_ids"]:
        assert eid in valid_ids
