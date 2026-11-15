"""Tests for MCP explain tool contracts and error safety (FR-MCP-001 ~ 003)."""

import json
import pytest
from scripts.mcp_server import runtime_explain_process_behavior


def test_mcp_tool_returns_error_json_on_invalid_input():
    """Verify tool returns structured JSON error when no valid input provided."""
    raw = runtime_explain_process_behavior()
    data = json.loads(raw)
    assert data["success"] is False
    assert "error" in data


def test_mcp_tool_with_valid_report_data():
    """Verify tool handles in-memory report data correctly."""
    report = {
        "verdict": "HEALTHY",
        "process_name": "worker_pool",
        "pid": 5678,
        "report": {
            "threads": {"rows": [{"name": "worker_1", "state": "running"}]},
            "evidence_ledger": [],
        },
    }
    raw = runtime_explain_process_behavior(report_data=report, language="ko")
    data = json.loads(raw)
    assert data["success"] is True
    assert "process_goal" in data
