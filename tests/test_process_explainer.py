"""Tests for process_explainer (runtime_explain_process_behavior)."""

import gzip
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor.process_explainer import explain_process_behavior  # noqa: E402

PROFILE = os.path.join(ROOT, "tests", "fixtures", "profile")


class TestProcessExplainer(unittest.TestCase):
    def test_explain_idle_server_ko(self):
        fixture_path = os.path.join(PROFILE, "ok_idle_server.json.gz")
        res = explain_process_behavior(report_path=fixture_path, language="ko")
        self.assertTrue(res["success"])
        goal = res["process_goal"]
        self.assertEqual(goal["name"], "ok_idle_server")
        self.assertEqual(goal["verdict"], "HEALTHY")
        self.assertTrue(goal["is_normal"])
        self.assertIn("네트워크 서비스", goal["category"])
        self.assertIn("ok_idle_server", goal["primary_purpose"])

        threads = res["threads"]
        self.assertEqual(len(threads), 2)
        names = {t["thread_name"] for t in threads}
        self.assertIn("acceptor", names)
        acceptor = [t for t in threads if t["thread_name"] == "acceptor"][0]
        self.assertEqual(acceptor["role"], "네트워크/이벤트 리스너")
        self.assertEqual(acceptor["state"], "waiting")
        self.assertEqual(acceptor["waits_on"]["name"], "ppoll")
        self.assertIn("ppoll", acceptor["behavior_description"])

        # Check evidence of normal operation
        ev = res["normal_operation_evidence"]
        self.assertTrue(len(ev) >= 3)
        self.assertTrue(any("HEALTHY" in e for e in ev))
        self.assertTrue(any("락 경합" in e for e in ev))

        # Check markdown content
        md = res["explanation_markdown"]
        self.assertIn("# 프로세스 분석 리포트: ok_idle_server", md)
        self.assertIn("1. 프로세스 목표 및 소프트웨어 정체성", md)
        self.assertIn("2. 쓰레드별 동작 및 역할 분석", md)
        self.assertIn("3. 정상 동작 평가 및 상태 요약", md)
        self.assertIn("정상(Normal / Healthy)", md)

    def test_explain_idle_server_en(self):
        fixture_path = os.path.join(PROFILE, "ok_idle_server.json.gz")
        res = explain_process_behavior(report_path=fixture_path, language="en")
        self.assertTrue(res["success"])
        goal = res["process_goal"]
        self.assertEqual(goal["verdict"], "HEALTHY")
        self.assertIn("Network Service", goal["category"])

        threads = res["threads"]
        acceptor = [t for t in threads if t["thread_name"] == "acceptor"][0]
        self.assertEqual(acceptor["role"], "Network / Event I/O Listener")

        md = res["explanation_markdown"]
        self.assertIn("# Process Analysis Report: ok_idle_server", md)
        self.assertIn("1. Process Goal & Software Purpose", md)
        self.assertIn("2. Thread-by-Thread Activity Analysis", md)

    def test_explain_request_threads(self):
        fixture_path = os.path.join(PROFILE, "request_threads.json.gz")
        res = explain_process_behavior(report_path=fixture_path, language="ko")
        self.assertTrue(res["success"])
        goal = res["process_goal"]
        self.assertIn("워커 프로세스", goal["category"])
        threads = res["threads"]
        req_worker = [t for t in threads if t["thread_name"] == "req_handler"][0]
        self.assertEqual(req_worker["count"], 64)
        self.assertEqual(req_worker["role"], "작업 처리 워커(Task Worker)")
        self.assertIn("handle_request", req_worker["behavior_description"])

    def test_explain_deadlock_pipeline(self):
        fixture_path = os.path.join(PROFILE, "deadlock_pipeline.json.gz")
        res = explain_process_behavior(report_path=fixture_path, language="ko")
        self.assertTrue(res["success"])
        goal = res["process_goal"]
        self.assertFalse(goal["is_normal"])
        self.assertIn("데이터 파이프라인", goal["category"])

        threads = {t["thread_name"]: t for t in res["threads"]}
        self.assertEqual(threads["ingest"]["role"], "동기화 락 대기")
        self.assertEqual(threads["flush"]["role"], "동기화 락 대기")

    def test_mcp_tool_direct_call(self):
        from scripts.mcp_server import runtime_explain_process_behavior
        fixture_path = os.path.join(PROFILE, "ok_idle_server.json.gz")
        raw = runtime_explain_process_behavior(report_path=fixture_path, language="ko")
        data = json.loads(raw)
        self.assertTrue(data["success"])
        self.assertEqual(data["process_goal"]["name"], "ok_idle_server")


if __name__ == "__main__":
    unittest.main()
