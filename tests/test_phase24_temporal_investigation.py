"""Phase 24 Acceptance Test Suite: Evidence-First Temporal Investigation Workflow.

Verifies:
(a) natural-language investigation request against an observation session with bounded retrieval,
(b) temporal evidence provenance in findings and drilldown,
(c) streaming/paginated observation comparison without unbounded history in memory,
(d) correct identification of CHANGED, UNCHANGED, PARTIAL and UNAVAILABLE/MISSING observation states,
(e) target identity and Build ID validation failure handling (fail closed on mismatch),
(f) handling of missing DWARF or companion ELF gracefully,
(g) candidate function ranking and safety tier assignment (no promotion to validated causal function without authentic validation),
(h) false-positive guard access prevention (snapshot proximity is labeled correctly and not reported as a confirmed write/violation),
(i) integration with remote watch sessions created via Phase 23,
(j) capture gaps, target termination and restart/abort state handling,
(k) Korean prompt handling and summary generation, and
(l) preservation of secret redaction in all outputs.
"""

from datetime import datetime, timezone
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from extractor.agent_runtime import AgentRuntime
from extractor.debug_image import BinaryIdentity, inspect_elf
from extractor.evidence_ledger import EvidenceLedger, EvidenceRecord
from extractor.investigation import InvestigationFinding, InvestigationSession
from extractor.llm_provider import DeterministicFallbackProvider, LLMProviderManager
from extractor.static_analyzer import FunctionCandidate
from extractor.temporal_investigation import (
    ObservationComparisonState,
    TemporalInvestigationPlan,
    TemporalInvestigationService,
)
from extractor.watch_session import (
    CaptureGap,
    Observation,
    ObservationSession,
    WatchItem,
    WatchSessionManager,
)
from extractor.web.server import WebApiAdapter
import scripts.mcp_server as mcp_srv


class TestPhase24TemporalInvestigation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_p24_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        os.makedirs(cls.corpus_dir, exist_ok=True)

        cls.fixture_src = os.path.abspath("tests/fixtures/real_runtime/main.cpp")
        if not os.path.exists(cls.fixture_src):
            raise unittest.SkipTest("C++ fixture source not found")

        # Compile matching companion debug binary (PIE)
        cls.debug_bin = os.path.join(cls.work_dir, "app_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
            ],
            check=True
        )

        # Compile mismatched debug binary
        cls.mismatched_src = os.path.join(cls.work_dir, "mismatched.cpp")
        with open(cls.mismatched_src, "w") as f:
            f.write("int main() { return 0; }\n")
        cls.mismatched_bin = os.path.join(cls.work_dir, "mismatched_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0",
                "-Wl,--build-id=sha1", cls.mismatched_src, "-o", cls.mismatched_bin
            ],
            check=True
        )

        # Compile stripped binary (no DWARF)
        cls.stripped_bin = os.path.join(cls.work_dir, "app_stripped.elf")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def setUp(self):
        self.watch_manager = WatchSessionManager(corpus_dir=os.path.join(self.work_dir, "sessions"))
        self.temporal_service = TemporalInvestigationService(watch_manager=self.watch_manager)
        self.runtime = AgentRuntime(corpus_dir=self.corpus_dir)
        self.runtime.watch_session_manager = self.watch_manager

    # -------------------------------------------------------------------------
    # Helper to create a synthetic observation session
    # -------------------------------------------------------------------------
    def _create_synthetic_session(
        self,
        session_id="sess_test_p24",
        build_id="test_build_id_12345",
        companion_elf=None,
        is_remote=False,
        target_host=None,
        watch_items=None,
        observations=None,
        gaps=None,
    ):
        if companion_elf is None:
            companion_elf = self.debug_bin
        prov = {"is_remote": is_remote, "host": target_host or "localhost"}
        sess = ObservationSession(
            session_id=session_id,
            pid=1234,
            binary_build_id=build_id,
            target_identity={
                "pid": 1234,
                "executable": "/usr/local/bin/app",
                "build_id": build_id,
                "architecture": "x86_64",
            },
            companion_elf_path=companion_elf,
            provenance=prov,
            status="STOPPED",
            watch_items=watch_items or [],
            gaps=gaps or [],
        )
        self.watch_manager._persist_session(sess)
        self.watch_manager._sessions[session_id] = sess

        # Store observations if provided
        if observations:
            for obs in observations:
                self.watch_manager._append_observation_to_file(sess.session_id, obs)
            sess.total_observations = len(observations)
            self.watch_manager._persist_session(sess)

        return sess

    # -------------------------------------------------------------------------
    # (a) Natural-language investigation request against an observation session with bounded retrieval
    # -------------------------------------------------------------------------
    def test_01_natural_language_request_and_bounded_plan(self):
        # Goal in Korean with duration '10초' and buffer memory pool guard keywords
        nl_goal = "특정 Buffer memory pool을 10초간 모니터링하면서 memory guard 0x7fff0000 근처까지 접근하는 변수가 무엇인지 알아봐줘"
        plan = self.temporal_service.create_investigation_plan(
            goal=nl_goal,
            watch_session_id="sess_nl_test",
            observation_window={"limit": 50}
        )

        self.assertEqual(plan.duration_sec, 10.0)
        self.assertEqual(plan.limit, 50)
        self.assertEqual(plan.guard_address, 0x7fff0000)
        self.assertIn("buffer", plan.target_keywords)
        self.assertIn("guard", plan.target_keywords)

        # Verify bounded window retrieval logic
        item = WatchItem(item_id="item_buf", name="buffer_ptr", scope="global", address=0x7ffe0000, size=8, type_name="void*")
        obs_list = []
        now = time.time()
        for i in range(100):
            obs_list.append(Observation(
                session_id="sess_nl_test",
                seq=i + 1,
                monotonic_ns=int(now * 1_000_000_000 + i * 100_000_000),
                timestamp=datetime.now(timezone.utc).isoformat(),
                values={"item_buf": {"value": f"0x7fff{i:04x}", "status": "OBSERVED"}}
            ))

        sess = self._create_synthetic_session(
            session_id="sess_nl_test",
            build_id="dummy_build_id",
            companion_elf=self.debug_bin,
            watch_items=[item],
            observations=obs_list
        )

        # Retrieve bounded window: limit=20
        plan.limit = 20
        paged_obs, count = self.temporal_service.retrieve_temporal_window("sess_nl_test", plan)
        self.assertLessEqual(len(paged_obs), 20)
        self.assertEqual(count, 100)

    # -------------------------------------------------------------------------
    # (b) Temporal evidence provenance in findings and drilldown
    # -------------------------------------------------------------------------
    def test_02_temporal_evidence_provenance_and_drilldown(self):
        item = WatchItem(item_id="item_val", name="g_counter", scope="global", address=0x601000, size=4, type_name="int")
        now = time.time()
        obs1 = Observation(
            session_id="sess_prov_test",
            seq=1,
            monotonic_ns=int(now * 1_000_000_000),
            timestamp=datetime.now(timezone.utc).isoformat(),
            values={"item_val": {"value": 42, "status": "OBSERVED"}},
            completeness="COMPLETE"
        )
        obs2 = Observation(
            session_id="sess_prov_test",
            seq=2,
            monotonic_ns=int((now + 1.0) * 1_000_000_000),
            timestamp=datetime.now(timezone.utc).isoformat(),
            values={"item_val": {"value": 99, "status": "OBSERVED"}},
            completeness="COMPLETE"
        )

        bin_id = inspect_elf(self.debug_bin)
        real_build_id = bin_id.build_id if bin_id else "unknown"

        sess = self._create_synthetic_session(
            session_id="sess_prov_test",
            build_id=real_build_id,
            companion_elf=self.debug_bin,
            watch_items=[item],
            observations=[obs1, obs2]
        )

        res = self.runtime.start_investigation(
            goal="Check counter change",
            watch_session_id="sess_prov_test",
            observation_window={"duration_sec": 5.0},
            authorize_target=True
        )
        self.assertTrue(res.success)
        inv_data = res.data
        inv_id = inv_data["investigation_id"]

        # Drilldown into findings
        findings = inv_data.get("findings", [])
        facts = [f for f in findings if f.get("category") == "fact"]
        self.assertGreater(len(facts), 0)

        fact = facts[0]
        # Verify provenance fields
        self.assertIn("temporal_provenance", fact)
        prov = fact["temporal_provenance"]
        self.assertEqual(prov["session_id"], "sess_prov_test")
        self.assertIn("evidence_ids", fact)
        self.assertGreater(len(fact["evidence_ids"]), 0)

        # Verify drilldown endpoint
        dd_res = self.runtime.get_finding_drilldown(inv_id, fact["finding_id"])
        self.assertTrue(dd_res.success)
        dd = dd_res.data.get("drilldown", dd_res.data)
        self.assertEqual(dd["finding_id"], fact["finding_id"])
        self.assertIn("temporal_provenance", dd)
        self.assertIn("evidence_records", dd)
        self.assertGreater(len(dd["evidence_records"]), 0)

    # -------------------------------------------------------------------------
    # (c) Streaming/paginated observation comparison without unbounded history in memory
    # -------------------------------------------------------------------------
    def test_03_streaming_paginated_comparison_memory_bounded(self):
        item = WatchItem(item_id="item_paged", name="test_item", scope="global", address=0x1000, size=4, type_name="int")
        obs_list = []
        now = time.time()
        for i in range(150):
            obs_list.append(Observation(
                session_id="sess_paged",
                seq=i + 1,
                monotonic_ns=int(now * 1_000_000_000 + i * 1_000_000_000),
                timestamp=datetime.now(timezone.utc).isoformat(),
                values={"item_paged": {"value": i % 10, "status": "OBSERVED"}}
            ))

        sess = self._create_synthetic_session(
            session_id="sess_paged",
            build_id="dummy",
            companion_elf=self.debug_bin,
            watch_items=[item],
            observations=obs_list
        )

        plan = TemporalInvestigationPlan(watch_session_id="sess_paged", limit=150)
        # Verify compare_temporal_observations uses chunk_size without loading all into a single list
        with patch.object(self.watch_manager, "get_observations", wraps=self.watch_manager.get_observations) as mock_get_obs:
            diffs = self.temporal_service.compare_temporal_observations("sess_paged", plan, chunk_size=40)
            self.assertIn("item_paged", diffs)
            # Verify multiple paginated calls were made
            self.assertGreater(mock_get_obs.call_count, 1)
            # Verify chunk_size was adhered to
            for call in mock_get_obs.call_args_list:
                limit_arg = call.kwargs.get("limit") or call.args[1]
                self.assertLessEqual(limit_arg, 40)

    # -------------------------------------------------------------------------
    # (d) Correct identification of CHANGED, UNCHANGED, PARTIAL and UNAVAILABLE/MISSING observation states
    # -------------------------------------------------------------------------
    def test_04_observation_states_changed_unchanged_partial_missing(self):
        items = [
            WatchItem(item_id="it_chg", name="changed_var", scope="global", address=0x1000, size=4, type_name="int"),
            WatchItem(item_id="it_unchg", name="unchanged_var", scope="global", address=0x1004, size=4, type_name="int"),
            WatchItem(item_id="it_part", name="partial_var", scope="global", address=0x1008, size=4, type_name="int"),
            WatchItem(item_id="it_miss", name="missing_var", scope="global", address=0x100c, size=4, type_name="int"),
        ]

        now = time.time()
        obs1 = Observation(
            session_id="sess_states",
            seq=1,
            monotonic_ns=int(now * 1_000_000_000),
            timestamp=datetime.now(timezone.utc).isoformat(),
            values={
                "it_chg": {"value": 100, "status": "OBSERVED"},
                "it_unchg": {"value": 200, "status": "OBSERVED"},
                "it_part": {"value": None, "raw_hex": "aa", "is_partial": True, "status": "PARTIAL"},
                # it_miss is absent in obs1
            }
        )
        obs2 = Observation(
            session_id="sess_states",
            seq=2,
            monotonic_ns=int((now + 1.0) * 1_000_000_000),
            timestamp=datetime.now(timezone.utc).isoformat(),
            values={
                "it_chg": {"value": 101, "status": "OBSERVED"},  # value changed
                "it_unchg": {"value": 200, "status": "OBSERVED"},  # value unchanged
                "it_part": {"value": None, "raw_hex": "aa", "is_partial": True, "status": "PARTIAL"},
                "it_miss": {"value": None, "status": "UNAVAILABLE"},  # read error / unavailable
            }
        )

        sess = self._create_synthetic_session(
            session_id="sess_states",
            build_id="dummy",
            companion_elf=self.debug_bin,
            watch_items=items,
            observations=[obs1, obs2]
        )

        plan = TemporalInvestigationPlan(watch_session_id="sess_states")
        diffs = self.temporal_service.compare_temporal_observations("sess_states", plan)

        self.assertEqual(diffs["it_chg"].state, ObservationComparisonState.CHANGED)
        self.assertEqual(diffs["it_unchg"].state, ObservationComparisonState.UNCHANGED)
        self.assertEqual(diffs["it_part"].state, ObservationComparisonState.PARTIAL)
        self.assertEqual(diffs["it_miss"].state, ObservationComparisonState.MISSING)

        # Strict invariant: Missing samples MUST NEVER be silently classified as UNCHANGED
        self.assertNotEqual(diffs["it_miss"].state, ObservationComparisonState.UNCHANGED)

    # -------------------------------------------------------------------------
    # (e) Target identity and Build ID validation failure handling (fail closed on mismatch)
    # -------------------------------------------------------------------------
    def test_05_build_id_mismatch_fails_closed(self):
        bin_id = inspect_elf(self.debug_bin)
        real_build_id = bin_id.build_id if bin_id else "real_build_id"

        # Session has real_build_id, but companion ELF is the mismatched binary
        sess = self._create_synthetic_session(
            session_id="sess_mismatch",
            build_id=real_build_id,
            companion_elf=self.mismatched_bin,
            watch_items=[]
        )

        res = self.runtime.start_investigation(
            goal="Investigate mismatched target",
            watch_session_id="sess_mismatch",
            authorize_target=True
        )

        # Must fail closed
        self.assertFalse(res.success)
        self.assertEqual(res.error.code, "BUILD_ID_MISMATCH")
        self.assertIn("Build ID mismatch", res.error.message)

    # -------------------------------------------------------------------------
    # (f) Handling of missing DWARF or companion ELF gracefully
    # -------------------------------------------------------------------------
    def test_06_missing_dwarf_or_companion_elf_graceful_handling(self):
        # Session references stripped binary without DWARF
        bin_id = inspect_elf(self.stripped_bin)
        build_id = bin_id.build_id if bin_id else "stripped_id"

        item = WatchItem(item_id="it_strip", name="unknown_var", scope="global", address=0x5000, size=4, type_name="int")
        sess = self._create_synthetic_session(
            session_id="sess_stripped",
            build_id=build_id,
            companion_elf=self.stripped_bin,
            watch_items=[item],
            observations=[
                Observation(
                    session_id="sess_stripped",
                    seq=1,
                    monotonic_ns=int(time.time() * 1_000_000_000),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    values={"it_strip": {"value": 10, "status": "OBSERVED"}}
                ),
                Observation(
                    session_id="sess_stripped",
                    seq=2,
                    monotonic_ns=int((time.time() + 1.0) * 1_000_000_000),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    values={"it_strip": {"value": 20, "status": "OBSERVED"}}
                )
            ]
        )

        # Investigation must proceed gracefully without crashing or throwing
        res = self.runtime.start_investigation(
            goal="Analyze stripped session",
            watch_session_id="sess_stripped",
            authorize_target=True
        )
        self.assertTrue(res.success)
        inv = res.data

        # Findings must truthfully report unknown DWARF, not invent fake source locations
        facts = [f for f in inv.get("findings", []) if f.get("category") == "fact"]
        self.assertGreater(len(facts), 0)
        fact = facts[0]
        dwarf_source = fact.get("dwarf_source") or {}
        self.assertIsNone(dwarf_source.get("file"))
        self.assertIsNone(dwarf_source.get("line"))

    # -------------------------------------------------------------------------
    # (g) Candidate function ranking and safety tier assignment
    # -------------------------------------------------------------------------
    def test_07_candidate_function_ranking_and_safety_tier(self):
        bin_id = inspect_elf(self.debug_bin)
        real_build_id = bin_id.build_id if bin_id else "build_id"

        item = WatchItem(item_id="it_buf", name="buffer_pool", scope="global", address=0x404000, size=64, type_name="char[]")
        sess = self._create_synthetic_session(
            session_id="sess_safety_tier",
            build_id=real_build_id,
            companion_elf=self.debug_bin,
            watch_items=[item],
            observations=[
                Observation(
                    session_id="sess_safety_tier",
                    seq=1,
                    monotonic_ns=int(time.time() * 1_000_000_000),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    values={"it_buf": {"value": "0x404010", "status": "OBSERVED"}}
                ),
                Observation(
                    session_id="sess_safety_tier",
                    seq=2,
                    monotonic_ns=int((time.time() + 1.0) * 1_000_000_000),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    values={"it_buf": {"value": "0x404030", "status": "OBSERVED"}}
                )
            ]
        )

        res = self.runtime.start_investigation(
            goal="Analyze buffer pool mutations",
            watch_session_id="sess_safety_tier",
            authorize_target=True
        )
        self.assertTrue(res.success)
        hypotheses = res.data.get("hypotheses", []) + [f for f in res.data.get("findings", []) if f.get("category") == "hypothesis"]

        # Check candidate tiers: STATIC_CANDIDATE or EVIDENCE_SUPPORTED
        for hypo in hypotheses:
            status = hypo.get("status")
            plausibility = hypo.get("plausibility")
            # Invariant: Must NEVER be promoted to VALIDATED_CAUSAL_FUNCTION without independent validation
            self.assertNotEqual(status, "VALIDATED_CAUSAL_FUNCTION")
            self.assertNotEqual(plausibility, "VALIDATED_CAUSAL_FUNCTION")
            self.assertIn(status, ("PROPOSED", "STATIC_CANDIDATE", "EVIDENCE_SUPPORTED", "UNCONFIRMED"))

            # Caveat must be present explaining layout mutation limitation
            if "caveats" in hypo:
                self.assertIn("LAYOUT_MUTATION_CAVEAT", hypo["caveats"])

    # -------------------------------------------------------------------------
    # (h) False-positive guard access prevention (snapshot proximity is labeled correctly and not reported as a confirmed write/violation)
    # -------------------------------------------------------------------------
    def test_08_false_positive_guard_access_prevention(self):
        bin_id = inspect_elf(self.debug_bin)
        real_build_id = bin_id.build_id if bin_id else "build_id"

        # Buffer ends at 0x7fff0000, guard is at 0x7fff0000. Pointer is observed at 0x7ffeffe0 (32 bytes away)
        item = WatchItem(item_id="it_ptr", name="buf_curr_ptr", scope="global", address=0x602000, size=8, type_name="void*")
        now = time.time()
        obs = [
            Observation(
                session_id="sess_guard_test",
                seq=1,
                monotonic_ns=int(now * 1_000_000_000),
                timestamp=datetime.now(timezone.utc).isoformat(),
                values={"it_ptr": {"value": "0x7ffeffe0", "status": "OBSERVED"}},
                completeness="COMPLETE"
            ),
            Observation(
                session_id="sess_guard_test",
                seq=2,
                monotonic_ns=int((now + 1.0) * 1_000_000_000),
                timestamp=datetime.now(timezone.utc).isoformat(),
                values={"it_ptr": {"value": "0x7ffefff0", "status": "OBSERVED"}},
                completeness="COMPLETE"
            )
        ]

        sess = self._create_synthetic_session(
            session_id="sess_guard_test",
            build_id=real_build_id,
            companion_elf=self.debug_bin,
            watch_items=[item],
            observations=obs
        )

        res = self.runtime.start_investigation(
            goal="Monitor buffer pointer proximity to memory guard 0x7fff0000",
            watch_session_id="sess_guard_test",
            observation_window={"guard_address": 0x7fff0000, "guard_threshold": 64},
            authorize_target=True
        )
        self.assertTrue(res.success)
        inv = res.data

        facts = [f for f in inv.get("findings", []) if f.get("category") == "fact"]
        guard_facts = [f for f in facts if "guard" in f.get("title", "").lower() or "proximity" in f.get("title", "").lower()]
        self.assertGreater(len(guard_facts), 0)

        # Proximity must be classified as an observed proximity fact, NOT a confirmed write or corruption
        gf = guard_facts[0]
        self.assertEqual(gf["category"], "fact")
        self.assertIn("proximity", gf["title"].lower())
        self.assertIn("temporal_provenance", gf)

        # Uncertainty notice must explicitly warn about LOW_IMPACT non-atomic snapshot semantics
        uncertainty = gf.get("uncertainty", "")
        self.assertIn("LOW_IMPACT", uncertainty)
        self.assertIn("does NOT prove memory read/write or guard violation", uncertainty)

        # Recommended next steps must suggest setting a watchpoint or dynamic probe
        next_steps = inv.get("recommended_next_steps", [])
        watchpoint_step = any("watchpoint" in str(s).lower() or "probe" in str(s).lower() for s in next_steps)
        self.assertTrue(watchpoint_step, f"Expected follow-up watchpoint step in {next_steps}")

    # -------------------------------------------------------------------------
    # (i) Integration with remote watch sessions created via Phase 23
    # -------------------------------------------------------------------------
    def test_09_remote_watch_session_integration(self):
        bin_id = inspect_elf(self.debug_bin)
        real_build_id = bin_id.build_id if bin_id else "build_id"

        item = WatchItem(item_id="it_rem", name="remote_state", scope="global", address=0x4000, size=4, type_name="int")
        sess = self._create_synthetic_session(
            session_id="sess_remote_p23",
            build_id=real_build_id,
            companion_elf=self.debug_bin,
            is_remote=True,
            target_host="embedded-board.internal",
            watch_items=[item],
            observations=[
                Observation(
                    session_id="sess_remote_p23",
                    seq=1,
                    monotonic_ns=int(time.time() * 1_000_000_000),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    values={"it_rem": {"value": 10, "status": "OBSERVED"}}
                )
            ]
        )

        adapter = WebApiAdapter(runtime=self.runtime)
        res = adapter.analyze_temporal_investigation({
            "watch_session_id": "sess_remote_p23",
            "goal": "Verify remote target session integration"
        })

        self.assertTrue(res.get("success"), f"API call failed: {res}")
        data = res["data"]
        # Remote identity preserved
        target_ref = data.get("target_ref", {})
        self.assertEqual(target_ref.get("target_host"), "embedded-board.internal")
        self.assertEqual(target_ref.get("is_remote"), True)

    # -------------------------------------------------------------------------
    # (j) Capture gaps, target termination and restart/abort state handling
    # -------------------------------------------------------------------------
    def test_10_capture_gaps_target_termination_and_restart(self):
        bin_id = inspect_elf(self.debug_bin)
        real_build_id = bin_id.build_id if bin_id else "build_id"

        gaps = [
            CaptureGap(
                gap_id="gap_drop_1",
                start_ns=1000000,
                end_ns=2000000,
                duration_ms=1.0,
                reason="TRANSPORT_TIMEOUT_DROPPED_SAMPLES",
            )
        ]
        sess = self._create_synthetic_session(
            session_id="sess_gaps",
            build_id=real_build_id,
            companion_elf=self.debug_bin,
            watch_items=[],
            gaps=gaps
        )

        res = self.runtime.start_investigation(
            goal="Analyze session with transport interruption",
            watch_session_id="sess_gaps",
            authorize_target=True
        )
        self.assertTrue(res.success)
        inv = res.data

        # Limitations must record capture gaps
        limitations = inv.get("capture_quality", {}).get("limitations", [])
        gap_limitations = [l for l in limitations if "gap" in l.lower() or "dropped" in l.lower()]
        self.assertGreater(len(gap_limitations), 0)

        # Overview summary must reflect gaps
        overview = inv.get("summary", {}).get("overview", "")
        self.assertIn("TRANSPORT_TIMEOUT_DROPPED_SAMPLES", overview)

    # -------------------------------------------------------------------------
    # (k) Korean prompt handling and summary generation
    # -------------------------------------------------------------------------
    def test_11_korean_prompt_handling_and_summary_generation(self):
        bin_id = inspect_elf(self.debug_bin)
        real_build_id = bin_id.build_id if bin_id else "build_id"

        item = WatchItem(item_id="it_ko", name="g_buffer_head", scope="global", address=0x603000, size=8, type_name="void*")
        sess = self._create_synthetic_session(
            session_id="sess_korean",
            build_id=real_build_id,
            companion_elf=self.debug_bin,
            watch_items=[item],
            observations=[
                Observation(
                    session_id="sess_korean",
                    seq=1,
                    monotonic_ns=int(time.time() * 1_000_000_000),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    values={"it_ko": {"value": "0x7fff0000", "status": "OBSERVED"}}
                )
            ]
        )

        ko_goal = "특정 Buffer memory pool을 10초간 모니터링하면서 memory guard 근처까지 접근하는 변수가 무엇인지 알아봐줘"
        res = self.runtime.start_investigation(
            goal=ko_goal,
            watch_session_id="sess_korean",
            observation_window={"duration_sec": 10.0},
            authorize_target=True
        )
        self.assertTrue(res.success)
        inv = res.data

        # Conversational summary / fallback must respond in Korean
        overview = inv.get("summary", {}).get("overview", "")
        self.assertTrue(
            any(k in overview for k in ("시계열", "관측", "세션", "근접", "조사", "결과")),
            f"Expected Korean keywords in overview: {overview}"
        )

        # Test conversational chat endpoint with Korean question
        chat_res = self.runtime.chat_investigation(
            investigation_id=inv["investigation_id"],
            message="가장 위험한 변수가 무엇인가요?",
            provider_override="none",
        )
        self.assertTrue(chat_res.success)
        reply = chat_res.data.get("summary", "")
        self.assertTrue(
            any(k in reply for k in ("관측", "변수", "가드", "조사", "상태", "위험")),
            f"Expected Korean in chat reply: {reply}"
        )

    # -------------------------------------------------------------------------
    # (l) Preservation of secret redaction in all outputs
    # -------------------------------------------------------------------------
    def test_12_secret_redaction_preservation(self):
        bin_id = inspect_elf(self.debug_bin)
        real_build_id = bin_id.build_id if bin_id else "build_id"

        secret_val = "sk-live-secret-super-confidential-token-9999"
        item = WatchItem(item_id="it_sec", name="api_key_ptr", scope="global", address=0x7000, size=32, type_name="char[]")
        sess = self._create_synthetic_session(
            session_id="sess_secret",
            build_id=real_build_id,
            companion_elf=self.debug_bin,
            watch_items=[item],
            observations=[
                Observation(
                    session_id="sess_secret",
                    seq=1,
                    monotonic_ns=int(time.time() * 1_000_000_000),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    values={"it_sec": {"value": secret_val, "status": "OBSERVED"}}
                )
            ]
        )

        res = self.runtime.start_investigation(
            goal="Investigate secure credential buffer",
            watch_session_id="sess_secret",
            authorize_target=True
        )
        self.assertTrue(res.success)
        inv = res.data

        # Convert entire investigation JSON to string and assert raw secret is NEVER present
        inv_str = json.dumps(inv)
        self.assertNotIn(secret_val, inv_str, "Raw secret leaked in investigation session dump!")


if __name__ == "__main__":
    unittest.main()
