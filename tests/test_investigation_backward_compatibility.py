"""Automated tests for Backward Compatibility of Existing CLI, API, and Schema.

Tests acceptance criterion 9:
9. Backward compatibility of existing CLI/API/schema behavior.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from extractor.agent_models import AgentAction
from extractor.agent_runtime import AgentRuntime
from extractor.semantic_state import SemanticState
from extractor.snapshot import RuntimeSnapshot
from extractor.state_corpus import StateCorpus



class TestInvestigationBackwardCompatibility(unittest.TestCase):
    """Test preservation of existing CLI, ARP protocol actions, and snapshot schemas."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="dynstate_compat_test_")
        self.corpus_dir = os.path.join(self.temp_dir, "corpus")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cli_subcommands_preserved_and_extended(self):
        """Verify all original CLI subcommands remain functional alongside new ones."""
        # 1. Main CLI help lists all commands
        proc = subprocess.run(
            [sys.executable, "-m", "extractor.cli", "--help"],
            capture_output=True,
            text=True,
            check=True,
        )
        help_output = proc.stdout
        # Original commands
        self.assertIn("capture-memory", help_output)
        self.assertIn("analyze-memory", help_output)
        self.assertIn("list-modules", help_output)
        self.assertIn("runtime-info", help_output)
        self.assertIn("extract-state", help_output)
        self.assertIn("server", help_output)
        self.assertIn("analyze", help_output)
        # New commands
        self.assertIn("investigate", help_output)
        self.assertIn("compare", help_output)

    def test_cli_investigate_and_compare_execution(self):
        """Test executing investigate and compare via CLI with JSON output."""
        corpus = StateCorpus(self.corpus_dir)
        snap_a = {
            "snapshot_id": "snap_cli_01",
            "timestamp": "2026-10-11T00:00:00Z",
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_cfg",
                        "type": "Config",
                        "address": 0x3000,
                        "fields": [{"name": "count", "type": "int", "value": 10}],
                    }
                ]
            },
            "execution": {"threads": []},
            "consistency": {"level": "STOPPED"},
        }
        snap_b = {
            "snapshot_id": "snap_cli_02",
            "timestamp": "2026-10-11T00:01:00Z",
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_cfg",
                        "type": "Config",
                        "address": 0x3000,
                        "fields": [{"name": "count", "type": "int", "value": 20}],
                    }
                ]
            },
            "execution": {"threads": []},
            "consistency": {"level": "NON_ATOMIC"},
        }
        corpus.add(snap_a)
        corpus.add(snap_b)

        # 1. CLI investigate
        inv_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "extractor.cli",
                "investigate",
                "--goal",
                "CLI verification goal",
                "--snapshot",
                "snap_cli_01",
                "--corpus",
                self.corpus_dir,
                "--json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        inv_data = json.loads(inv_proc.stdout)
        self.assertEqual(inv_data["goal"], "CLI verification goal")
        self.assertIn("findings", inv_data)
        self.assertIn("next_steps", inv_data)
        self.assertGreater(inv_data["evidence_count"], 0)


        # 2. CLI compare
        cmp_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "extractor.cli",
                "compare",
                "--snapshot-a",
                "snap_cli_01",
                "--snapshot-b",
                "snap_cli_02",
                "--corpus",
                self.corpus_dir,
                "--json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        cmp_data = json.loads(cmp_proc.stdout)
        self.assertEqual(cmp_data["summary"]["value_changes"], 1)
        self.assertIsNotNone(cmp_data["uncertainty"])

    def test_arp_existing_capabilities_and_actions_unaltered(self):
        """Verify preexisting ARP actions and capabilities remain intact."""
        runtime = AgentRuntime(corpus_dir=self.corpus_dir)

        # 1. Capabilities schema includes all preexisting blocks
        caps_res = runtime.capabilities()
        self.assertTrue(caps_res.success)
        caps = caps_res.data
        self.assertIn("runtime", caps)
        self.assertIn("observation_modes", caps)
        self.assertIn("low_impact", caps)
        self.assertIn("memory_snapshot", caps)
        self.assertIn("mutation", caps)
        self.assertIn("capture", caps)
        self.assertIn("snapshot_branch", caps)
        self.assertIn("determinism", caps)
        self.assertIn("replay", caps)
        # And the new capability is seamlessly added
        self.assertIn("investigation", caps)

        # 2. Preexisting actions continue to work
        # Add snapshot to corpus
        snap = {
            "snapshot_id": "snap_legacy_001",
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_node",
                        "type": "Node",
                        "address": 0x1000,
                        "fields": [{"name": "val", "type": "int", "value": 5}],
                    }
                ]
            },
            "execution": {"threads": []},
            "consistency": {"level": "STOPPED"},
        }
        state_id, _ = runtime.corpus.add(snap)
        lab_snap_id = runtime.state_lab.add_snapshot(SemanticState.from_snapshot(snap))

        # LIST_OBJECTS action
        act_list = AgentAction(action="LIST_OBJECTS", snapshot_id=state_id)
        res_list = runtime.dispatch_action(act_list)
        self.assertTrue(res_list.success)
        self.assertEqual(len(res_list.data), 1)
        self.assertEqual(res_list.data[0]["object_id"], "obj_node")

        # INSPECT_OBJECT action
        act_inspect = AgentAction(action="INSPECT_OBJECT", snapshot_id=state_id, object_id="obj_node")
        res_inspect = runtime.dispatch_action(act_inspect)
        self.assertTrue(res_inspect.success)
        self.assertEqual(res_inspect.data["object_id"], "obj_node")

        # STATE_HASH action
        act_hash = AgentAction(action="STATE_HASH", snapshot_id=state_id)
        res_hash = runtime.dispatch_action(act_hash)
        self.assertTrue(res_hash.success)
        self.assertIn("state_hash", res_hash.data)

        # LIST_STATES action
        act_states = AgentAction(action="LIST_STATES")
        res_states = runtime.dispatch_action(act_states)
        self.assertTrue(res_states.success)
        self.assertGreaterEqual(len(res_states.data), 1)

        # State Laboratory branch and diff
        branch_res = runtime.branch_snapshot(lab_snap_id)
        self.assertTrue(branch_res.success)
        child_snap_id = branch_res.data["snapshot_id"]

        diff_res = runtime.diff_snapshots(lab_snap_id, child_snap_id)
        self.assertTrue(diff_res.success)



    def test_schema_and_corpus_backward_compatibility(self):
        """Verify existing snapshot model (v0.3) and StateCorpus (v0.4) index formats."""
        corpus = StateCorpus(self.corpus_dir)

        # Create RuntimeSnapshot using legacy constructor
        snap = RuntimeSnapshot(
            snapshot_id="snap_v03",
            schema_version="0.3",
            process={"pid": 1001, "binary": "/bin/app"},
            persistent={"objects": []},
        )
        self.assertEqual(snap.schema_version, "0.3")

        # Add to StateCorpus
        state_id, is_new = corpus.add(snap.to_dict())
        self.assertTrue(is_new)
        self.assertIn("state_", state_id)

        # Reload corpus from disk and verify index
        reloaded_corpus = StateCorpus(self.corpus_dir)
        self.assertEqual(reloaded_corpus.get_metadata(state_id)["snapshot_id"], "snap_v03")
        loaded_snap = reloaded_corpus.get(state_id)
        self.assertEqual(loaded_snap["schema_version"], "0.3")
        self.assertEqual(loaded_snap["snapshot_id"], "snap_v03")


if __name__ == "__main__":
    unittest.main()
