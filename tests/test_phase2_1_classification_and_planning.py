"""Phase 2.1 — Problem Classification and Investigation Planning Tests.

Verifies:
1. Bilingual (English and Korean) natural language problem classification across all 12 categories.
2. Entity extraction: functions, variables, threads, addresses, error codes, and symptoms.
3. Vague query detection and broad multi-domain screening strategy generation.
4. Target assessment: process accessibility, thread count, RSS, and DWARF capability detection.
5. Multi-factor investigation planning and deterministic step ranking.
"""

import os
import unittest

from extractor.diagnostic_recipes import (
    CATEGORY_ABNORMAL_VARIABLE_CHANGES,
    CATEGORY_DATA_RACE_INDICATORS,
    CATEGORY_DEADLOCK_INDICATORS,
    CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY,
    CATEGORY_INVALID_DOUBLE_FREE,
    CATEGORY_MEMORY_CORRUPTION,
    CATEGORY_MEMORY_LEAK,
    CATEGORY_PROCESS_INSTABILITY,
    CATEGORY_RESOURCE_EXHAUSTION,
    CATEGORY_STACK_CORRUPTION,
    CATEGORY_UNEXPECTED_STATE_TRANSITIONS,
    CATEGORY_USE_AFTER_FREE,
)
from extractor.expert_diagnostic_engine import (
    InvestigationPlanner,
    ProblemClassifier,
    TargetAssessor,
)


class TestPhase21ClassificationAndPlanning(unittest.TestCase):
    """Test suite for Stage A classification and Stage C planning."""

    def setUp(self):
        self.classifier = ProblemClassifier()
        self.assessor = TargetAssessor()
        self.planner = InvestigationPlanner()

    def test_bilingual_classification_all_12_categories(self):
        """Verifies natural language classification for all 12 problem categories in EN and KO."""
        test_cases = [
            # 1. MEMORY_CORRUPTION
            ("Worker thread crashed with SIGSEGV due to corrupted memory at 0x7fff0000", CATEGORY_MEMORY_CORRUPTION),
            ("포인터가 깨져서 세그폴트 메모리 오염이 발생했습니다", CATEGORY_MEMORY_CORRUPTION),
            # 2. MEMORY_LEAK
            ("Process RSS growth and heap leak detected in unbounded buffer accumulation", CATEGORY_MEMORY_LEAK),
            ("메모리가 계속 늘어나고 힙 누수가 발생하는 것 같아요", CATEGORY_MEMORY_LEAK),
            # 3. INVALID_DOUBLE_FREE
            ("Fatal error: double free detected in buffer deallocation routine", CATEGORY_INVALID_DOUBLE_FREE),
            ("동일한 포인터에 대해 이중 해제 더블 프리가 감지되었습니다", CATEGORY_INVALID_DOUBLE_FREE),
            # 4. USE_AFTER_FREE
            ("Dangling pointer dereference and use after free in job completion", CATEGORY_USE_AFTER_FREE),
            ("이미 해제된 메모리 접근으로 인한 유즈 애프터 프리 의심", CATEGORY_USE_AFTER_FREE),
            # 5. STACK_CORRUPTION
            ("Stack smashing detected: return address clobbered by buffer overflow", CATEGORY_STACK_CORRUPTION),
            ("스택 카나리 파괴 및 스택 손상 이상 현상", CATEGORY_STACK_CORRUPTION),
            # 6. DATA_RACE_INDICATORS
            ("Data race indicators: concurrent write without lock on shared counter", CATEGORY_DATA_RACE_INDICATORS),
            ("스레드 간 락 없이 동시 접근하여 발생하는 데이터 레이스 의심", CATEGORY_DATA_RACE_INDICATORS),
            # 7. DEADLOCK_INDICATORS
            ("Process hung: circular wait deadlock detected between worker threads", CATEGORY_DEADLOCK_INDICATORS),
            ("스레드가 락을 잡고 멈췄어요 교착 상태 데드락인 것 같습니다", CATEGORY_DEADLOCK_INDICATORS),
            # 8. ABNORMAL_VARIABLE_CHANGES
            ("Abnormal variable jump: counter changed suddenly to unexpected value", CATEGORY_ABNORMAL_VARIABLE_CHANGES),
            ("변수 값이 갑자기 엉뚱한 값으로 튀는 비정상 변경", CATEGORY_ABNORMAL_VARIABLE_CHANGES),
            # 9. UNEXPECTED_STATE_TRANSITIONS
            ("State machine bug: illegal transition to unexpected state", CATEGORY_UNEXPECTED_STATE_TRANSITIONS),
            ("상태 머신에서 유효하지 않은 불법 전이가 발생했습니다", CATEGORY_UNEXPECTED_STATE_TRANSITIONS),
            # 10. RESOURCE_EXHAUSTION
            ("Resource exhaustion: out of file descriptors and socket limits", CATEGORY_RESOURCE_EXHAUSTION),
            ("파일 디스크립터 누수로 인한 fd 자원 고갈 현상", CATEGORY_RESOURCE_EXHAUSTION),
            # 11. PROCESS_INSTABILITY
            ("Process instability: frequent restart and crash flapping", CATEGORY_PROCESS_INSTABILITY),
            ("프로세스가 자주 죽고 재부팅을 반복하는 불안정한 상태", CATEGORY_PROCESS_INSTABILITY),
            # 12. FUNCTIONAL_STATE_INCONSISTENCY
            ("Functional state inconsistency: internal invariant violated in cache buffer", CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY),
            ("버퍼 내부 상태 모순 및 데이터 정합성 깨짐 불변식 위반", CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY),
        ]

        for query, expected_cat in test_cases:
            res = self.classifier.classify(query)
            self.assertEqual(
                res.primary_category,
                expected_cat,
                f"Failed classification for query: '{query}' -> got {res.primary_category}, expected {expected_cat}",
            )
            self.assertGreaterEqual(res.confidence, 0.40)
            self.assertFalse(res.is_vague)

    def test_entity_extraction(self):
        """Verifies extraction of addresses, threads, functions, variables, and error codes."""
        query = (
            "Thread tid 1042 running Worker::execute_task() failed at 0x7fffbeef1000 "
            "with SIGSEGV while accessing g_registry.buffer"
        )
        res = self.classifier.classify(query)
        entities = res.extracted_entities
        self.assertIn("0x7fffbeef1000", entities["addresses"])
        self.assertIn("SIGSEGV", entities["error_codes"])
        self.assertTrue(any("1042" in t for t in entities["threads"]))
        self.assertTrue(any("execute_task" in f for f in entities["functions"]))
        self.assertTrue(any("g_registry" in v for v in entities["variables"]))

    def test_vague_query_handling(self):
        """Verifies handling of vague queries and broad multi-domain screening strategy."""
        vague_queries = [
            "Check whether this process has a runtime problem",
            "이 프로세스에 문제가 있는지 검사해줘",
            "Is the target process healthy?",
            "프로세스 상태 점검 종합 분석",
        ]
        for vq in vague_queries:
            res = self.classifier.classify(vq)
            self.assertTrue(res.is_vague, f"Query should be classified as vague: '{vq}'")
            self.assertIsNotNone(res.screening_strategy)
            self.assertIn("BROAD_MULTI_DOMAIN_SCREENING", res.screening_strategy)

    def test_target_assessment_with_live_proc_and_companion_elf(self):
        """Verifies assessment of local process and companion ELF with DWARF."""
        my_pid = os.getpid()
        assessment = self.assessor.assess(pid=my_pid, companion_elf="/tmp/expert_diagnostic_debug.elf")
        self.assertTrue(assessment.accessible)
        self.assertGreaterEqual(assessment.thread_count, 1)
        self.assertGreaterEqual(assessment.rss_kb, 0)
        self.assertIn("PROC_FS_AVAILABLE", assessment.capabilities)
        self.assertIn("PROCESS_VM_READV_ZERO_STOP", assessment.capabilities)
        self.assertTrue(assessment.prerequisites_met)

    def test_target_assessment_missing_prerequisites(self):
        """Verifies explicit recording of missing prerequisites and limitations."""
        assessment = self.assessor.assess(pid=99999999, companion_elf="/nonexistent/path/app.elf")
        self.assertFalse(assessment.accessible)
        self.assertFalse(assessment.prerequisites_met)
        self.assertTrue(len(assessment.limitations) >= 2)
        self.assertTrue(any("not found" in lim.lower() for lim in assessment.limitations))

    def test_investigation_planning_multi_factor_ranking(self):
        """Verifies multi-factor scoring and ranking of diagnostic steps."""
        classification = self.classifier.classify("Investigate memory corruption and wild pointer dereference")
        assessment = self.assessor.assess(pid=os.getpid(), companion_elf="/tmp/expert_diagnostic_debug.elf")
        plan = self.planner.create_plan(classification, assessment)

        self.assertGreater(plan.total_steps, 0)
        self.assertEqual(len(plan.steps), plan.total_steps)
        # Verify steps are ordered by multi-factor score descending
        for i in range(len(plan.steps) - 1):
            self.assertGreaterEqual(plan.steps[i].multi_factor_score, plan.steps[i+1].multi_factor_score)
        # Verify top step matches category
        self.assertEqual(plan.steps[0].category, CATEGORY_MEMORY_CORRUPTION)
        self.assertGreaterEqual(plan.steps[0].multi_factor_score, 0.70)


if __name__ == "__main__":
    unittest.main()
