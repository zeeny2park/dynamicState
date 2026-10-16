# Phase 18 Investigation Quality Benchmark Report

**Evaluation Timestamp (UTC):** `2026-10-15T23:26:37.785601+00:00`  
**Causal False-Positive SLA:** `✅ PASSED (0.0% FP)`  
**Corpus Version:** `1.0.0` (`4420d5089980`)  
**Fixture SHA-256:** `af1671068a61`  
**Target GNU Build ID:** `3617f02cd67911ffa65c17ada5af4e89516ac27c`  
**Active Provider:** `none` (`deterministic-engine`)  

## Aggregate Summary Metrics

| Evaluation Track | Scenarios | Fact F1 | Evidence P/R | Unsupp. Claims | Disarm Rate | Uncertainty Cal. | Next Obs. Useful | Causal FP Rate | SLA Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Real-Runtime C++** | 6/6 | 94.4% | 44.4% / 100.0% | 0.0% | 100.0% | 50.0% | 46.4% | `0.0%` | ✅ PASS |
| **Unit Fixture** | 6/6 | 100.0% | 100.0% / 100.0% | 0.0% | 100.0% | 100.0% | 33.3% | `0.0%` | ✅ PASS |

## Real-Runtime C++ Scenario Results

| ID | Scenario | Category | Ground Truth Causal | Fact F1 | Ev. Prec / Rec | Calibrated | Promoted? | Confusion Matrix | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `scenario_1` | Valid Transition | valid_transition | Yes | 100.0% | 67% / 100% | ✅ Yes | **VALIDATED_CAUSAL_FUNCTION** | **TP** | Outcome: TP |
| `scenario_2` | Stale / Inconsistent Field | stale_inconsistent_field | No | 100.0% | 67% / 100% | ⚠️ No | STATIC_CANDIDATE | **TN** | Outcome: TN |
| `scenario_3` | Invalid Enum / State | invalid_enum_state | No | 100.0% | 33% / 100% | ⚠️ No | STATIC_CANDIDATE | **TN** | Outcome: TN |
| `scenario_4` | Null / Invalid Pointer | null_invalid_pointer | No | 100.0% | 33% / 100% | ⚠️ No | STATIC_CANDIDATE | **TN** | Outcome: TN |
| `scenario_5` | Cross-Thread Non-Atomic Ambiguity | cross_thread_non_atomic | No | 66.7% | 33% / 100% | ✅ Yes | STATIC_CANDIDATE | **TN** | Outcome: TN |
| `scenario_6` | Negative Control (No Causal Function) | negative_control | No | 100.0% | 33% / 100% | ✅ Yes | STATIC_CANDIDATE | **TN** | Outcome: TN |

## Methodological Notes & Limitations
- **Sample Size Calibration Note**: The canonical defect corpus consists of N=6 scenarios designed for deterministic coverage. This sample size is sufficient for binary calibration concordance but too small for a statistically granular 10-bin reliability curve.
- **Strict Causal Safety Gate**: `FUNCTION_TIER_VALIDATED_CAUSAL` promotion requires verified runtime transition proofs and independent function attribution; ungrounded candidate names, caller booleans, and negative controls strictly yield zero promotions (0.0% FP).
- **Track Isolation**: Real-runtime results and unit-fixture results are tracked independently with distinct denominators and provenance.
