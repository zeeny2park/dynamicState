# Phase 19 Investigation Quality Benchmark Report

**Evaluation Timestamp (UTC):** `2026-10-16T06:34:43.680488+00:00`  
**Causal False-Positive SLA:** `✅ PASSED (0.0% FP)`  
**Corpus Version:** `1.1.0` (`cfb50179bbc1`)  
**Fixture SHA-256:** `b39c383e093e`  
**Target GNU Build ID:** `33d119106ac2184acc68abda6f471cc3535bf86f`  
**Active Provider:** `none` (`deterministic-engine`)  

## Headline Product Investigation Quality (REAL_RUNTIME_PRODUCT_PIPELINE)

| Evaluation Track | Scenarios | Fact F1 | Evidence P/R | Unsupp. Claims | Disarm Rate | Uncertainty Cal. | Next Obs. Useful | Causal FP Rate | SLA Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Real-Runtime C++ Pipeline** | 6/6 | 94.4% | 44.4% / 100.0% | 0.0% | 100.0% | 33.3% | 46.4% | `0/5 (0.0%)` | ✅ PASS |
| **Evaluator Self-Test (Unit Fixture)** | 6/6 | 100.0% | 100.0% / 100.0% | 0.0% | 100.0% | 100.0% | 33.3% | `0/5 (0.0%)` | ✅ PASS |

## Real-Runtime C++ Pipeline Scenario Results

| ID | Scenario | Category | Ground Truth Causal | Fact F1 | Ev. Prec / Rec | Calibrated | Observed Tier | Confusion Matrix | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `scenario_1` | Valid Transition | valid_transition | Yes | 100.0% | 67% / 100% | ⚠️ No | STATIC_CANDIDATE | **FN** | Outcome: FN |
| `scenario_2` | Stale / Inconsistent Field | stale_inconsistent_field | No | 100.0% | 67% / 100% | ⚠️ No | STATIC_CANDIDATE | **TN** | Outcome: TN |
| `scenario_3` | Invalid Enum / State | invalid_enum_state | No | 100.0% | 33% / 100% | ⚠️ No | STATIC_CANDIDATE | **TN** | Outcome: TN |
| `scenario_4` | Null / Invalid Pointer | null_invalid_pointer | No | 100.0% | 33% / 100% | ⚠️ No | STATIC_CANDIDATE | **TN** | Outcome: TN |
| `scenario_5` | Cross-Thread Non-Atomic Ambiguity | cross_thread_non_atomic | No | 66.7% | 33% / 100% | ✅ Yes | STATIC_CANDIDATE | **TN** | Outcome: TN |
| `scenario_6` | Negative Control (Unproven Causal Attribution) | negative_control | No | 100.0% | 33% / 100% | ✅ Yes | STATIC_CANDIDATE | **TN** | Outcome: TN |

## Provider Evaluation Matrix

| Provider | Resolved Model | Status | Fallback Occurred | Scenarios | Causal FP Rate | SLA Met |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `none` | `deterministic-engine` | `COMPLETED_MODEL_RESPONSE` | No | 1 | 0.0% | ✅ PASS |

## Methodological Notes & Limitations
- **Zero Fabricated Traces**: Real-runtime captures produce STATIC_CANDIDATE or EVIDENCE_SUPPORTED_CANDIDATE. VALIDATED_CAUSAL_FUNCTION is never awarded without authentic runtime execution traces; absence of trace produces FN rather than fabricated TP.
- **Strict Causal Safety Gate**: False positive causal promotion is evaluated over eligible completed negative scenarios (0/5) and strictly enforced at 0.0% FP.
- **Track Isolation**: Real-runtime product pipeline results and evaluator self-tests are kept strictly isolated with distinct provenance and denominators.
