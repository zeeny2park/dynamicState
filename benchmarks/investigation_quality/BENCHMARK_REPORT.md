# Phase 20 Investigation Quality Benchmark Report

**Evaluation Timestamp (UTC):** `2026-10-16T14:54:00.253366+00:00`  
**Product Causal False-Positive SLA:** `✅ PASSED (0.0% FP)`  
**Corpus Version:** `1.1.0` (`cfb50179bbc1`)  
**Fixture SHA-256:** `cb7f5b191a78`  
**Target GNU Build ID:** `4290a5f819f4e1232ac0dff7716f1e81dd83d567`  
**Active Provider:** `none` (`deterministic-engine`)  

## Headline Product Investigation Quality (REAL_RUNTIME_PRODUCT_PIPELINE)

| Evaluation Track | Scenarios (Comp/Total) | Fact F1 (Micro/Macro) | Evidence P/R | Unsupp. Claims | Disarm Rate | Uncertainty Cal. | Next Obs. Useful | Causal FP Rate | SLA Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Real-Runtime C++ Pipeline** | 2/2 | 100.0% / 100.0% | 50.0% / 100.0% | 0.0% | 100.0% | 50.0% | 50.0% | `0/1 (0.0%)` | ✅ PASS |
| **Evaluator Self-Test (Unit Fixture)** | 2/2 | 100.0% / 100.0% | 100.0% / 100.0% | 0.0% | 100.0% | 100.0% | 50.0% | `0/1 (0.0%)` | ✅ PASS |

## Real-Runtime C++ Pipeline Scenario Results

| ID | Scenario | Category | Ground Truth Causal | Fact F1 | Ev. Prec / Rec | Calibrated | Observed Tier | Confusion Matrix | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `scenario_1` | Valid Transition | valid_transition | Yes | 100.0% | 67% / 100% | ⚠️ No | STATIC_CANDIDATE | **FN** | Outcome: FN |
| `scenario_6` | Negative Control (Unproven Causal Attribution) | negative_control | No | 100.0% | 33% / 100% | ✅ Yes | STATIC_CANDIDATE | **TN** | Outcome: TN |

## Provider Evaluation Matrix

| Provider | Mode | Resolved Model | Status | Fallback Count | Scenarios Evaluated | Model Success Rate | Causal FP Rate | SLA Met |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `none` | `real_runtime` | `deterministic-engine` | `COMPLETED_MODEL_RESPONSE` | 0 / 1 | 1 | 100.0% | 0.0% | ✅ PASS |

## Methodological Notes & Limitations
- **Zero Fabricated Traces**: Real-runtime captures produce STATIC_CANDIDATE or EVIDENCE_SUPPORTED_CANDIDATE. VALIDATED_CAUSAL_FUNCTION is never awarded without authentic runtime execution traces; absence of trace produces FN rather than fabricated TP.
- **Strict Causal Safety Gate**: False positive causal promotion is evaluated over eligible completed negative scenarios (0/5) and strictly enforced at 0.0% FP.
- **Track Isolation**: Real-runtime product pipeline results and evaluator self-tests are kept strictly isolated with distinct provenance and denominators.
- **Empty Denominator Safety**: An empty eligible negative denominator produces NOT_EVALUABLE and cannot pass the SLA.
