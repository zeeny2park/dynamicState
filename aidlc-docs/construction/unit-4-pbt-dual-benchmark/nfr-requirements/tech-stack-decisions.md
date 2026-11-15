# Technology Stack Decisions: PBT Invariants & Clean Benchmark Verification (Unit 4)

> **Unit ID**: `unit-4-pbt-dual-benchmark`  

---

## 1. PBT 및 벤치마크 기술 스택
- **속성 기반 테스트**: `hypothesis` (Python 3.9+ 호환, deterministic seed 지원)
- **단위/통합 테스트 러너**: `pytest`
- **벤치마크 실행기**: `benchmarks/diagnosis_accuracy/run_benchmark.py` (표준 Python 및 POSIX 컴파일러)
