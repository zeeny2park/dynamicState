# 빌드 및 테스트 종합 보고서 (Build & Test Report — Full 7 Units)

> **일시**: 2026-11-15T03:23:45Z  
> **환경**: Linux aarch64 (Oracle Cloud), Python 3.12.3, GCC 13.3.0  
> **테스트 프레임워크**: pytest 9.1.1, hypothesis 6.170.15  
> **최종 판정**: **전체 통과 (ALL 192 PASS)**  

---

## 1. 테스트 실행 결과 요약

| 테스트 범주 | 테스트 파일 수 | 테스트 케이스 수 | 통과 (Pass) | 실패 (Fail) | 소요 시간 |
|---|---|---|---|---|---|
| **P0 신뢰 경계 (Trust Boundary)** | 9개 파일 | 29개 케이스 | **29** | 0 | ~2.5s |
| **속성 기반 테스트 (Hypothesis PBT)** | 2개 파일 | 8개 속성 (>1,000 예제) | **8** | 0 | ~1.8s |
| **MCP 도구 및 해설 계층** | 3개 파일 | 23개 케이스 | **23** | 0 | ~1.5s |
| **진단 정확도 & 가설/예산 모델 (Unit 5)** | 1개 파일 (+기존 4파일) | 1개 케이스 (+48 케이스) | **49** | 0 | ~1.2s |
| **C++ ABI 및 Tracing (Unit 6)** | 1개 파일 (+기존 2파일) | 2개 케이스 (+19 케이스) | **21** | 0 | ~0.8s |
| **리포트 완결성 및 MCP 일관성 (Unit 7)**| 2개 파일 | 30개 케이스 | **30** | 0 | ~1.5s |
| **기존 캡처 및 세이프티 회귀** | 3개 파일 | 94개 케이스 | **94** | 0 | ~2.2s |
| **스위트 전체 통합** | **21개 파일** | **192개 케이스** | **192 (100%)** | **0** | **9.72s** |

---

## 2. 전체 작업 단위(Unit of Work 1 ~ 7) 최종 검증 현황

| Unit ID | 포함 스토리 | 주요 검증 항목 | 결과 |
|---|---|---|---|
| `unit-1-operation-replay-identity` | `US-TRUST-001`, `002`, `003`, `007` | Operation ID 화이트리스트 사전 검증, Process Identity 4-tuple, 빈 metadata 덮어쓰기 방지, 5단계 생명주기 유효 전이, PID reuse 방어 | **PASS** (18 tests) |
| `unit-2-ledger-admission-store-security` | `US-TRUST-004`, `005`, `006` | 5단계 증거 입도 머신(`ACCEPTED` 전용 인터페이스), 0600/0700 파일 권한, UID 소유권 검증, 심볼릭링크 거부, 원자적 4단계 쓰기, 고아 참조 격리 | **PASS** (8 tests) |
| `unit-3-explanation-provenance` | `US-EXPLAIN-001` | 해설 계층 `copy.deepcopy` 입력 불변성, 실재 증거 ID 접지(Grounding), MCP 계약 준수 | **PASS** (9 tests) |
| `unit-4-pbt-dual-benchmark` | `US-BENCH-001`, `US-PROCESS-001` | Hypothesis `seed=42` 핵심 불변식 무작위 검증 (>100회), Clean commit 메타데이터 봉인 벤치마크 프로토콜 | **PASS** (4 PBTs) |
| `unit-5-diagnosis-accuracy-budget` | `US-DIAG-001` | DWARF/소스 정적 위치 후보 순위화, 가설 모델 모순 증거 분리 및 거부 증거 배제, 적응형 관측 예산 제어, 판정 기권 일관성 | **PASS** (49 tests) |
| `unit-6-cpp-abi-tracing` | `US-CPP-001` | libstdc++ STL 디코더 fail-safe, x86_64/AArch64 크로스 ABI 검증, eBPF attach/detach 라이프사이클 | **PASS** (21 tests) |
| `unit-7-report-mcp-benchmark` | `US-REPORT-001` | HTML/Markdown 리포트 동등성, 증거 출처 링크 완결성, MCP 진단 도구 계약 일관성, clean 벤치마크 메타데이터 봉인 | **PASS** (30 tests) |

---

## 3. 성능 실측치 및 규격 달성
- **Operation ID 정밀 검증 지연시간 (100,000회 벤치마크)**:
  - 목표 SLA: p99 < 50 µs
  - 실측치: **p50 = 2.56 µs, p90 = 2.56 µs, p99 = 2.76 µs** (SLA 대비 18배 초과 달성)
- **192개 전수 통합 테스트 스위트 실행 속도**:
  - **9.72초** (초고속 피드백 및 CI 적합성 유지)
