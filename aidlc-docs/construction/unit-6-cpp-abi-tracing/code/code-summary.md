# Code Summary: C++ STL Decoders & Cross-ABI Tracing (Unit 6)

> **Unit ID**: `unit-6-cpp-abi-tracing`  
> **Status**: COMPLETED  
> **Target Files**:
> - [extractor/cpp_containers.py](file:///home/ubuntu/workspace/ut/extractor/cpp_containers.py)
> - [extractor/target_abi.py](file:///home/ubuntu/workspace/ut/extractor/target_abi.py)
> - [extractor/tracing_mode.py](file:///home/ubuntu/workspace/ut/extractor/tracing_mode.py)
> **Test Files**:
> - [tests/test_target_abi_consistency.py](file:///home/ubuntu/workspace/ut/tests/test_target_abi_consistency.py)
> - [tests/test_cpp_e2e_investigation.py](file:///home/ubuntu/workspace/ut/tests/test_cpp_e2e_investigation.py)
> - [tests/test_ebpf_integration.py](file:///home/ubuntu/workspace/ut/tests/test_ebpf_integration.py)

---

## 1. 구현 내용 요약
- **C++ 컨테이너 ABI 지원 (`FR-CPP-001`)**:
  - `std::vector`, `std::map` 등의 포인터 기반 레이아웃을 안전하게 파싱하며, 비정상 메모리 포인터 접근 시 fail-safe하게 에러 격리.
- **Cross-ABI 아키텍처 일관성 (`FR-CPP-002`)**:
  - `target_abi.py`의 `check_support()`를 통해 x86_64 및 AArch64 양대 아키텍처에 대해 동일한 메모리 오프셋 및 glibc 구조체 지원 결정론적 검증.
- **eBPF Tracing 제어 및 분리 (`FR-TRACE-001 & 002`)**:
  - `tracing_mode.py`에서 opt-in 기반 eBPF 이벤트 추적, 타임아웃 캡, 이벤트 손실 계량 및 clean detach 보장.

---

## 2. 검증 결과
- `tests/test_target_abi_consistency.py`: 2 passed
- `tests/test_cpp_e2e_investigation.py`: 5 passed
- `tests/test_ebpf_integration.py`: 14 passed
- Unit 6 관련 전체 테스트 통과 (0 failures, 0 regressions).
