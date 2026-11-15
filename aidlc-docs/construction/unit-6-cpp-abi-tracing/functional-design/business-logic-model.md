# Business Logic Model: C++ STL Decoders & Cross-ABI Tracing (Unit 6)

> **Unit ID**: `unit-6-cpp-abi-tracing`  
> **Source Files**: 
> - [cpp_containers.py](file:///home/ubuntu/workspace/ut/extractor/cpp_containers.py)
> - [target_abi.py](file:///home/ubuntu/workspace/ut/extractor/target_abi.py)
> - [tracing_mode.py](file:///home/ubuntu/workspace/ut/extractor/tracing_mode.py)  
> **Related Stories**: `US-CPP-001`  
> **Related Requirements**: `FR-CPP-001`, `FR-CPP-002`, `FR-TRACE-001`, `FR-TRACE-002`  

---

## 1. C++ STL 디코더 및 ABI 매핑 모델 (`FR-CPP-001 & 002`)

- `std::vector`, `std::map`, `std::set`, `std::string`의 메모리 레이아웃(포인터 트리플렛, RB 트리 노드 포인터 등)을 디버그 대상 프로세스의 실제 메모리 바이트로부터 파싱.
- **Fail-Safe 메모리 경계**: 잘못된 포인터(0x0, out-of-range, 손상된 힙 포인터) 참조 시 프로세스가 크래시되지 않고 즉시 안전하게 `CorruptedContainerError` 또는 None을 반환.
- **Cross-ABI 동등성**: AArch64(64-bit little endian)와 x86_64(64-bit little endian) 간 데이터 패딩 및 구조체 오프셋의 동등성 보장.

---

## 2. eBPF Tracing 수명주기 및 격리 모델 (`FR-TRACE-001 & 002`)

- **Attach / Detach 수명주기**:
  - eBPF 프로브 연결 시 항상 try-finally 블록을 통해 detach를 보장하여 커널 내 프로브 누수 방지.
- **선택적 Opt-in**:
  - root 권한이 없거나 BPF 지원이 없는 환경에서는 fail-soft하게 스킵되고, 정적/스냅샷 기반 진단으로 원활히 폴백.
- **이벤트 손실 통지**:
  - perf/ring buffer의 이벤트 오버플로 시 손실된 이벤트 수를 진단 증거 메타데이터에 명시.
