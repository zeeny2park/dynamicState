# NFR Requirements & Tech Stack: C++ STL Decoders & Cross-ABI Tracing (Unit 6)

> **Unit ID**: `unit-6-cpp-abi-tracing`  

---

## 1. NFRs
- **NFR-SEC-U6-001 (Safe Memory Dereferencing)**: 임의의 부패된 메모리 블록을 디코딩할 때 segmentation fault나 프로세스 패닉을 일으키지 않고 Python 레벨에서 안전하게 격리.
- **NFR-PERF-U6-001 (Trace Ringbuffer Overflow Protection)**: 초당 100,000건의 트레이스 이벤트 발생 시 메모리 고갈 없이 링버퍼 오버플로를 드롭 카운터로 계량.

## 2. Tech Stack
- Python ctypes / struct 메모리 언패킹
- Linux eBPF / BCC / libbpf 호환 C 수집기
