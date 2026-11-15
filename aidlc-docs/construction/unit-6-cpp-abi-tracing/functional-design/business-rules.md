# Business Rules: C++ STL Decoders & Cross-ABI Tracing (Unit 6)

> **Unit ID**: `unit-6-cpp-abi-tracing`  

---

## 1. C++ STL 디코딩 불변식 (Rule BR-CPP-001)
- 메모리 디코딩 중 잘못된 포인터(0, 잘못된 정렬, 비정상 범위)가 감지되면 예외 없이 fail-safe하게 null/빈 컬렉션 또는 부패 플래그를 반환한다.
- x86_64와 AArch64 양대 아키텍처에서 동일한 libstdc++ STL 메모리 레이아웃 디코딩 규칙을 적용한다.

## 2. eBPF 수명주기 불변식 (Rule BR-TRACE-001)
- eBPF 프로브는 비정상 종료 시에도 항상 언마운트/detach되어야 한다.
- root 권한 부재 시 에러로 진단을 중단하지 않고 비-추적 모드로 안전하게 폴백한다.
