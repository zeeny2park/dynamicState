# Domain Entities: Evidence Ledger Admission & Store Security (Unit 2)

> **Unit ID**: `unit-2-ledger-admission-store-security`  
> **Source Files**: [evidence_ledger.py](file:///home/ubuntu/workspace/ut/extractor/evidence_ledger.py), [capture_backend.py](file:///home/ubuntu/workspace/ut/extractor/capture_backend.py)  

---

## 1. Domain Entities & Enums

### 1.1 `EvidenceAdmissionState` (Enum)
```python
from enum import Enum

class EvidenceAdmissionState(str, Enum):
    """증거의 신뢰 입도 상태를 정의하는 열거형."""
    ACCEPTED = "ACCEPTED"          # 검증 완료된 권위 있는 증거 (진단 사용 가능)
    REJECTED = "REJECTED"          # 무결성/서명/규칙 위반으로 거부된 증거
    QUARANTINED = "QUARANTINED"    # 출처 결손 또는 고아 참조로 격리된 증거
    NOT_COVERED = "NOT_COVERED"    # 미검증 상태의 기본 증거
    PARTIAL = "PARTIAL"            # 부분적 속성만 확인된 불완전 증거
```

### 1.2 `ProvenanceLineage` (Data Class)
```python
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass(frozen=True)
class ProvenanceLineage:
    """증거의 수집 출처 및 계통 정보를 담는 값 객체."""
    operation_id: str
    target_identity: str
    boot_id: str
    pid: int
    process_start_time: str
    build_id: str
    parent_evidence_refs: List[str] = field(default_factory=list)
```

### 1.3 `SecurityViolationError` (Exception)
```python
class SecurityViolationError(RuntimeError):
    """파일시스템 권한, 소유자 UID 불일치, 심볼릭링크 시도 등 보안 위반 시 발생하는 예외."""
    pass
```

### 1.4 `EvidenceRecord` 확장 속성
- `admission_state`: `EvidenceAdmissionState` (기본값: `EvidenceAdmissionState.NOT_COVERED`)
- `admission_reason`: `str` (거부 또는 격리 시 그 구체적 사유)
- `provenance_lineage`: `Optional[ProvenanceLineage]` (선택적 구조화 출처 객체)

### 1.5 `EvidenceLedger` 확장 메서드
- `get_eligible_evidence() -> List[EvidenceRecord]`: 오직 `admission_state == EvidenceAdmissionState.ACCEPTED`인 증거 레코드만 반환.
- `get_audit_trail() -> List[EvidenceRecord]`: 모든 증거 레코드(`ACCEPTED`, `REJECTED`, `QUARANTINED`, `NOT_COVERED`, `PARTIAL`)를 반환.
- `quarantine_record(evidence_id: str, reason: str) -> None`: 특정 레코드를 격리 상태로 전이.
- `reject_record(evidence_id: str, reason: str) -> None`: 특정 레코드를 거부 상태로 전이.
- `accept_record(evidence_id: str) -> None`: 특정 레코드를 권위 있는 상태로 승격.
