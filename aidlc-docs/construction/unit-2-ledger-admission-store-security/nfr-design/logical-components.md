# Logical Components: Evidence Ledger Admission & Store Security (Unit 2)

> **Unit ID**: `unit-2-ledger-admission-store-security`  

---

## 1. 컴포넌트 상호작용 다이어그램

```mermaid
graph TD
    subgraph EvidenceLedger["EvidenceLedger (extractor/evidence_ledger.py)"]
        AdmissionState["EvidenceAdmissionState<br/>(ACCEPTED, REJECTED, QUARANTINED, NOT_COVERED, PARTIAL)"]
        EligibleQuery["get_eligible_evidence()"]
        AuditQuery["get_audit_trail()"]
        ProvenanceValidator["Provenance Lineage Validator"]
    end

    subgraph DurableTrustStore["DurableTrustStore (extractor/capture_backend.py)"]
        FSSecurity["Filesystem Security Verifier<br/>(0600/0700, UID match, No Symlinks)"]
        AtomicWriter["Atomic 4-Step Writer<br/>(tmp -> fsync -> replace -> dir fsync)"]
        TempCleaner["Stale Temp Cleaner<br/>(.trust_tmp_*)"]
    end

    subgraph DownstreamEngine["Diagnostic Pipeline (Downstream)"]
        CompHypo["CompetingHypothesis Engine"]
        ExpertDiag["ExpertDiagnosticEngine"]
    end

    DownstreamEngine --> EligibleQuery
    EligibleQuery --> AdmissionState
    EvidenceLedger --> ProvenanceValidator
    EvidenceLedger --> DurableTrustStore
```

## 2. 컴포넌트 인터페이스 명세

1. **`EvidenceLedger`**:
   - `get_eligible_evidence() -> List[EvidenceRecord]`: `ACCEPTED` 레코드만 반환.
   - `get_audit_trail() -> List[EvidenceRecord]`: 모든 상태의 레코드 반환.
   - `validate_and_admit(record: EvidenceRecord) -> EvidenceAdmissionState`: 출처 및 무결성 검증 후 입도 상태 결정.
2. **`DurableTrustStore`**:
   - `_verify_path_security(path: Path) -> None`: UID, 권한, 심볼릭링크 검증. 위반 시 `SecurityViolationError`.
   - `_cleanup_stale_temp_files() -> None`: `.trust_tmp_*` 파일 삭제.
   - `save() -> None`: 원자적 4단계 디스크 영속화.
