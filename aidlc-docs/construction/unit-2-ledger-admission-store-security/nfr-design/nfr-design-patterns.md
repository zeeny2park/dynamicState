# NFR Design Patterns: Evidence Ledger Admission & Store Security (Unit 2)

> **Unit ID**: `unit-2-ledger-admission-store-security`  

---

## 1. Gateway Pattern (Admission Boundary)

- **패턴**: API 게이트웨이 / 가드 필터 패턴
- **적용**: `EvidenceLedger`의 `get_eligible_evidence()`가 모든 가설 평가 엔진과 증거 저장소 사이의 엄격한 관문 역할을 수행.
- **효과**: 가설 평가 및 판정 로직이 개별 증거의 무결성 검증 세부사항을 몰라도, 오직 승인된(`ACCEPTED`) 고신뢰 증거만을 소비하도록 보장.

## 2. Secure Storage Pattern (Filesystem Isolation)

- **패턴**: 방어적 파일시스템 샌드박싱
- **적용**: `DurableTrustStore`가 저장소 경로를 열기 전 `lstat()`을 통한 심볼릭링크 검사, 소유자 UID 일치 검사, 권한 비트 검사를 수행.
- **효과**: 권한이 없는 계정이나 심볼릭링크 공격을 통한 파일 변조 및 탈취 위험 완전 차단.

## 3. Atomic Commit Pattern (Two-Phase Durability)

- **패턴**: Write-Ahead Temp Replacement with Double Fsync
- **적용**: 
  1. 임시 파일 생성 및 기록
  2. 파일 데이터 및 메타데이터 디스크 동기화 (`os.fsync(fd)`)
  3. 원자적 파일 치환 (`os.replace`)
  4. 디렉터리 메타데이터 동기화 (`os.fsync(dir_fd)`)
- **효과**: 전원 단절이나 비정상 종료 시에도 영수증 파일이 손상되거나 빈 파일로 남지 않음.
