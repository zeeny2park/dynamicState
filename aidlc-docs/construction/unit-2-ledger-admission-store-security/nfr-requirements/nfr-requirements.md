# NFR Requirements: Evidence Ledger Admission & Store Security (Unit 2)

> **Unit ID**: `unit-2-ledger-admission-store-security`  
> **Related Requirements**: `NFR-SECURITY-001`, `NFR-RESILIENCY-001`, `NFR-PERF-001`  

---

## 1. 보안 비기능 요구사항 (Security NFRs)

- **NFR-SEC-U2-001 (File Permissions)**:
  - TrustStore 영수증 파일 권한은 POSIX 모드 `0600` (소유자 rw, 그룹/타인 접근 불가)을 엄격히 강제한다.
  - 상위 디렉터리 권한은 POSIX 모드 `0700` (소유자 rwx, 그룹/타인 접근 불가)을 강제한다.
  - umask와 무관하게 명시적인 `chmod` 또는 `open` 모드 파라미터로 권한을 부여한다.
- **NFR-SEC-U2-002 (Single-Process Ownership)**:
  - 파일 및 디렉터리 접근 시 현재 프로세스의 실효 사용자 ID(`os.getuid()`)와 파일의 소유자 UID(`st_uid`)의 일치성을 검증한다.
  - 소유자가 다를 경우 절대 신뢰 저장소로 마운트하거나 읽기/쓰기를 수행하지 않고 즉시 fail-closed 차단한다.
- **NFR-SEC-U2-003 (Symlink / TOCTOU Prevention)**:
  - 저장소 경로가 심볼릭링크이거나 저장소 디렉터리 내에 심볼릭링크가 생성되어 있는 경우 즉시 `SecurityViolationError`를 발생시킨다.
  - 파일 열기 시 `os.O_NOFOLLOW` 플래그를 사용하여 경로 가로채기(race condition)를 방지한다.

---

## 2. 복원력 비기능 요구사항 (Resiliency NFRs)

- **NFR-RES-U2-001 (Atomic Persistence)**:
  - 모든 영속화 쓰기는 대상 파일에 직접 쓰지 않고 동일 파일시스템 디렉터리에 임시 파일(`.trust_tmp_*`)을 작성 후 원자적으로 교체(`os.replace`)한다.
- **NFR-RES-U2-002 (Crash Consistency)**:
  - 임시 파일 디스크립터에 `os.fsync()`를 호출하여 물리적 저장 장치에 데이터가 플러시된 것을 확인한 후 교체한다.
  - 교체 후 대상 파일이 위치한 부모 디렉터리의 fd에 대해 `os.fsync()`를 실행하여 메타데이터 엔트리 영속화를 보장한다.
- **NFR-RES-U2-003 (Orphan Temp File Reclamation)**:
  - 초기화 및 로드 단계에서 이전 프로세스 크래시로 잔존한 `.trust_tmp_*` 파일들을 안전하게 unlink 정리한다.

---

## 3. 성능 비기능 요구사항 (Performance NFRs)

- **NFR-PERF-U2-001 (Eligible Filter Overhead)**:
  - `get_eligible_evidence()`는 메모리 인덱스 또는 필터링 캐시를 활용하여 10,000개 레코드 기준 500 마이크로초(µs) 이내에 `ACCEPTED` 목록을 추출해야 한다.
