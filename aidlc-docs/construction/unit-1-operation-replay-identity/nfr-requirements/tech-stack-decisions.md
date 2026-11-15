# 기술 스택 및 플랫폼 결정서 (Tech Stack Decisions)

- **대상 작업 단위**: `unit-1-operation-replay-identity`
- **담당 모듈**: `extractor/capture_backend.py`

---

## 1. 런타임 언어 및 의존성 제약

| 영역 | 결정 사항 | 기술적 근거 |
|---|---|---|
| **Python 버전 호환성** | **Python 3.9+ 완벽 호환 유지** | 타깃 임베디드 리눅스 및 다양한 호스트 환경의 기본 파이썬 배포판 지원. |
| **표준 라이브러리 엄수** | **순수 Python 표준 라이브러리만 사용**<br/>(`re`, `dataclasses`, `enum`, `fcntl`, `hashlib`, `os`, `time`, `typing`, `uuid`) | 보안 및 신뢰 핵심(Core Security Boundary)에 외부 서드파티 패키지 공급망 취약점(Supply Chain Attack) 원천 차단. |
| **외부 프레임워크 금지** | **신규 외부 런타임 의존성 추가 절대 금지**<br/>(Pydantic, attrs, marshmallow 등 불허) | 불필요한 직렬화 오버헤드 배제 및 초경량 마이크로초 단위 실행 성능 유지. |
| **기존 의존성 재사용** | 기존 `pyproject.toml`에 명시된 프로젝트 환경 및 도구 체계 재사용 | Monolith 아키텍처 원칙 준수 및 빌드 복잡도 증가 방지. |

---

## 2. 플랫폼 특화 기술 결정 및 가정 (Platform Assumptions)

| 항목 | 채택 기술 / 가정 | 플랫폼 제약 및 대체 고려사항 |
|---|---|---|
| **프로세스 간 파일 락** | **POSIX `fcntl.flock(LOCK_EX)`** | Linux 커널 및 POSIX 준수 OS 전제. Windows 등 비POSIX 환경에서는 파일 락 호환 레이어가 필요하며, 현재 타깃 범위(Linux x86_64, AArch64)에 완전히 부합. |
| **부팅 및 프로세스 식별자** | **Linux `/proc` 가상 파일시스템**<br/>- `/proc/sys/kernel/random/boot_id`<br/>- `/proc/<pid>/stat` (22번째 starttime 필드) | Linux 커널 2.6 이상 표준 지원. 컨테이너 내부 실행 시 `/proc` 마운트가 필요하며, 읽기 실패 시 fail-closed 정책 적용. |
| **호스트 고유 식별자** | **`/etc/machine-id` (systemd) 또는 `/var/lib/dbus/machine-id`** | 불변 머신 식별자로 활용. 파일 부재 시 네트워크 정규화 호스트명으로 폴백. |
| **지원 파일시스템** | **로컬 저널링 파일시스템 (ext4, xfs, btrfs)** | `flock`의 완전한 POSIX 시맨틱 및 원자적 `os.replace` 보장. NFS, CIFS/SMB, GlusterFS 등 네트워크 분산 파일시스템에서는 원격 락 동기화 지연 및 stale 락 위험이 존재하므로 명시적으로 지원 대상에서 제외하거나 경고. |

---

## 3. 테스트 및 품질 도구 체계

| 영역 | 채택 도구 / 라이브러리 | 사용 목적 |
|---|---|---|
| **단위 및 회귀 테스트** | Python 표준 `unittest` | 기존 프로젝트의 253개 테스트 파일과 일관된 실행 체계 유지. |
| **속성 기반 테스트 (PBT)** | `hypothesis` (개발/테스트 의존성) | 무작위 문자열, 특수문자, PID 재사용 경계, 상태 전이 퍼징(Fuzzing) 및 최소 반례 축소. |
| **벤치마크 도구** | `time.perf_counter_ns()` 기반 전용 마이크로 벤치마크 | 나노초 정밀도의 결정론적 레이턴시 측정 및 p50/p90/p99 분포 추출. |

---

## 4. 엔지니어링 준수 불변식

1. **코드 변경 전 기존 구현 감사**:
   - `capture_backend.py`의 기존 `CaptureKeyStore`, `LiveCaptureReceipt`, `DurableTrustStore`, `CausalAttestation` 클래스 구조를 온전히 보존한다.
2. **중복 추상화 금지**:
   - 병렬 identity/lifecycle 서브시스템을 별도 파일로 분리하지 않고, `capture_backend.py` 내부의 응집력 있는 헬퍼 함수와 기존 클래스 메서드로 구현한다.
3. **실제 런타임 경로 벤치마크**:
   - 격리된 헬퍼 함수뿐만 아니라 실제 `DurableTrustStore.consume_attestation()` 및 `record_used_operation()` 전체 호출 경로를 측정한다.
4. **선행 TDD 강제**:
   - 구현 코드 작성 전 결함을 재현하는 실패 테스트(`tests/test_trust_boundary_*.py`)를 먼저 작성하여 커밋한다.
