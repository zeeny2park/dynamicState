# Technology Stack Decisions: Evidence Ledger Admission & Store Security (Unit 2)

> **Unit ID**: `unit-2-ledger-admission-store-security`  
> **Target Environment**: Python 3.9+ POSIX Standard Library  

---

## 1. 표준 라이브러리 준수 (Standard Library Only)

- 외부 신규 종속성 추가를 금지하며, Python 표준 라이브러리(`os`, `stat`, `fcntl`, `hashlib`, `uuid`, `dataclasses`, `enum`, `pathlib`)만을 사용합니다.
- 파일 보안 및 원자적 영속화는 `os.open`, `os.O_CREAT`, `os.O_EXCL`, `os.O_WRONLY`, `os.O_NOFOLLOW`, `os.lstat`, `os.fsync`, `os.replace` 표준 API를 사용합니다.

## 2. 동시성 제어 기술

- 동일 프로세스 내 스레드 안전성: `threading.RLock`
- 프로세스 간 상호 배제: `fcntl.flock(LOCK_EX)` (Unit 1에서 구현된 파일 잠금 컨텍스트 매니저 재사용)

## 3. 호환성 및 플랫폼 전제

- 대상 플랫폼은 POSIX 호환 시스템(Linux aarch64 및 x86_64)입니다.
- POSIX UID 검증(`os.getuid`, `stat.st_uid`) 및 `os.O_NOFOLLOW`는 Linux 커널의 기본 지원 기능을 따릅니다.
