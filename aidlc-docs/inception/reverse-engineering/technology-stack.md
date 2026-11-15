# 기술 스택 (Technology Stack)

> 기준: `main` HEAD `9b327dd` (PR #1 머지 완료).

## 프로그래밍 언어

- Python - 3.10 이상(`requires-python = ">=3.10"`; CI 는 3.10, 개발 호스트는 3.12.3) - 호스트 분석 도구 전체(`extractor/`, `scripts/`, `benchmarks/`, `skills/`)
- C (C99, `-std=c99 -D_GNU_SOURCE`) - 표준 라이브러리만 사용 - 대상용 수집기 `target/collector/`(버전 1.3.0)와 벤치마크/매트릭스 대상 프로그램
- C++ - 컴파일러 기본 표준(C++14/C++17) - libstdc++ 테스트 픽스처와 예제 프로그램
- 셸(bash, POSIX sh) - 테스트 러너, 워크플로 동기화, 수집기 없는 대상용 `dd` 기반 폴백 명령
- JavaScript, HTML, CSS - 프레임워크 없는 모듈형 웹 UI 및 시각적 인시던트 리포트 템플릿(`extractor/web/ui/`)

## 프레임워크 및 라이브러리

- MCP Python SDK(`mcp`) - `>=2.0.0,<3` - stdio MCP 서버(`scripts/mcp_server.py`)
- 웹 프레임워크 - 없음 - 표준 라이브러리 `http.server` 기반 자체 구현(`extractor/web/server.py`)
- 데이터베이스 - 없음 - 상태는 파일(`corpus/`, 세션 파일)로 지속
- 동적 추적 - Linux eBPF / uprobe (선택적 동적 추적 모드 지원)
- 테스트 프레임워크 - 표준 `unittest`

## 인프라

- GitHub Actions - CI(`.github/workflows/test.yml`, `.github/workflows/gdb92.yml`, `.github/workflows/embedded-matrix.yml`)
- Docker - GDB 9.2 호환 테스트용 컨테이너(`docker/gdb92/Dockerfile`)
- QEMU 시스템 에뮬레이션 - ARM64 glibc 환경 에뮬레이션(`scripts/qemu_matrix/`)
- OpenSSH 클라이언트 - 원격 프로세스 진단 연결 지원
- 지원 대상 플랫폼 - Linux 64비트 little-endian glibc (x86-64, aarch64)

## 빌드 및 도구

- setuptools - `>=61` - Python 패키지 빌드
- GNU make - 수집기 빌드(`target/collector/Makefile`)
- gcc, g++ - 호스트 및 교차 컴파일러(x86_64, aarch64)
- binutils - DWARF 디버그 심볼, CFI 언와인딩, 위치 목록 파싱
