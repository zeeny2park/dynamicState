# 빌드 안내서 (Build Instructions)

> **프로젝트**: dynamicState Diagnosis Engine  
> **아키텍처**: Monolith (Python 3.9+ 패키지 `extractor` + C 타깃 픽스처)  
> **작업 디렉터리**: `/home/ubuntu/workspace/ut`  

---

## 1. 사전 조건 (Prerequisites)

- **Python 버전**: Python 3.9 이상 (현재 환경: Python 3.12.3)
- **C 컴파일러**: GCC 11+ (현재 환경: `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`)
- **빌드 및 패키징 도구**: `setuptools`, `pip`, `make`, `cmake`
- **의존성**:
  - Python 패키지: `pytest`, `hypothesis`, `anyio`
  - 표준 라이브러리: `os`, `stat`, `fcntl`, `hashlib`, `json`, `uuid`, `dataclasses`, `enum`, `threading`, `time`

---

## 2. 빌드 단계 (Build Steps)

### Step 1: Python 패키지 환경 확인 및 설치
```bash
python3 -m pip install -e .
```

### Step 2: C 기반 수집기 및 타깃 바이너리 빌드
```bash
make -C target/collector
# 또는 CMake 사용 시:
# cmake -B build -S . && cmake --build build
```

### Step 3: 빌드 성공 확인
- Python 패키지 로드 테스트:
```bash
python3 -c "import extractor; print('extractor version:', getattr(extractor, '__version__', 'development'))"
```
- 컴파일러 및 플랫폼 아키텍처 확인:
```bash
uname -m  # aarch64 또는 x86_64
```

---

## 3. 문제 해결 (Troubleshooting)

- **`hypothesis` 누락 시**:
  ```bash
  python3 -m pip install --user --break-system-packages hypothesis
  ```
- **`fcntl` 모듈 에러 시**:
  POSIX 환경(Linux/Unix)에서 실행해야 하며, Windows 네이티브 환경에서는 WSL2를 사용합니다.
