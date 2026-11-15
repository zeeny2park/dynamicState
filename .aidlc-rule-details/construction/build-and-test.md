# Build and Test

**목적 (Purpose)**: 모든 unit 을 빌드하고 포괄적인 테스트 전략을 실행한다

## 사전 조건 (Prerequisites)
- 모든 unit 의 Code Generation 이 완료되어 있어야 한다
- 모든 코드 산출물이 생성되어 있어야 한다
- 프로젝트가 빌드 및 테스트 준비가 되어 있어야 한다

---

## Step 1: 테스트 요구사항 분석

프로젝트를 분석하여 적절한 테스트 전략을 정한다:
- **단위 테스트 (Unit tests)**: 코드 생성 중 unit 별로 이미 생성됨
- **통합 테스트 (Integration tests)**: unit/서비스 간 상호작용 테스트
- **성능 테스트 (Performance tests)**: 부하, 스트레스, 확장성 테스트
- **E2E 테스트 (End-to-end tests)**: 사용자 워크플로우 전체
- **계약 테스트 (Contract tests)**: 서비스 간 API 계약 검증
- **보안 테스트 (Security tests)**: 취약점 스캔, 침투 테스트

---

## Step 2: 빌드 안내서 생성

`aidlc-docs/construction/build-and-test/build-instructions.md` 를 만든다:

```markdown
# 빌드 안내 (Build Instructions)

## 사전 조건 (Prerequisites)
- **빌드 도구 (Build Tool)**: [도구 이름과 버전]
- **의존성 (Dependencies)**: [필요한 의존성 전체 목록]
- **환경 변수 (Environment Variables)**: [필요한 환경 변수 목록]
- **시스템 요구사항 (System Requirements)**: [OS, 메모리, 디스크 공간]

## 빌드 단계 (Build Steps)

### 1. 의존성 설치
\`\`\`bash
[의존성 설치 명령]
# 예: npm install, mvn dependency:resolve, pip install -r requirements.txt
\`\`\`

### 2. 환경 구성
\`\`\`bash
[환경 구성 명령]
# 예: 변수 export, 자격 증명 구성
\`\`\`

### 3. 모든 unit 빌드
\`\`\`bash
[모든 unit 빌드 명령]
# 예: mvn clean install, npm run build, brazil-build
\`\`\`

### 4. 빌드 성공 확인
- **예상 출력 (Expected Output)**: [성공한 빌드 출력 설명]
- **빌드 산출물 (Build Artifacts)**: [생성된 산출물과 위치 목록]
- **흔한 경고 (Common Warnings)**: [허용 가능한 경고]

## 문제 해결 (Troubleshooting)

### 의존성 오류로 빌드 실패
- **원인 (Cause)**: [흔한 원인]
- **해결 (Solution)**: [단계별 해결 방법]

### 컴파일 오류로 빌드 실패
- **원인 (Cause)**: [흔한 원인]
- **해결 (Solution)**: [단계별 해결 방법]
```

---

## Step 3: 단위 테스트 실행 안내서 생성

`aidlc-docs/construction/build-and-test/unit-test-instructions.md` 를 만든다:

```markdown
# 단위 테스트 실행 (Unit Test Execution)

## 단위 테스트 실행

### 1. 모든 단위 테스트 실행
\`\`\`bash
[모든 단위 테스트 실행 명령]
# 예: mvn test, npm test, pytest tests/unit
\`\`\`

### 2. 테스트 결과 검토
- **기대 결과 (Expected)**: [X] 개 테스트 통과, 실패 0
- **테스트 커버리지 (Test Coverage)**: [기대 커버리지 비율]
- **테스트 보고서 위치 (Test Report Location)**: [테스트 보고서 경로]

### 3. 실패한 테스트 수정
테스트가 실패하면:
1. [위치] 에서 테스트 출력을 검토한다
2. 실패한 테스트 케이스를 찾는다
3. 코드 문제를 수정한다
4. 모두 통과할 때까지 테스트를 다시 실행한다
```

---

## Step 4: 통합 테스트 안내서 생성

`aidlc-docs/construction/build-and-test/integration-test-instructions.md` 를 만든다:

```markdown
# 통합 테스트 안내 (Integration Test Instructions)

## 목적 (Purpose)
unit/서비스 간 상호작용을 테스트하여 함께 올바르게 동작하는지 확인한다.

## 테스트 시나리오 (Test Scenarios)

### 시나리오 1: [Unit A] → [Unit B] 통합
- **설명 (Description)**: [테스트 대상]
- **준비 (Setup)**: [필요한 테스트 환경 구성]
- **테스트 단계 (Test Steps)**: [단계별 테스트 실행]
- **기대 결과 (Expected Results)**: [일어나야 할 일]
- **정리 (Cleanup)**: [테스트 후 정리 방법]

### 시나리오 2: [Unit B] → [Unit C] 통합
[같은 구조]

## 통합 테스트 환경 구성

### 1. 필요한 서비스 시작
\`\`\`bash
[서비스 시작 명령]
# 예: docker-compose up, 테스트 데이터베이스 시작
\`\`\`

### 2. 서비스 endpoint 구성
\`\`\`bash
[endpoint 구성 명령]
# 예: export API_URL=http://localhost:8080
\`\`\`

## 통합 테스트 실행

### 1. 통합 테스트 묶음 실행
\`\`\`bash
[통합 테스트 실행 명령]
# 예: mvn integration-test, npm run test:integration
\`\`\`

### 2. 서비스 상호작용 확인
- **테스트 시나리오 (Test Scenarios)**: [핵심 통합 테스트 시나리오 목록]
- **기대 결과 (Expected Results)**: [예상 결과 설명]
- **로그 위치 (Logs Location)**: [로그 확인 위치]

### 3. 정리
\`\`\`bash
[테스트 환경 정리 명령]
# 예: docker-compose down, 테스트 서비스 중지
\`\`\`
```

---

## Step 5: 성능 테스트 안내서 생성 (해당 시)

`aidlc-docs/construction/build-and-test/performance-test-instructions.md` 를 만든다:

```markdown
# 성능 테스트 안내 (Performance Test Instructions)

## 목적 (Purpose)
부하 상황에서 시스템 성능을 검증하여 요구사항을 충족하는지 확인한다.

## 성능 요구사항 (Performance Requirements)
- **응답 시간 (Response Time)**: 요청의 [Y]% 에 대해 < [X]ms
- **처리량 (Throughput)**: 초당 [X] 요청
- **동시 사용자 (Concurrent Users)**: 동시 사용자 [X] 명 지원
- **오류율 (Error Rate)**: < [X]%

## 성능 테스트 환경 구성

### 1. 테스트 환경 준비
\`\`\`bash
[성능 테스트 환경 구성 명령]
# 예: 서비스 확장, 부하 분산기 구성
\`\`\`

### 2. 테스트 매개변수 구성
- **테스트 시간 (Test Duration)**: [X] 분
- **증가 시간 (Ramp-up Time)**: [X] 초
- **가상 사용자 (Virtual Users)**: [X] 명

## 성능 테스트 실행

### 1. 부하 테스트 실행
\`\`\`bash
[부하 테스트 실행 명령]
# 예: jmeter -n -t test.jmx, k6 run script.js
\`\`\`

### 2. 스트레스 테스트 실행
\`\`\`bash
[스트레스 테스트 실행 명령]
# 예: 실패할 때까지 부하를 점진적으로 증가
\`\`\`

### 3. 성능 결과 분석
- **응답 시간 (Response Time)**: [실제 vs 기대]
- **처리량 (Throughput)**: [실제 vs 기대]
- **오류율 (Error Rate)**: [실제 vs 기대]
- **병목 (Bottlenecks)**: [찾은 병목]
- **결과 위치 (Results Location)**: [성능 보고서 경로]

## 성능 최적화

성능이 요구사항을 충족하지 못하면:
1. 테스트 결과에서 병목을 찾는다
2. 코드/쿼리/설정을 최적화한다
3. 테스트를 다시 실행하여 개선을 검증한다
```

---

## Step 6: 추가 테스트 안내서 생성 (필요 시)

프로젝트 요구사항에 따라 추가 테스트 안내서 파일을 생성한다:

### 계약 테스트 (Contract Tests) (microservices 용)
`aidlc-docs/construction/build-and-test/contract-test-instructions.md` 를 만든다:
- 서비스 간 API 계약 검증
- 소비자 주도 계약 테스트 (Consumer-driven contract testing)
- 스키마 검증

### 보안 테스트 (Security Tests)
`aidlc-docs/construction/build-and-test/security-test-instructions.md` 를 만든다:
- 취약점 스캔
- 의존성 보안 점검
- 인증/인가 테스트
- 입력 검증 테스트

### E2E 테스트 (End-to-End Tests)
`aidlc-docs/construction/build-and-test/e2e-test-instructions.md` 를 만든다:
- 사용자 워크플로우 전체 테스트
- 서비스 간 시나리오
- UI 테스트 (해당 시)

---

## Step 7: 테스트 요약 생성

`aidlc-docs/construction/build-and-test/build-and-test-summary.md` 를 만든다:

```markdown
# 빌드 및 테스트 요약 (Build and Test Summary)

## 빌드 상태 (Build Status)
- **빌드 도구 (Build Tool)**: [도구 이름]
- **빌드 상태 (Build Status)**: [Success/Failed]
- **빌드 산출물 (Build Artifacts)**: [산출물 목록]
- **빌드 시간 (Build Time)**: [소요 시간]

## 테스트 실행 요약 (Test Execution Summary)

### 단위 테스트 (Unit Tests)
- **전체 테스트 (Total Tests)**: [X]
- **통과 (Passed)**: [X]
- **실패 (Failed)**: [X]
- **커버리지 (Coverage)**: [X]%
- **상태 (Status)**: [Pass/Fail]

### 통합 테스트 (Integration Tests)
- **테스트 시나리오 (Test Scenarios)**: [X]
- **통과 (Passed)**: [X]
- **실패 (Failed)**: [X]
- **상태 (Status)**: [Pass/Fail]

### 성능 테스트 (Performance Tests)
- **응답 시간 (Response Time)**: [실제] (목표: [기대])
- **처리량 (Throughput)**: [실제] (목표: [기대])
- **오류율 (Error Rate)**: [실제] (목표: [기대])
- **상태 (Status)**: [Pass/Fail]

### 추가 테스트 (Additional Tests)
- **계약 테스트 (Contract Tests)**: [Pass/Fail/N/A]
- **보안 테스트 (Security Tests)**: [Pass/Fail/N/A]
- **E2E 테스트 (E2E Tests)**: [Pass/Fail/N/A]

## 전체 상태 (Overall Status)
- **빌드 (Build)**: [Success/Failed]
- **전체 테스트 (All Tests)**: [Pass/Fail]
- **Operations 준비 (Ready for Operations)**: [Yes/No]

## 다음 단계 (Next Steps)
[모두 통과 시]: 실행 계획에 EXECUTE 인 Operations stage 가 있으면 Operations phase 로 진행할 준비 완료, 모두 SKIP 이면 workflow 완료
[Operations 판정 없음]: 실행 계획에 Operations 7 stage 의 EXECUTE / SKIP 판정이 없으면 (예: v1.0.0 으로 만든 계획처럼 Operations 가 1줄로만 있는 경우) workflow 완료로 안내하지 않고, 7 stage 각각의 EXECUTE / SKIP 을 사용자에게 먼저 묻고 실행 계획 · aidlc-state.md 에 반영
[실패 시]: 실패한 테스트를 해결하고 다시 빌드
```

---

## Step 8: 상태 추적 갱신

`aidlc-docs/aidlc-state.md` 를 갱신한다:
- Build and Test stage 를 완료로 표시한다
- 현재 상태를 갱신한다

---

## Step 9: 사용자에게 결과 제시

완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# 🔨 Build and Test 완료 (Build and Test Complete)
```

     2. **AI 요약 (AI Summary)** (선택): 빌드 및 테스트 결과를 구조화된 글머리 기호로 요약
        - 형식: "빌드 및 테스트가 다음 결과로 완료되었습니다:"
        - 빌드 상태와 산출물 나열
        - 범주별 테스트 결과 나열 (단위, 통합, 성능 등)
        - 생성한 안내서 파일 나열
        - 워크플로우 안내 문구를 넣지 않는다 ("검토해 주세요 (please review)", "알려 주세요 (let me know)", "다음 phase 로 진행 (proceed to next phase)", "진행하기 전에 (before we proceed)")
        - 사실 중심, 내용 중심으로 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 빌드 및 테스트 요약을 검토해 주세요: `aidlc-docs/construction/build-and-test/build-and-test-summary.md`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 빌드 및 테스트 안내서 수정 요청
> ✅ **승인 후 계속 (Approve & Continue)** - 빌드 및 테스트 결과를 승인하고 **[실행 계획의 첫 EXECUTE Operations stage / workflow 완료]** 로 진행

---
```

---

## Step 10: 상호작용 기록

**MANDATORY (필수)**: `aidlc-docs/audit.md` 에 stage 완료를 기록한다:

```markdown
## Build and Test Stage
**Timestamp**: [ISO timestamp]
**Build Status**: [Success/Failed]
**Test Status**: [Pass/Fail]
**Files Generated**:
- build-instructions.md
- unit-test-instructions.md
- integration-test-instructions.md
- performance-test-instructions.md
- build-and-test-summary.md

---
```
