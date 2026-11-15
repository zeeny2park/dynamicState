# Reverse Engineering

**목적**: 기존 코드베이스를 분석하고 포괄적인 설계 산출물을 만든다

**실행 조건**: Brownfield (기존 코드) 프로젝트로 감지된 경우 (작업 공간에서 기존 코드 발견)

**건너뛰는 조건**: Greenfield (신규) 프로젝트 (기존 코드 없음)

**다시 실행 동작**: 다시 실행 여부는 workspace-detection.md 가 정한다. 기존 reverse engineering 산출물이 있고 여전히 최신이면, 그 산출물을 불러오고 reverse engineering 은 건너뛴다. 산출물이 오래되었거나 (코드베이스의 마지막 주요 수정보다 이전) 사용자가 다시 실행을 명시적으로 요청하면, 산출물이 현재 코드 상태를 반영하도록 reverse engineering 을 다시 실행한다

## Step 1: 다중 패키지 탐색

### 1.1 작업 공간 탐색
- 모든 패키지 (언급된 것만이 아님)
- 설정 파일을 통한 패키지 간 관계
- 패키지 유형: Application, Infrastructure (IaC), Models, Clients, Tests

### 1.2 비즈니스 맥락 파악
- 시스템 전체가 구현하는 핵심 비즈니스
- 각 패키지의 비즈니스 개요
- 시스템에 구현된 비즈니스 트랜잭션 (Business Transaction) 목록

### 1.3 인프라 탐색
- IaC 코드 (Terraform `.tf`, CDK · Pulumi 등 인프라 패키지)
- 배포 템플릿 · 매니페스트 (Kubernetes · Helm · CloudFormation 등 `.yaml`/`.json`)
- 배포 스크립트, 컨테이너 설정 (Dockerfile, compose)
- 해당 항목이 없으면 "없음" 으로 기록한다 (추측해서 채우지 않는다)

### 1.4 빌드 시스템 탐색
- 빌드 시스템: Maven, Gradle, npm, pip · uv · poetry 등
- 빌드 시스템 선언용 설정 파일
- 패키지 간 빌드 의존성

### 1.5 서비스 아키텍처 탐색
- 실행 진입점 (서버, CLI, 서버리스 함수 handler, 예약 작업)
- 컨테이너 · 오케스트레이션 설정
- API 정의 (OpenAPI 명세, gRPC proto 등)
- 데이터 저장소 (DB, 파일 · 객체 저장소, 캐시 등)

### 1.6 코드 품질 분석
- 프로그래밍 언어와 프레임워크
- 테스트 커버리지 지표
- 린트 (linting) 설정
- CI/CD 파이프라인

## Step 2: 비즈니스 개요 문서 생성

`aidlc-docs/inception/reverse-engineering/business-overview.md` 를 만든다:

```markdown
# 비즈니스 개요 (Business Overview)

## 비즈니스 맥락 도식
[비즈니스 맥락을 보여주는 Mermaid 도식]

## 비즈니스 설명
- **비즈니스 설명**: [시스템이 하는 일에 대한 전체 비즈니스 설명]
- **비즈니스 트랜잭션**: [시스템이 구현하는 비즈니스 트랜잭션 목록과 설명]
- **비즈니스 용어집**: [시스템이 따르는 비즈니스 용어와 그 의미]

## 컴포넌트 수준 비즈니스 설명
### [패키지/컴포넌트 이름]
- **목적**: [비즈니스 관점에서 하는 일]
- **책임**: [주요 책임]
```

## Step 3: 아키텍처 문서 생성

`aidlc-docs/inception/reverse-engineering/architecture.md` 를 만든다:

```markdown
# 시스템 아키텍처 (System Architecture)

## 시스템 개요
[시스템에 대한 상위 수준 설명]

## 아키텍처 도식
[모든 패키지, 서비스, 데이터 저장소, 관계를 보여주는 Mermaid 도식]

## 컴포넌트 설명
### [패키지/컴포넌트 이름]
- **목적**: [하는 일]
- **책임**: [주요 책임]
- **의존성**: [의존하는 대상]
- **유형**: [Application/Infrastructure/Model/Client/Test]

## 데이터 흐름
[주요 워크플로우의 Mermaid sequence 도식]

## 연동 지점
- **외부 API**: [목적과 함께 목록]
- **데이터베이스**: [목적과 함께 목록]
- **서드파티 서비스**: [목적과 함께 목록]

## 인프라 컴포넌트
- **인프라 정의 (IaC)**: [목적과 함께 목록, 없으면 "없음"]
- **배포 모델**: [설명, 없으면 "없음"]
- **네트워킹**: [네트워크 · 보안 구성, 없으면 "없음"]
```

## Step 4: 코드 구조 문서 생성

`aidlc-docs/inception/reverse-engineering/code-structure.md` 를 만든다:

```markdown
# 코드 구조 (Code Structure)

## 빌드 시스템
- **유형**: [Maven/Gradle/npm/pip · uv 등]
- **설정**: [주요 빌드 파일과 설정]

## 주요 클래스/모듈
[Mermaid class 도식 또는 모듈 계층]

### 기존 파일 목록
[모든 소스 파일과 그 목적 - brownfield 프로젝트에서 수정 대상 후보]

**형식 예**:
- `[path/to/file]` - [목적/책임]

## 설계 패턴
### [패턴 이름]
- **위치**: [사용된 곳]
- **목적**: [사용 이유]
- **구현**: [구현 방식]

## 핵심 의존성
### [의존성 이름]
- **버전**: [버전 번호]
- **사용**: [사용 방식과 위치]
- **목적**: [필요한 이유]
```

## Step 5: API 문서 생성

`aidlc-docs/inception/reverse-engineering/api-documentation.md` 를 만든다:

```markdown
# API 문서 (API Documentation)

## REST API
### [엔드포인트 이름]
- **Method**: [GET/POST/PUT/DELETE]
- **Path**: [/api/path]
- **목적**: [하는 일]
- **요청**: [요청 형식]
- **응답**: [응답 형식]

## 내부 API
### [인터페이스/클래스 이름]
- **메서드**: [시그니처와 함께 목록]
- **매개변수**: [매개변수 설명]
- **반환 타입**: [반환 타입 설명]

## 데이터 모델
### [모델 이름]
- **필드**: [필드 설명]
- **관계**: [관련 모델]
- **검증**: [검증 규칙]
```

## Step 6: 컴포넌트 목록 생성

`aidlc-docs/inception/reverse-engineering/component-inventory.md` 를 만든다:

```markdown
# 컴포넌트 목록 (Component Inventory)

## 애플리케이션 패키지
- [패키지 이름] - [목적]

## 인프라 패키지
- [패키지 이름] - [IaC 도구] - [목적] (없으면 "없음")

## 공용 패키지
- [패키지 이름] - [Models/Utilities/Clients] - [목적]

## 테스트 패키지
- [패키지 이름] - [Integration/Load/Unit] - [목적]

## 전체 개수
- **전체 패키지**: [개수]
- **Application**: [개수]
- **Infrastructure**: [개수]
- **Shared**: [개수]
- **Test**: [개수]
```

## Step 7: 기술 스택 문서 생성

`aidlc-docs/inception/reverse-engineering/technology-stack.md` 를 만든다:

```markdown
# 기술 스택 (Technology Stack)

## 프로그래밍 언어
- [언어] - [버전] - [용도]

## 프레임워크
- [프레임워크] - [버전] - [목적]

## 인프라
- [서비스] - [목적]

## 빌드 도구
- [도구] - [버전] - [목적]

## 테스트 도구
- [도구] - [버전] - [목적]
```

## Step 8: 의존성 문서 생성

`aidlc-docs/inception/reverse-engineering/dependencies.md` 를 만든다:

```markdown
# 의존성 (Dependencies)

## 내부 의존성
[패키지 의존성을 보여주는 Mermaid 도식]

### [패키지 A] 가 [패키지 B] 에 의존
- **유형**: [Compile/Runtime/Test]
- **이유**: [의존성이 있는 이유]

## 외부 의존성
### [의존성 이름]
- **버전**: [버전]
- **목적**: [사용 이유]
- **라이선스**: [라이선스 종류]
```

## Step 9: 코드 품질 평가 생성

`aidlc-docs/inception/reverse-engineering/code-quality-assessment.md` 를 만든다:

```markdown
# 코드 품질 평가 (Code Quality Assessment)

## 테스트 커버리지
- **전체**: [백분율 또는 Good/Fair/Poor/None]
- **단위 테스트**: [상태]
- **통합 테스트**: [상태]

## 코드 품질 지표
- **린트**: [Configured/Not configured]
- **코드 스타일**: [Consistent/Inconsistent]
- **문서화**: [Good/Fair/Poor]

## 기술 부채
- [문제 설명과 위치]

## 패턴과 안티 패턴
- **좋은 패턴**: [목록]
- **안티 패턴**: [위치와 함께 목록]
```

## Step 10: 시각 기록 파일 생성

`aidlc-docs/inception/reverse-engineering/reverse-engineering-timestamp.md` 를 만든다:

```markdown
# Reverse Engineering 메타데이터 (Reverse Engineering Metadata)

**분석 일시**: [ISO timestamp]
**분석 주체**: AI-DLC
**작업 공간**: [작업 공간 경로]
**분석한 전체 파일 수**: [개수]

## 생성한 산출물
- [x] architecture.md
- [x] code-structure.md
- [x] api-documentation.md
- [x] component-inventory.md
- [x] technology-stack.md
- [x] dependencies.md
- [x] code-quality-assessment.md
```

## Step 11: 상태 추적 갱신

`aidlc-docs/aidlc-state.md` 를 갱신한다:

```markdown
## Reverse Engineering Status
- [x] Reverse Engineering - Completed on [timestamp]
- **Artifacts Location**: aidlc-docs/inception/reverse-engineering/
```

## Step 12: 사용자에게 완료 메시지 표시

```markdown
# 🔍 Reverse Engineering 완료 (Reverse Engineering Complete)

[AI 가 작성한 분석 주요 결과 요약 (글머리표 형식)]

> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 다음 위치의 reverse engineering 산출물을 검토해 주세요: `aidlc-docs/inception/reverse-engineering/`

> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 것:**
>
> 🔧 **변경 요청 (Request Changes)** - 필요하면 reverse engineering 분석의 수정을 요청
> ✅ **승인 후 계속 (Approve & Continue)** - 분석을 승인하고 **Requirements Analysis** 로 진행
```

## Step 13: 사용자 승인 대기

- **MANDATORY (필수)**: 사용자가 명시적으로 승인할 때까지 진행하지 않는다
- **MANDATORY (필수)**: 사용자의 답변을 입력 원문 그대로 audit.md 에 기록한다
