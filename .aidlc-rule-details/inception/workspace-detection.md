# Workspace Detection

**목적**: 작업 공간 (workspace) 상태를 파악하고 기존 AI-DLC 프로젝트가 있는지 확인

## Step 1: 기존 AI-DLC 프로젝트 확인

`aidlc-docs/aidlc-state.md` 가 있는지 확인한다:
- **있으면**: 마지막 phase 부터 재개한다 (이전 phase 의 맥락을 불러온다)
- **없으면**: 새 프로젝트 평가를 계속한다

## Step 2: 작업 공간의 기존 코드 탐색

**작업 공간에 기존 코드가 있는지 판단한다:**
- 작업 공간에서 소스 코드 파일을 탐색한다 (.java, .py, .js, .ts, .jsx, .tsx, .kt, .kts, .scala, .groovy, .go, .rs, .rb, .php, .c, .h, .cpp, .hpp, .cc, .cs, .fs 등)
- 빌드 파일을 확인한다 (pom.xml, package.json, build.gradle 등)
- 프로젝트 구조를 나타내는 단서를 찾는다
- 작업 공간 최상위 폴더를 확인한다 (aidlc-docs/ 가 아님)

**발견 내용을 기록한다:**
```markdown
## Workspace State
- **Existing Code**: [Yes/No]
- **Programming Languages**: [List if found]
- **Build System**: [Maven/Gradle/npm/etc. if found]
- **Project Structure**: [Monolith/Microservices/Library/Empty]
- **Workspace Root**: [Absolute path]
```

## Step 3: 다음 Phase 결정

**작업 공간이 비어 있으면 (기존 코드 없음)**:
- 플래그 설정: `brownfield = false`
- 다음 phase: Requirements Analysis

**작업 공간에 기존 코드가 있으면**:
- 플래그 설정: `brownfield = true`
- `aidlc-docs/inception/reverse-engineering/` 에 기존 reverse engineering 산출물이 있는지 확인한다
- **reverse engineering 산출물이 있으면**:
    - 산출물이 오래되었는지 확인한다 (산출물 시각과 코드베이스의 마지막 주요 수정 시각을 비교)
    - **산출물이 최신이면**: 불러온 뒤 Requirements Analysis 로 건너뛴다
    - **산출물이 오래되었으면**: 다음 phase 는 Reverse Engineering (다시 실행해 산출물 갱신)
    - **사용자가 다시 실행을 명시적으로 요청하면**: 오래되었는지와 상관없이 다음 phase 는 Reverse Engineering
- **reverse engineering 산출물이 없으면**: 다음 phase 는 Reverse Engineering

## Step 4: 초기 상태 파일 생성

`aidlc-docs/aidlc-state.md` 를 만든다:

```markdown
# AI-DLC State Tracking

## Project Information
- **Project Type**: [Greenfield/Brownfield]
- **Start Date**: [ISO timestamp]
- **Current Stage**: INCEPTION - Workspace Detection

## Workspace State
- **Existing Code**: [Yes/No]
- **Reverse Engineering Needed**: [Yes/No]
- **Workspace Root**: [Absolute path]

## Code Location Rules
- **Application Code**: Workspace root (NEVER in aidlc-docs/)
- **Documentation**: aidlc-docs/ only
- **Structure patterns**: See code-generation.md Critical Rules

## Stage Progress
[Will be populated as workflow progresses]
```

## Step 5: 완료 메시지 표시

**Brownfield (기존 코드) 프로젝트:**
```markdown
# 🔍 Workspace Detection 완료 (Workspace Detection Complete)

작업 공간 분석 결과:
• **프로젝트 유형**: Brownfield 프로젝트
• [AI 가 작성한 작업 공간 분석 결과 요약 (글머리표)]
• **다음 stage (승인 후)**: 기존 코드베이스를 분석하는 **Reverse Engineering** (기존 산출물이 있으면 **Requirements Analysis**)

> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 것:**
>
> 🔧 **변경 요청 (Request Changes)** - 작업 공간 분석 결과의 수정을 요청
> ✅ **승인 후 계속 (Approve & Continue)** - 분석을 승인하고 **[Reverse Engineering 또는 Requirements Analysis]** 로 진행
```

**Greenfield (신규) 프로젝트:**
```markdown
# 🔍 Workspace Detection 완료 (Workspace Detection Complete)

작업 공간 분석 결과:
• **프로젝트 유형**: Greenfield 프로젝트
• **다음 stage (승인 후)**: **Requirements Analysis**

> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 것:**
>
> 🔧 **변경 요청 (Request Changes)** - 작업 공간 분석 결과의 수정을 요청
> ✅ **승인 후 계속 (Approve & Continue)** - 분석을 승인하고 **Requirements Analysis** 로 진행
```

## Step 6: 사용자 승인 대기

- **MANDATORY (필수)**: 사용자가 명시적으로 승인할 때까지 다음 stage 로 진행하지 않는다 (자동 진행 없음, 과정판)
- **MANDATORY (필수)**: 사용자의 답변을 입력 원문 그대로 audit.md 에 기록한다
- 승인 후 다음 stage:
  - **Brownfield**: Reverse Engineering (기존 산출물이 없는 경우) 또는 Requirements Analysis (산출물이 있는 경우)
  - **Greenfield**: Requirements Analysis
