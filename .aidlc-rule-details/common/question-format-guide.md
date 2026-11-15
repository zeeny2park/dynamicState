# 질문 형식 가이드 (Question Format Guide)

## MANDATORY (필수): 모든 질문은 이 형식을 따른다

### 규칙: 채팅으로 질문하지 않는다
**CRITICAL (필수)**: 채팅에서 직접 질문하는 일은 절대 없어야 한다. 모든 질문은 전용 질문 파일에 작성한다.

### 질문 파일 형식

#### 파일 이름 규칙
- 내용을 알 수 있는 이름 사용: `{phase-name}-questions.md`
- 예:
  - `classification-questions.md`
  - `requirements-questions.md`
  - `story-planning-questions.md`
  - `design-questions.md`

#### 질문 구조
모든 질문에는 의미 있는 선택지와 함께 마지막 선택지로 "Other" 를 둔다:

```markdown
## Question [Number]
[명확하고 구체적인 질문 내용]

A) [첫 번째 의미 있는 선택지]

B) [두 번째 의미 있는 선택지]

[...필요한 만큼 선택지 추가...]

X) Other (please describe after [Answer]: tag below)

[Answer]: 
```

**CRITICAL (필수)**:
- 모든 질문에서 "Other" 는 **반드시** 마지막 선택지로 둔다
- 의미 있는 선택지만 넣는다 - 칸을 채우려고 선택지를 지어내지 않는다
- 선택지 수는 상황에 맞게 늘리거나 줄인다 (최소 2개 + Other)
- **각 선택지 사이에는 빈 줄을 둔다** → 엄격한 CommonMark 렌더러 (IntelliJ, PyCharm 등) 에서 선택지가 한 문단으로 합쳐지지 않고 줄마다 따로 표시됨

### 전체 예시

```markdown
# 요구사항 확인 질문 (Requirements Clarification Questions)

요구사항을 명확히 하기 위해 다음 질문에 답해 주세요.

## Question 1
주된 사용자 인증 방식은 무엇입니까?

A) 아이디와 비밀번호

B) 소셜 로그인 (Google, Facebook)

C) Single Sign-On (SSO)

D) 다중 인증 (Multi-factor authentication)

E) Other (please describe after [Answer]: tag below)

[Answer]: 

## Question 2
웹 애플리케이션입니까, 모바일 애플리케이션입니까?

A) 웹 애플리케이션

B) 모바일 애플리케이션

C) 웹과 모바일 모두

D) Other (please describe after [Answer]: tag below)

[Answer]: 

## Question 3
신규 프로젝트입니까, 기존 코드베이스입니까?

A) 신규 프로젝트 (greenfield)

B) 기존 코드베이스 (brownfield)

C) Other (please describe after [Answer]: tag below)

[Answer]: 
```

### 사용자 응답 형식
사용자는 [Answer]: 태그 뒤에 선택지 문자를 적어 답한다:

```markdown
## Question 1
주된 사용자 인증 방식은 무엇입니까?

A) 아이디와 비밀번호

B) 소셜 로그인 (Google, Facebook)

C) Single Sign-On (SSO)

D) 다중 인증 (Multi-factor authentication)

[Answer]: C
```

### 사용자 응답 읽기
사용자가 답변 완료를 알린 뒤:
1. 질문 파일을 읽는다
2. [Answer]: 태그 뒤의 답을 추출한다
3. 모든 질문에 답했는지 확인한다
4. 응답을 바탕으로 분석을 진행한다

### 객관식 작성 지침

#### 선택지 수
- 최소: 의미 있는 선택지 2개 + "Other" (A, B, C)
- 보통: 의미 있는 선택지 3-4개 + "Other" (A, B, C, D, E)
- 최대: 의미 있는 선택지 5개 + "Other" (A, B, C, D, E, F)
- **CRITICAL (필수)**: 칸을 채우려고 선택지를 지어내지 않는다 - 의미 있는 선택지만 넣는다

#### 선택지 품질
- 선택지끼리 서로 겹치지 않게 한다
- 가장 흔한 상황을 포괄한다
- 의미 있고 현실적인 선택지만 넣는다
- **"Other" 는 항상 마지막 선택지로 넣는다** (MANDATORY, 필수)
- 구체적이고 명확하게 쓴다
- **A, B, C, D 칸을 채우려고 선택지를 지어내지 않는다**

#### 좋은 예:
```markdown
## Question 5
어떤 데이터베이스 기술을 사용합니까?

A) 관계형 (PostgreSQL, MySQL)

B) NoSQL 문서형 (MongoDB, DynamoDB)

C) NoSQL 키-값 (Redis, Memcached)

D) 그래프 데이터베이스 (Neo4j, Neptune)

E) Other (please describe after [Answer]: tag below)

[Answer]: 
```

#### 나쁜 예 (피할 것):
```markdown
## Question 5
어떤 데이터베이스를 사용합니까?

A) 예

B) 아니요

C) 아마도

[Answer]: 
```

### 워크플로 연계

#### Step 1: 질문 파일 생성
```markdown
모든 질문을 담아 aidlc-docs/{phase-name}-questions.md 생성
```

#### Step 2: 사용자에게 알림
```
"{phase-name}-questions.md 에 질문 [X]개를 작성했습니다. 
각 질문의 [Answer]: 태그 뒤에 선택지 문자를 적어 답해 주세요. 
맞는 선택지가 없으면 마지막 선택지 (Other) 를 고르고 원하는 내용을 적어 주세요. 다 끝나면 알려 주세요."
```

#### Step 3: 완료 확인 대기
사용자가 "done", "completed", "finished", "완료했어" 또는 비슷한 말을 할 때까지 기다린다.

#### Step 4: 읽고 분석
```
aidlc-docs/{phase-name}-questions.md 읽기
모든 답 추출
누락 여부 확인
분석 진행
```

### 오류 처리

#### 답이 없는 경우
[Answer]: 태그가 비어 있으면:
```
"Question [X] 에 답이 없습니다. 진행하기 전에 모든 질문에 
선택지 문자 중 하나로 답해 주세요."
```

#### 답이 잘못된 경우
답이 유효한 선택지 문자가 아니면:
```
"Question [X] 의 답 '[answer]' 이 유효하지 않습니다. 
질문에 제시된 선택지 문자만 사용해 주세요."
```

#### 답이 모호한 경우
사용자가 문자 대신 설명을 적었으면:
```
"Question [X] 에 대해 답과 가장 가까운 선택지 문자를 적어 주세요. 
맞는 것이 없으면 'Other' 를 고르고 [Answer]: 태그 뒤에 설명을 덧붙여 주세요."
```

### 모순 · 모호함 감지

**MANDATORY (필수)**: 사용자 응답을 읽은 뒤 **반드시** 모순과 모호함을 점검한다.

#### 모순 감지
논리적으로 맞지 않는 답을 찾는다:
- 범위 불일치: "버그 수정" 인데 "코드베이스 전체에 영향"
- 위험 불일치: "낮은 위험" 인데 "호환성을 깨는 변경 (breaking changes)"
- 일정 불일치: "빠른 수정" 인데 "여러 하위 시스템"
- 영향 불일치: "단일 컴포넌트" 인데 "큰 아키텍처 변경"

#### 모호함 감지
불분명하거나 경계에 걸친 응답을 찾는다:
- 여러 분류에 모두 해당할 수 있는 답
- 구체성이 부족한 응답
- 여러 질문에 걸쳐 서로 엇갈리는 신호

#### 확인 질문 작성
모순이나 모호함을 발견하면:

1. **확인 질문 파일 생성**: `{phase-name}-clarification-questions.md`
2. **문제 설명**: 어떤 모순 · 모호함을 발견했는지 명확히 적는다
3. **겨냥한 질문**: 객관식 형식으로 문제를 해소할 질문을 한다
4. **원래 질문 참조**: 어느 질문들의 답이 서로 충돌했는지 보여 준다

**예시**:
```markdown
# [Phase Name] 확인 질문 (Clarification Questions)

응답에서 확인이 필요한 모순을 발견했습니다:

## Contradiction 1: [간단한 설명]
"[Answer A]" (Q[X]:[Letter]) 라고 답하셨지만 "[Answer B]" (Q[Y]:[Letter]) 라고도 답하셨습니다.
[설명] 때문에 두 응답은 서로 모순됩니다.

### Clarification Question 1
[모순을 해소할 구체적인 질문]

A) [첫 번째 답 쪽으로 정리하는 선택지]

B) [두 번째 답 쪽으로 정리하는 선택지]

C) [절충안 선택지]

D) [질문 자체를 다시 정의하는 선택지]

[Answer]: 

## Ambiguity 1: [간단한 설명]
Q[X] 에 대한 응답 ("[Answer]") 은 [설명] 때문에 모호합니다.

### Clarification Question 2
[모호함을 해소할 구체적인 질문]

A) [명확한 선택지 1]

B) [명확한 선택지 2]

C) [명확한 선택지 3]

D) [명확한 선택지 4]

[Answer]: 
```

#### 확인 질문 워크플로

1. **감지 (Detect)**: 모든 응답에서 모순 · 모호함을 분석한다
2. **생성 (Create)**: 문제가 있으면 확인 질문 파일을 만든다
3. **알림 (Inform)**: 사용자에게 문제와 확인 질문 파일을 알린다
4. **대기 (Wait)**: 사용자가 확인 답변을 줄 때까지 진행하지 않는다
5. **재검증 (Re-validate)**: 확인 답변 뒤 일관성을 다시 점검한다
6. **진행 (Proceed)**: 모든 모순이 해소된 뒤에만 진행한다

#### 사용자 메시지 예시
```
"응답에서 모순 2건을 발견했습니다:

1. 버그 수정 범위 vs. 코드베이스 영향 (Q1 vs Q2)
2. 낮은 위험 vs. 호환성을 깨는 변경 (Q7 vs Q4)

이를 해소하기 위해 classification-clarification-questions.md 에 질문 2개를 작성했습니다.
분류를 진행하기 전에 이 확인 질문에 답해 주세요."
```

### 모범 사례

1. **구체적으로**: 질문은 명확하고 모호하지 않아야 한다
2. **빠짐없이**: 필요한 정보를 모두 다룬다
3. **간결하게**: 질문 하나는 주제 하나에 집중한다
4. **실용적으로**: 선택지는 현실적이고 실행 가능해야 한다
5. **일관되게**: 모든 질문 파일에서 같은 형식을 쓴다

### Phase 별 예시

#### 의미 있는 선택지 2개 예시:
```markdown
## Question 1
신규 프로젝트입니까, 기존 코드베이스입니까?

A) 신규 프로젝트 (greenfield)

B) 기존 코드베이스 (brownfield)

C) Other (please describe after [Answer]: tag below)

[Answer]: 
```

#### 의미 있는 선택지 3개 예시:
```markdown
## Question 2
배포 대상은 어디입니까?

A) 클라우드 (AWS, Azure, GCP)

B) 사내 서버 (On-premises)

C) 하이브리드 (클라우드와 사내 서버 모두)

D) Other (please describe after [Answer]: tag below)

[Answer]: 
```

#### 의미 있는 선택지 4개 예시:
```markdown
## Question 3
어떤 아키텍처 패턴을 사용해야 합니까?

A) 모놀리식 아키텍처

B) 마이크로서비스 아키텍처

C) 서버리스 아키텍처

D) 이벤트 기반 아키텍처

E) Other (please describe after [Answer]: tag below)

[Answer]: 
```

## 요약

**기억할 것**: 
- ✅ 항상 질문 파일을 만든다
- ✅ 항상 객관식 형식을 쓴다
- ✅ **"Other" 는 항상 마지막 선택지로 넣는다 (MANDATORY, 필수)**
- ✅ 의미 있는 선택지만 넣는다 - 칸을 채우려고 지어내지 않는다
- ✅ 항상 [Answer]: 태그를 쓴다
- ✅ 항상 사용자의 완료 알림을 기다린다
- ✅ 항상 응답의 모순을 점검한다
- ✅ 필요하면 항상 확인 질문 파일을 만든다
- ✅ 진행 전에 항상 모순을 해소한다
- ❌ 채팅으로 질문하지 않는다
- ❌ A, B, C, D 를 채우려고 선택지를 지어내지 않는다
- ❌ 답 없이 진행하지 않는다
- ❌ 모순이 해소되지 않은 채 진행하지 않는다
- ❌ 모호한 응답을 추측으로 해석하지 않는다
