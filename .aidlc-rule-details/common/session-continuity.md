# 세션 이어가기 템플릿 (Session Continuity Templates)

## 복귀 환영 프롬프트 템플릿
사용자가 기존 AI-DLC 프로젝트의 작업을 이어가려고 돌아오면 다음 프롬프트를 보여준다:

```markdown
**다시 오신 것을 환영합니다! 진행 중인 AI-DLC 프로젝트가 있습니다.**

aidlc-state.md 기준 현재 상태:
- **프로젝트**: [project-name]
- **현재 Phase**: [INCEPTION/CONSTRUCTION/OPERATIONS]
- **현재 Stage**: [Stage Name]
- **마지막 완료**: [Last completed step]
- **다음 단계**: [Next step to work on]

**오늘은 어떤 작업을 하시겠습니까?**

A) 중단한 곳부터 계속 ([Next step description])

B) 이전 stage 검토 ([Show available stages])

[Answer]: 
```

## MANDATORY (필수): 세션 이어가기 지시 사항
1. 기존 프로젝트를 감지하면 **항상 aidlc-state.md 를 먼저 읽는다**
2. 워크플로우 파일에서 **현재 상태를 파싱**하여 프롬프트를 채운다
3. **MANDATORY (필수): 이전 Stage 산출물 불러오기** - 어떤 stage 든 재개하기 전에, 이전 stage 의 관련 산출물을 모두 자동으로 읽는다:
   - **Reverse Engineering**: architecture.md, code-structure.md, api-documentation.md 를 읽는다
   - **Requirements Analysis**: requirements.md, requirement-verification-questions.md 를 읽는다
   - **User Stories**: stories.md, personas.md, story-generation-plan.md 를 읽는다
   - **Application Design**: application-design 산출물 (components.md, component-methods.md, services.md) 을 읽는다
   - **Design (Units)**: unit-of-work.md, unit-of-work-dependency.md, unit-of-work-story-map.md 를 읽는다
   - **Unit 별 설계 (Per-Unit Design)**: unit 별 산출물은 `aidlc-docs/construction/{unit-name}/` 아래
     `functional-design/`, `nfr-requirements/`, `nfr-design/`, `infrastructure-design/`
     하위 폴더에 있다. 재개 시 `aidlc-state.md` 에서 진행 중인 unit 을 확인하고, 그 unit 의
     설계 산출물과 그 unit 이 의존하는 모든 unit 의 설계 산출물
     (`unit-of-work-dependency.md` 기준) 을 불러온다. 각 하위 폴더의 정확한 파일 목록은
     해당 construction stage 규칙에 나와 있다.
   - **코드 Stage**: 모든 코드 파일, 계획, 그리고 이전의 모든 산출물을 읽는다
4. **Stage 별 맞춤 맥락 불러오기**:
   - **초기 Stage (Workspace Detection, Reverse Engineering)**: 작업 공간 (workspace) 분석 결과를 불러온다
   - **Requirements/Stories**: reverse engineering + requirements 산출물을 불러온다
   - **설계 Stage**: requirements + stories + architecture + 설계 산출물을 불러온다
   - **코드 Stage**: 모든 산출물 + 기존 코드 파일을 불러온다
5. 아키텍처 선택과 현재 phase 에 맞춰 **선택지를 조정**한다
6. 일반적인 설명 대신 **구체적인 다음 단계를 보여준다**
7. 이어가기 프롬프트를 시각 (timestamp) 과 함께 audit.md 에 **기록한다**
8. **맥락 요약**: 산출물을 불러온 뒤, 무엇을 불러왔는지 사용자가 알 수 있게 짧게 요약한다
9. **질문하기**: 명확화 질문이나 사용자 의견 질문은 항상 .md 파일에 담아서 한다. 객관식 질문을 채팅 세션 안에 직접 쓰지 않는다.

## 오류 처리
세션 재개 중 산출물이 없거나 손상된 경우, 복구 절차는 [error-handling.md](error-handling.md) 를 참조한다.
