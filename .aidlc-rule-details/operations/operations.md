# Operations

**목적 (Purpose)**: Construction 에서 만들고 테스트한 소프트웨어를 배포하고, 관측 · 장애 대비 · 성능 검증 · 운영 개선까지 이어간다.

**상태 (Status)**: 한국어 확장판 기능. AI-DLC 2.x 의 Operation phase (Stage 4.1~4.7) 를 1.0 규칙 형식으로 옮긴 것이다.

## Stage 구성

| 순서 | 상세 규칙 파일 | Stage | 교안 이름 | 목적 | 주요 산출물 |
| --- | --- | --- | --- | --- | --- |
| 1 | `operations/deployment-pipeline.md` | Deployment Pipeline | 파이프라인 구성 | 배포 흐름 · 전략 · 롤백 절차 | cd-config, deployment-strategy, rollback-runbook |
| 2 | `operations/environment-provisioning.md` | Environment Provisioning | 환경 준비 | 대상 환경 준비 · 검증 | environment-inventory, validation-report |
| 3 | `operations/deployment-execution.md` | Deployment Execution | 배포 실행 | 배포 · smoke test · health check | deployment-log, smoke-test-results, health-check-report |
| 4 | `operations/observability-setup.md` | Observability Setup | 관측 설정 | SLO · 지표 · 알람 · 로그 조회 | dashboards, alarms, slo-config, log-queries |
| 5 | `operations/incident-response.md` | Incident Response | 장애 대응 | runbook · 장애 대응 계획 · 연락 체계 | runbooks, incident-plan, escalation-matrix |
| 6 | `operations/performance-validation.md` | Performance Validation | 성능 검증 | 부하 테스트 · NFR 목표 검증 | load-test-plan, test-results, nfr-validation-matrix |
| 7 | `operations/feedback-optimization.md` | Feedback & Optimization | 운영 피드백 | SLO · 비용 · drift 점검, 개선 과제 | slo-report, cost-analysis, drift-report, feedback-loop |

## 실행 원칙

- 모든 stage 는 CONDITIONAL 이다. Workflow Planning 이 실행 계획에서 stage 별로 EXECUTE / SKIP 을 정한다
- 순서는 위 표 순서로 고정한다. SKIP 된 stage 는 건너뛰고 다음 EXECUTE stage 로 간다
- phase 단위로 1회 실행한다 (unit 별 반복이 아니다). 모든 unit 의 Build and Test 가 끝난 뒤 시작한다
- 실행 계획에 EXECUTE 인 Operations stage 가 하나도 없으면 workflow 는 Build and Test 승인으로 끝난다
- 마지막으로 실행한 stage 를 승인하면 workflow 를 완료한다. 운영 피드백에서 나온 개선 과제는 새 "Using AI-DLC" 요청으로 시작한다 (Workspace Detection → INCEPTION)

## 경로 규칙

- 계획 + 질문 파일: `aidlc-docs/operations/plans/<slug>-plan.md` (`[Answer]:` 태그 포함)
- 산출물: `aidlc-docs/operations/<slug>/<artifact>.md`
- `<slug>` = 상세 규칙 파일 이름 (예: `deployment-pipeline`)
- 실제 설정 파일 (파이프라인 설정, IaC, 스크립트 등) 을 만들거나 고칠 때는 1.0 코드 위치 규칙을 따른다: 작업 공간 루트에 두고, aidlc-docs/ 안에는 절대 (NEVER) 두지 않는다
- 참고 자료: `operations/reference/README.md` (stage 진행 시 해당 역할 · 지식 문서를 참고한다)

## 공통 안전 규칙 (MANDATORY (필수), 모든 Operations stage 에 적용)

1. **실재하는 대상만 사용**: 배포 대상 · 환경 · 도구는 작업 공간의 설정 파일, 이전 산출물, 사용자 답변으로 확인된 것만 사용한다. 없는 환경 · 배포 경로 · CI 나 인프라 산출물을 지어내지 않는다. 확인할 수 없으면 질문하거나 SKIP 한다
2. **외부 영향 명령은 사람 확인 후에만**: 배포, 인프라 변경, 부하 테스트, 데이터 이전처럼 작업 공간 밖에 영향을 주는 명령은 계획 승인 + 실행 직전 사용자 확인을 받은 뒤에만 실행한다. 운영 (production) 환경은 기본적으로 명령만 제시하고 사람이 실행한다
3. **롤백 단계 필수**: 모든 배포 절차에 롤백 단계를 둔다. 모든 변경을 되돌리는 방법을 문서화한다
   - blue/green 이나 canary 전략은 트래픽 전환 기준과 중단 조건을 문서화한다
4. **검증 전 성공 선언 금지**: smoke test · health check 를 통과하기 전에는 배포 성공을 선언하지 않는다. 운영 배포에는 정해진 smoke test 또는 health check 가 반드시 있어야 한다
5. **SLO 는 수치로**: SLO 는 구체적인 비율과 기간으로 정의한다 (예: "30일 이동 기간 동안 가용성 99.9%"). 알람 기준은 SLO 위반보다 앞서 울리도록 정해 대응 시간을 확보한다
   - 새 서비스 · 컴포넌트마다 health 지표와 오류율 지표를 최소 1개씩 둔다
6. **비밀값 기록 금지**: 비밀값 · 토큰 · 계정 ID 를 산출물, 질문 파일, audit.md 에 기록하지 않는다. 식별이 필요하면 마스킹한다 (예: 계정 `********1234`)
7. **P1 · P2 장애는 사후 검토**: P1 · P2 장애마다 사후 검토 (post-incident review) 로 경과, 근본 원인, 재발 방지책을 기록한다. runbook 에는 상향 보고 (escalation) 경로와 연락처를 넣는다
8. **조건 미충족 stage 는 SKIP**: 실행 조건을 충족하지 못하면 SKIP 하고 사유를 audit.md 와 aidlc-state.md 에 기록한다. 빈 산출물을 만들지 않는다

**인프라 안전**: 인프라 변경은 보안 검토를 거치고 변경마다 보안 영향을 문서화한다. 기존 보안 통제는 명시적 승인과 문서화된 근거 없이 제거하거나 우회하지 않는다. 권한 (계정 · 역할 등), 네트워크 정책, 암호화 설정 변경에는 위험 평가를 포함한다.

## 승인 방식

- 모든 stage 는 표준 2-선택지 완료 메시지를 사용한다: `🔧 **변경 요청 (Request Changes)**` / `✅ **다음 Stage 로 진행 (Continue to Next Stage)**`
- 즉흥적인 3-선택지 메뉴를 만들지 않는다 (DO NOT use emergent behavior)
- 각 stage 의 승인 응답은 원문 그대로 audit.md 에 기록하고, aidlc-state.md 의 OPERATIONS 절 해당 행을 갱신한다

> 출처: awslabs/aidlc-workflows v2.11.1 `docs/reference/04-stages/operation.md`, `core/memory/phases/operation.md` (MIT-0) 를 1.0 형식으로 변환
