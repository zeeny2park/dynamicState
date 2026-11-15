# Operations 참고 자료 (Reference)

Operations stage 를 진행할 때 관점으로 참고하는 역할 문서와 지식 문서다. 이 키트는 서브에이전트를 실행하지 않는다. 규칙은 `operations/*.md` 가 정하고, 이 폴더는 참고만 한다.

| 파일 | 원본 경로 | 무엇을 담는지 | 참고하는 stage |
| --- | --- | --- | --- |
| `agent-pipeline-deploy.md` | `core/agents/aidlc-pipeline-deploy-agent.md` | CI/CD · 배포 전략 · 롤백 · 릴리스 관리 역할과 원칙 | Deployment Pipeline, Deployment Execution |
| `agent-operations.md` | `core/agents/aidlc-operations-agent.md` | 관측 · SLO · 장애 대응 · 카오스 · 운영 피드백 역할과 원칙 | Observability Setup, Incident Response, Feedback & Optimization |
| `observability-patterns.md` | `core/knowledge/aidlc-operations-agent/observability-patterns.md` | 지표 · 로그 · 추적, 황금 신호, 대시보드 · 알람, 로그 쿼리 | Observability Setup |
| `slo-sli-patterns.md` | `core/knowledge/aidlc-operations-agent/slo-sli-patterns.md` | SLI 유형, SLO 목표 정하기, 오류 예산 정책, 소진 속도 알림 | Observability Setup, Feedback & Optimization |
| `incident-response-guide.md` | `core/knowledge/aidlc-operations-agent/incident-response-guide.md` | 심각도 수준, 상향 보고 표, 당번, 사후 검토, runbook, RTO/RPO | Incident Response |
| `nfr-performance-guide.md` | `core/knowledge/aidlc-operations-agent/nfr-performance-guide.md` | 성능 요구사항 형식, 유형별 목표, 용량 계획, 확장 결정 표 | Performance Validation (원본 lead = Quality Agent) |

- 특정 클라우드 서비스 예시는 도구 중립 표현으로 정리했다
- 산출물 경로는 `operations/operations.md` 의 경로 규칙 (`aidlc-docs/operations/<slug>/`) 을 따른다

> 출처: awslabs/aidlc-workflows v2.11.2 `core/agents/`, `core/knowledge/aidlc-operations-agent/` (MIT-0) 를 한국어로 번역 · 1.0 키트에 맞게 정리 (AWS Platform Agent 제외)
