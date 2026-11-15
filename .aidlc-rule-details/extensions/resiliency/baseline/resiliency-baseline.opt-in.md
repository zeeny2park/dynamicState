# Resiliency Baseline — Opt-In (사용 동의)

**확장 (Extension)**: Resiliency Baseline

## Opt-In 질문 (Opt-In Prompt)

이 확장이 로드되면, 다음 질문이 Requirements Analysis 의 확인 질문에 자동으로 포함된다:

```markdown
## Question: 복원력 확장 (Resiliency Extensions)
이 프로젝트에 복원력 기준 (resiliency baseline) 을 적용할까요?

**이 확장이 하는 일.** 활성화하면 복원력 있는 시스템을 만들기 위한 **방향 제시용 · 설계 단계 모범 사례** 묶음을 적용합니다. 이 모범 사례는 **AWS Well-Architected Framework (Reliability Pillar)** 와 복원력 검토 지침에서 가져온 것입니다. 요구사항 · 설계 · 코드를 장애 허용 (fault tolerance), 고가용성, 관측 가능성 (observability), 복구 가능성 쪽으로 이끌며, 비즈니스 목표, 변경 관리, 관측 가능성, 고가용성, 재해 복구, 지속적 개선에 걸친 15개 실천 영역을 다룹니다.

**이 확장이 하지 않는 일.** 활성화해도 워크로드가 운영 환경에 바로 투입 가능한 상태 (production-ready) 가 되지는 **않으며**, 어떤 가용성 · RTO · RPO 목표도 인증하거나 보장하지 않습니다. 좋은 복원력 결정을 초기에 잡아 주는 **출발점**일 뿐이며, 완성된 시스템에 대한 정식 **AWS Well-Architected Review** 를 대신하지 않습니다.

결과물은 이후 보완 · 검증해 나갈, 근거 있는 **복원력 태세 초안**으로 다루십시오. 완성된 결과나 운영 인증을 받은 결과가 아닙니다.

A) 예 — 복원력 기준을 방향 제시용 모범 사례 및 설계 단계 지침으로 적용 (비즈니스 핵심 워크로드에 권장. 운영 개시 전에 검증 · 강화할 수 있는, 근거 있는 출발점)

B) 아니오 — 복원력 기준 생략 (신뢰성보다 빠른 반복이 중요한 PoC, 프로토타입, 실험 프로젝트에 적합)

X) Other (please describe after [Answer]: tag below)

[Answer]: 
```
