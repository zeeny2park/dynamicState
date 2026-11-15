# NFR 성능 · 확장성 가이드 (NFR Performance and Scalability Guide)

> 이 가이드는 Security Engineer (NFR Requirements stage 의 lead agent) 가 가진 전체 NFR 요구사항 가이드를 보충한다. NFR Requirements · NFR Design stage 에서 인프라 관점으로 기여하는 DevOps Engineer 에게 필요한 성능 · 확장성 부분을 제공한다.

## 성능 요구사항 기준 정하기 (Performance Requirement Benchmarking)

### 성능 요구사항 정의 방법
모든 성능 요구사항은 다음을 명시해야 한다.
- **지표 (Metric)**: 무엇을 측정하는지 (응답 시간, 처리량, 자원 사용량)
- **목표 (Target)**: 정량 임계값
- **백분위 (Percentile)**: 목표가 적용되는 백분위 (p50, p95, p99)
- **부하 조건 (Load condition)**: 목표가 유지되어야 하는 동시성 · 트래픽 조건
- **측정 방법 (Measurement method)**: 지표를 어떻게, 어디서 수집하는지

### 애플리케이션 유형별 흔한 성능 목표

| 애플리케이션 유형 | 지표 | 목표 | 백분위 | 비고 |
|-----------------|--------|--------|------------|-------|
| 웹 애플리케이션 (대화형) | 페이지 로드 시간 | < 2s | p95 | First contentful paint |
| REST API (동기) | 응답 시간 | < 200ms | p99 | 네트워크 전송 제외 |
| 검색 쿼리 | 결과 전달 | < 500ms | p95 | 순위 계산 포함 |
| 배치 처리 | 처리량 | N records/min | Average | 최소 허용 속도 정의 |
| 실시간 메시징 | 종단 간 지연 시간 | < 100ms | p99 | 전송부터 전달까지 |
| 파일 업로드 | 처리 시간 | < 5s per MB | p95 | 업로드 후 처리 |

### 성능 반-요구사항 (Performance Anti-Requirements)
비합리적인 기대는 명시적으로 배제한다.
- "시스템은 빨라야 한다" (측정 불가)
- "모든 페이지가 즉시 로드된다" (목표 없음, 백분위 없음)
- "무제한 사용자를 처리한다" (용량 경계 없음)

다음처럼 바꾼다: "대시보드 페이지는 동시 사용자 500명에서 p95 기준 < 3초 안에 로드된다."

## 확장성 평가 틀 (Scalability Assessment Frameworks)

### 용량 계획 템플릿 (Capacity Planning Template)

| 차원 | 현재 | 6개월 목표 | 12개월 목표 | 확장 방식 |
|-----------|---------|---------------|-----------------|-------------------|
| 동시 사용자 | N | N * X | N * Y | 수평 자동 확장 |
| 데이터 양 | N GB | N * X GB | N * Y GB | 파티셔닝 전략 |
| 초당 요청 수 | N | N * X | N * Y | 로드 밸런서 + 복제본 |
| 저장소 증가 속도 | N GB/month | N * X GB/month | N * Y GB/month | 계층형 저장소 정책 |

### 확장성 요구사항 형식
```
NFR-SCALE-NNN: [Scalability Requirement]
Current baseline: [measured current capacity]
Target capacity: [required capacity at specific timeline]
Growth model: [linear, exponential, seasonal, step-function]
Scaling approach: [horizontal, vertical, partitioning, caching]
Cost constraint: [infrastructure cost must remain below $X/month at target scale]
Degradation policy: [what degrades first when approaching capacity limits]
```

### 확장 결정 표 (Scaling Decision Matrix)

| 신호 | Scale Up (수직 확장) | Scale Out (수평 확장) | 먼저 최적화 |
|--------|----------|-----------|----------------|
| CPU 가 계속 > 70% | 단일 인스턴스 워크로드 | 상태 없는 (stateless) 서비스 | 비효율적인 알고리즘 확인 |
| 메모리 압박 | 메모리 내 처리 | 분산 캐시 | 메모리 누수 확인 |
| I/O 대기 > 30% | 더 빠른 저장소 등급 | 읽기 복제본, 샤딩 | 쿼리 최적화, 인덱싱 |
| 큐 깊이 증가 | 더 빠른 consumer | consumer 인스턴스 추가 | 배치 크기 조정 |
| 연결 풀 고갈 | 풀 크기 확대 | 연결 다중화 | 연결 누수 조사 |

> 출처: awslabs/aidlc-workflows v2.11.2 `core/knowledge/aidlc-operations-agent/nfr-performance-guide.md` (MIT-0)
