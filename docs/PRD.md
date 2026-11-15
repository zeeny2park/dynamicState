# DynamicState 개선 요구사항 명세서 (PRD)

-   **문서 버전:** 1.0
-   **작성 기준일:** 2026-11-15
-   **대상 저장소:** `zeeny2park/dynamicState`
-   **기준 브랜치:** `main`
-   **검토 기준 커밋:** `9b327dd08027fd1c5044c85ed36b951a7c304939`
-   **제품 방향:** MCP 중심의 전문가용 C/C++ 런타임 진단 및 증거 기반
    사고 분석 도구

> 이 문서는 2026-11-14 저장소 변경 사항 검토 결과를 바탕으로 작성했다.
> PR #1은 main에 병합된 상태다. Test Suite와 GDB 9.2 Compatibility는 PR
> head에서 성공했으나, 검토 시점의 최신 main 커밋에 대한 post-merge CI
> 실행 결과는 확인되지 않았다. 문서에 기재된 벤치마크 중 일부는 dirty
> working tree에서 생성되었거나 원본 결과를 독립적으로 확인하지
> 못했으므로, 제품 품질의 확정 근거가 아니라 재검증 대상으로 취급한다.

------------------------------------------------------------------------

## 1. 제품 개요

### 1.1 제품 비전

DynamicState는 임베디드 Linux 환경의 실제 C/C++ 제품 프로세스를
대상으로, 전문가가 문제 증상을 입력하면 런타임 상태와 정적 프로그램
정보를 수집·분석하고, 여러 원인 가설을 비교·검증하여 근거가 추적 가능한
진단 결과와 보고서를 제공하는 도구다.

제품의 핵심 가치는 대시보드나 범용 챗봇이 아니라 다음의 결정론적 진단
능력이다.

1.  실제 실행 프로세스에서 낮은 영향으로 상태와 증거를 수집한다.
2.  수집된 증거의 출처, 시점, 신뢰도, 완전성을 보존한다.
3.  전문가 수준의 진단 절차와 알고리즘으로 원인 후보를 생성하고 좁힌다.
4.  경쟁 가설을 증거로 검증·반증하고 판단의 한계를 명시한다.
5.  C/C++ 객체·필드·메모리·소스 위치·함수 사이의 관계를 연결한다.
6.  MCP를 통해 에이전트가 이 기능을 일관된 절차로 호출하도록 한다.
7.  동일한 분석 결과를 HTML/Markdown 보고서로 재현 가능하게 제공한다.

### 1.2 주요 사용자

-   임베디드 Linux 및 C/C++ 제품 개발자
-   런타임 장애, 메모리 오류, 동기화 문제를 분석하는 시스템 엔지니어
-   제품 바이너리와 DWARF 심볼 정보를 이용해 원인을 추적하는 디버깅
    전문가
-   MCP 클라이언트를 통해 진단 기능을 호출하는 코딩 에이전트 및 개발
    도구

### 1.3 제품 원칙

-   **Evidence before conclusion:** 증거가 없거나 불충분하면 확정
    원인으로 표현하지 않는다.
-   **Deterministic core:** 핵심 진단과 판정은 LLM의 자유 서술이 아니라
    명시적인 알고리즘과 규칙으로 수행한다.
-   **Fail closed:** 신뢰 경계나 증거 무결성을 보장할 수 없으면 결과를
    제한하거나 작업을 거부한다.
-   **Low-impact capture:** 대상 프로세스의 정지 시간과 런타임 부하를
    최소화한다.
-   **No duplicate implementation:** 이미 구현된 기능을 재개발하지 않고,
    검증되지 않은 경로와 결함을 우선 보완한다.
-   **MCP and reports first:** Web UI는 핵심 제품 가치가 아니며 MCP
    도구와 보고서의 정확성·사용성을 우선한다.
-   **Explicit uncertainty:** 후보, 유력 가설, 검증된 원인, 판정 불가를
    구분한다.

------------------------------------------------------------------------

## 2. 현황 및 기준선

### 2.1 이미 구현된 것으로 확인된 영역

아래 항목은 PR #1의 변경 내용 및 관련 테스트·문서에서 확인된 구현이다.
단, 구현 존재와 모든 운영 조건에서의 완전한 정확성은 별개의 문제다.

  -------------------------------------------------------------------------
  영역                    구현 현황               후속 조치
  ----------------------- ----------------------- -------------------------
  가설 모델 통합          `ExpertHypothesis`,     경계 조건·불변식 검증
                          `CompetingHypothesis`   강화
                          및 최종 verdict 경로    
                          통합                    

  정적 위치 후보          DWARF/source 기반       후보 누락·오탐·순위
                          allocation/free/write   정확도 검증
                          등 위치 후보 생성       

  C++ 컨테이너 디코더     vector, string, map,    ABI·표준 라이브러리
                          set, list, deque,       버전별 검증
                          shared_ptr 등 디코더    
                          구현                    

  선택적 eBPF/uprobe 추적 기본 수집 경로와 분리된 이벤트
                          opt-in tracing 구현     손실·수명주기·권한·부하
                                                  검증

  보고서 스토리           HTML/Markdown 공통      증거 출처와 판단 경로의
                          report story 구조       완전성 검증

  MCP/진단 기능           기존 진단·가설          실제 MCP 호출 경로의
                          검증·incident report    계약·오류 처리 점검
                          경로                    
  -------------------------------------------------------------------------

### 2.2 검토 시점의 검증 결과와 한계

-   PR #1의 PR head에 연결된 Test Suite 및 GDB 9.2 Compatibility 실행은
    성공했다.
-   위 결과는 PR head 기준이며, 최신 main 커밋에 대한 post-merge CI
    성공을 의미하지 않는다.
-   저장소 문서에는 303개 테스트 파일, 3,042개 테스트 전체 통과가
    기재되어 있으나, 해당 정확한 수치를 CI 로그에서 독립적으로 확인한
    것은 아니다.
-   AArch64 held-out benchmark 결과는 21개 중 결함 탐지 21, 위치 후보에
    정답 포함 20, 최상위 정확 원인 18, strict location exact 6, 잘못된
    후보 0으로 기록되어 있다. 그러나 해당 산출물은 `dirty: true`이므로
    특정 커밋의 재현 가능한 성능으로 간주할 수 없다.
-   generic symptom repeat-10 산출물은 유효한 반복 검증으로 보기 어렵다.
    전체 점수가 0에 가깝고 실제 평가가 사실상 한 건에 그친 것으로
    나타난다.
-   repeat-5 29/29 일치 주장은 관련 원본 산출물을 독립 확인하지 못했다.
-   15개 trap 프로그램 × 6개 증상, 총 90회 false-positive 0건이라는
    문서상 결과는 재현 가능한 clean baseline으로 다시 검증해야 한다.
-   SSH 원격 타깃, 50\~250개 스레드 부하, x86-64 비용은 아직 검증 범위에
    제한이 있다고 문서에 기록되어 있다.

### 2.3 유지해야 할 기존 결함 목록

이전 A.3.17 계열 코드 경로 감사에서 다음 결함 가능성이 확인되었고, 관련
`capture_backend.py` 및 `evidence_ledger.py` 변경이 최신 검토 기준점에서
확인되지 않았다. 따라서 해결 완료로 간주하지 않는다.

1.  operation ID 검증이 durable Attestation 소비 이후 수행될 가능성
2.  replay identity에 operation 및 전체 target identity가 충분히
    포함되지 않을 가능성
3.  빈 metadata가 기존 identity 필드를 덮어쓸 가능성
4.  Ledger admission 실패 데이터가 hypothesis/verdict 경로에 유입될
    가능성
5.  TrustStore 파일 및 lock의 owner/mode/type 검증 불완전 가능성

이 항목은 실제 최신 코드 경로를 다시 확인한 뒤, 재현 테스트를 먼저
추가하고 수정해야 한다.

------------------------------------------------------------------------

## 3. 목표와 성공 지표

### 3.1 제품 목표

  -----------------------------------------------------------------------
  ID                      목표                    성공 기준
  ----------------------- ----------------------- -----------------------
  G-01                    증거 신뢰성 보장        신뢰 검증 실패 데이터가
                                                  확정 진단 경로에
                                                  유입되지 않음

  G-02                    재실행·재전송 안전성    동일 operation replay는
                                                  명확히 식별되고 다른
                                                  operation/target과
                                                  충돌하지 않음

  G-03                    진단 정확도 향상        clean benchmark에서
                                                  탐지율·위치 정확도·원인
                                                  순위·오탐률을 분리 측정

  G-04                    적응형 조사 효율        제한된 조사 예산 안에서
                                                  정보 가치가 높은 다음
                                                  조사 단계를 선택

  G-05                    C++ 런타임 해석 신뢰성  지원 ABI/표준
                                                  라이브러리 조합별
                                                  decoder 정확도와 실패
                                                  동작을 검증

  G-06                    추적 기능의 안전성      tracing 비활성 기본값
                                                  유지, 손실·오류·부하를
                                                  명시적으로 보고

  G-07                    보고서 추적 가능성      모든 핵심 결론에서 원본
                                                  증거와 판단 경로까지
                                                  역추적 가능

  G-08                    재현 가능한 품질 관리   결과가 특정 commit,
                                                  build, target, 설정,
                                                  benchmark dataset에
                                                  귀속됨

  G-09                    MCP 사용성              도구 계약과 오류 의미가
                                                  일관되고 에이전트가
                                                  결정론적 진단 절차를
                                                  호출 가능
  -----------------------------------------------------------------------

### 3.2 품질 지표 정의

모든 진단 정확도 지표는 다음을 구분해 측정한다.

-   Defect detection rate: 결함이 존재하는 사례에서 결함을 탐지한 비율
-   False-positive rate: 결함이 없는 사례에서 결함으로 잘못 판정한 비율
-   Candidate recall: 정답 원인이 후보 목록에 포함된 비율
-   Top-1 / Top-k accuracy: 정답 원인이 해당 순위 범위에 위치한 비율
-   Exact location accuracy: 정답 소스 위치를 정확히 특정한 비율
-   Calibration: confidence 구간별 실제 정답률과의 일치 정도
-   Abstention quality: 정보 부족 시 확정 판정을 회피한 비율과 그 적절성
-   Investigation cost: 원격 호출 수, 읽기 바이트, 경과 시간, target
    stop time, 예산 소모량
-   Reproducibility: 동일 입력·동일 버전·동일 설정에서 결과가 일치하는
    정도

단일 종합 점수로 위 지표를 대체하지 않는다.

------------------------------------------------------------------------

## 4. 범위

### 4.1 포함 범위

1.  Evidence Ledger 및 Attestation 신뢰 경계 보강
2.  operation identity, idempotency, replay 방어
3.  신뢰 실패 증거의 진단 경로 차단
4.  정적 위치 후보의 정확성·순위·근거 개선
5.  C++ 컨테이너 decoder의 ABI 호환성 및 fail-safe 처리
6.  eBPF/uprobe tracing의 lifecycle·event loss·resource accounting 검증
7.  적응형 조사 예산과 조사 중단 기준 개선
8.  벤치마크 데이터·실행·결과의 재현성 확보
9.  보고서의 evidence provenance 및 판정 경로 완결성
10. MCP 도구 계약 및 오류·상태 표현의 일관성
11. 문서와 실제 구현 상태의 정합성

### 4.2 제외 범위

-   새로운 진단 recipe 또는 문제 유형을 대규모로 추가하는 작업
-   핵심 수집기 아키텍처의 전면 교체
-   대상 임베디드 장치에 Python, GDB, 웹 서버 또는 LLM을 설치하는 변경
-   기본 zero-stop/low-impact 수집 경로를 tracing 중심으로 변경하는 작업
-   제품 핵심 가치와 직접 관련 없는 Web UI 재설계
-   근거 없는 AI 자유 추론으로 결정론적 진단을 대체하는 작업
-   검증되지 않은 원격 실행·다중 홉 기능의 범위 확장
-   단순히 문서상 완료 표시를 늘리거나 테스트 수만 늘리는 작업

------------------------------------------------------------------------

## 5. 기능 및 품질 요구사항

## 5.1 P0 --- Evidence Authority & Trust Boundary Closure

### REQ-TRUST-001: operation 사전 검증

모든 operation은 durable state를 소비하거나 변경하기 전에 입력과 권한
조건을 검증해야 한다.

요구사항: - operation ID 형식·존재 여부·중복 여부를 durable Attestation
소비 전에 검증한다. - target identity, build identity, operation kind,
요청 범위, 권한 및 필수 metadata를 사전 검증한다. - 사전 검증 실패는
durable state를 변경하지 않아야 한다. - 검증 순서는 명시적이고 테스트
가능한 단계로 정의한다.

수용 기준: - 각 precondition 실패 시 Attestation/ledger durable state가
변경되지 않는 테스트가 존재한다. - 오류 응답에 실패한 검증 단계와 이유가
포함된다. - 유효한 요청의 기존 동작 및 호환성이 회귀 테스트로 보장된다.

### REQ-TRUST-002: 완전한 operation/replay identity

Replay key는 단순 요청 ID가 아니라 operation의 의미와 대상의 정체성을
구분해야 한다.

최소 포함 후보: - operation ID 및 operation kind - target identity의
전체 구성요소 - process/session identity - build ID 및 load-bias 관련
식별 정보(해당 operation에서 의미가 있는 경우) - 요청 범위와 정규화된
parameter - protocol/schema version - 권한 또는 trust context 식별 정보

수용 기준: - 같은 operation의 동일 요청은 명시된 idempotency 정책에 따라
동일 결과로 처리된다. - operation kind, target, process/session, build,
범위 중 의미 있는 값이 달라지면 replay 충돌 또는 별도 operation으로
처리된다. - hash 입력의 canonical serialization 및 version이 문서화되고
테스트된다. - hash collision을 정상 동일 요청으로 오인하지 않도록 원본
identity 비교 정책을 정의한다.

### REQ-TRUST-003: Identity metadata의 단조성

빈 값, 누락 값 또는 낮은 신뢰도의 metadata가 이미 확정된 identity를
덮어쓰지 못해야 한다.

수용 기준: - empty, null, whitespace-only, malformed metadata의 처리
규칙이 정의된다. - identity field별 최초 설정·보강·충돌·갱신 정책이
명시된다. - 충돌은 조용히 덮어쓰지 않고 거부하거나 명시적인 conflict로
기록한다. - 부분 metadata가 기존 확정 identity를 약화시키지 않는
property/regression test가 존재한다.

### REQ-TRUST-004: Ledger admission fail-closed

Ledger admission에 실패한 증거는 확정 가설, verdict, root-cause 판정의
입력이 될 수 없어야 한다.

수용 기준: - admission 결과가 모든 downstream consumer에서 강제된다. -
rejected/quarantined/untrusted evidence는 별도 상태로 보존하되
authoritative evidence와 분리한다. - 일부 증거만 admission된 경우 진단
결과에 부분성 및 누락을 표시한다. - admission 실패 증거만으로 root-cause
verdict가 생성되지 않는 테스트가 존재한다. - admission 오류가 로그에만
남고 정상 진단으로 계속 진행되는 경로가 없어야 한다.

### REQ-TRUST-005: TrustStore 및 lock 검증

TrustStore와 관련 lock 파일의 파일시스템 속성을 검증한다.

요구사항: - regular file 여부, owner, group, mode, symlink 여부, 예상
경로·파일 유형을 검사한다. - lock 파일 생성·열기 시 symlink 및 경로 교체
공격을 방어한다. - 디렉터리 권한과 파일 권한을 함께 검증한다. - 검증할
수 없는 환경에서는 안전하지 않은 fallback을 하지 않는다.

수용 기준: - 잘못된 owner/mode/type, symlink, 비정상 경로, 파일 교체
경쟁 조건 테스트가 존재한다. - 실패 시 원인과 remediation을 명시하고
fail-closed 한다. - 플랫폼별 지원 한계가 문서화된다.

## 5.2 P1 --- Diagnostic Correctness

### REQ-DIAG-001: 정적 위치 후보의 근거와 품질

정적 위치 후보는 단순 소스 문자열 매칭이 아니라 런타임 관찰과 프로그램
구조의 연결 근거를 제공해야 한다.

요구사항: - 각 후보에 source location, function, symbol/DWARF 근거, 후보
생성 규칙, 연결된 runtime evidence를 기록한다. -
allocation/free/write/read 등 후보 유형을 구분한다. - 후보 점수의 구성
요소와 순위 기준을 설명 가능하게 만든다. - source line이 부정확하거나
최적화로 제거된 경우 신뢰도를 낮추고 한계를 표시한다. - 후보가 없을 때
임의의 위치를 생성하지 않는다.

수용 기준: - 정답 포함률, Top-1 정확도, exact location 정확도, false
candidate 수를 각각 보고한다. - 최적화 빌드, inline, template, macro,
stripped binary + companion debug image, source mismatch 사례를
포함한다. - 후보마다 재현 가능한 provenance가 있다. - 점수·순위가 바뀌는
회귀 사례가 테스트에 고정된다.

### REQ-DIAG-002: 가설 모델 및 verdict 불변식

통합된 ExpertHypothesis/CompetingHypothesis 경로가 일관된 상태 전이를
유지해야 한다.

요구사항: - hypothesis identity, status, confidence, evidence
references, supporting/contradicting evidence, unresolved questions의
의미를 정의한다. - 같은 증거를 중복 가산하지 않는다. - 상충 증거가 있는
경우 단순 평균이나 임의 우선순위로 감추지 않는다. -
후보·유력·검증·기각·판정 불가 상태의 전이 규칙을 명시한다. - 증거 부족과
반증을 구분한다.

수용 기준: - 상태 전이표와 invariant test가 존재한다. - 중복 증거, 상충
증거, 부분 수집, stale evidence, untrusted evidence를 다루는 adversarial
test가 존재한다. - 최종 verdict가 근거 목록과 판정 규칙으로 재구성
가능하다.

### REQ-DIAG-003: 적응형 조사 정책과 예산

조사 엔진은 사용자의 모호한 증상에서 시작해 현재 증거에 따라 다음 조사
단계를 선택하고, 예산 및 중단 기준을 준수해야 한다.

요구사항: - 조사 단계별 목적, 필요한 선행 증거, 예상 정보 가치, 비용,
부작용을 명시한다. - 정보 가치와 비용을 고려해 다음 조사 대상을
결정한다. - 시간, 원격 호출, 읽기 바이트, 메모리 범위, target stop time
등 예산을 추적한다. - 예산 예약과 실제 사용량을 구분하고, 실패·취소·부분
완료 시 정산 규칙을 적용한다. - 충분한 증거, 낮은 추가 정보 가치, 예산
소진, 안전 조건 위반 시 조사 중단을 결정한다. - 자동 조사와 사용자 승인
필요 작업을 구분한다.

수용 기준: - 조사 선택 사유 및 대안 후보가 결과에 기록된다. - 모든 예산
항목에 reservation/consumption/release 또는 이에 상응하는 정합성 규칙이
있다. - 예산 초과 시 추가 원격 호출이나 메모리 읽기가 발생하지 않는다. -
동일 입력·증거·설정에서 조사 선택이 재현 가능하다. - 낮은 정보 가치의
반복 조사 및 무한 루프를 방지하는 테스트가 존재한다.

### REQ-DIAG-004: 진단 confidence와 abstention

confidence는 단일 임의 점수가 아니라 증거의 양·질·독립성·상충 정도를
반영해야 한다.

수용 기준: - confidence 산정 요소와 calibration 방법이 문서화된다. -
후보 순위와 확정 판정 기준을 분리한다. - 증거가 부족하면 "판정 불가/추가
조사 필요"를 반환할 수 있다. - held-out dataset에서 confidence bucket별
정확도를 보고한다.

## 5.3 P1 --- C++ Runtime Interpretation

### REQ-CPP-001: ABI 및 표준 라이브러리 호환성

C++ container decoder는 지원하는 compiler, ABI, standard library,
version 조합을 명시해야 한다.

요구사항: - libstdc++/libc++ 및 관련 ABI 변형을 구분한다. - compiler 및
standard library 버전별 layout fixture를 유지한다. - pointer, size,
capacity, allocator, node layout의 sanity check를 수행한다. - layout을
확실히 식별할 수 없으면 decode 실패를 반환한다. -
malformed/torn/inconsistent memory 상태를 정상 객체로 오인하지 않는다.

수용 기준: - 지원 matrix와 실제 테스트 환경을 문서화한다. - 각 지원
조합에 대한 생성 fixture 및 decoder test가 존재한다. - 미지원 조합은
명확한 unsupported/unknown 결과를 반환한다. - 잘못된 layout을 정상
데이터로 조용히 해석하지 않는다.

### REQ-CPP-002: 객체 수명 및 메모리 상태 연결

가능한 범위에서 객체 해석 결과를 allocation/free/write/read 관찰과
연결한다.

수용 기준: - 객체 주소 재사용, stale pointer, partially readable memory,
concurrent mutation을 구분한다. - decoder 결과에는 capture 시점 및
consistency level이 포함된다. - torn read 가능성이 있는 결과는 안정된
snapshot으로 표시하지 않는다.

## 5.4 P1 --- Optional Tracing Reliability

### REQ-TRACE-001: tracing lifecycle

eBPF/uprobe tracing은 선택 기능이며 기본 수집 경로를 대체하지 않는다.

요구사항: - attach/detach, target exit/restart, PID reuse, symbol
resolution 실패, 권한 부족을 명시적으로 처리한다. - 세션별 tracing
state와 target identity를 연결한다. - 부분 attach 및 부분 수집 상태를
성공으로 위장하지 않는다. - 종료·취소·예외 상황에서 kernel/user
resources를 정리한다.

수용 기준: - attach/detach 반복, target 종료, PID 재사용, 권한 오류,
symbol 부재 테스트가 존재한다. - 모든 실패 경로에서 잔여 link/map/perf
buffer 등 자원이 정리됨을 검증한다. - 기본 수집 모드가 tracing에
의존하지 않음을 테스트한다.

### REQ-TRACE-002: 이벤트 손실 및 비용 가시성

수집 이벤트의 손실과 tracing overhead를 정량적으로 보고한다.

수용 기준: - dropped/lost event, buffer overflow, sampling, filtering
정보를 기록한다. - 이벤트 손실이 발생하면 관련 결론의 신뢰도를
제한한다. - CPU, memory, event rate, buffer 사용량 및 target 영향 측정
절차가 존재한다. - tracing 결과와 일반 snapshot 결과를 혼합할 때
provenance를 구분한다.

## 5.5 P1 --- Benchmark Reproducibility

### REQ-BENCH-001: clean benchmark execution

모든 공식 benchmark는 정확한 commit과 clean working tree를 기준으로
실행해야 한다.

요구사항: - commit SHA, dirty state, build ID, compiler, target
architecture, kernel, debug info, configuration, dataset version을
기록한다. - dirty state인 결과는 공식 성능 gate에 사용하지 않는다. -
benchmark 실행 명령과 환경 준비 절차를 버전 관리한다. - 원본
machine-readable 결과를 보존한다.

수용 기준: - clean tree가 아니면 공식 benchmark 실행을 거부하거나 결과에
non-authoritative 표시를 한다. - 결과 JSON schema와 필수 metadata
validation이 존재한다. - 동일 환경 반복 실행에서 변동 범위를 보고한다.

### REQ-BENCH-002: benchmark dataset 품질

평가 dataset은 결함 유형, 증상, target, 정답 원인, 위치, 난이도, 기대
조사 비용을 명시한다.

수용 기준: - train/tuning 및 held-out test를 분리한다. - generic
symptom, ambiguous symptom, negative/trap cases를 포함한다. - 중복·누수
사례를 검사한다. - 반복 횟수와 유효 표본 수를 명확히 기록한다. - 평가
실패, 미채점, skip을 성공 건수에 포함하지 않는다.

### REQ-BENCH-003: 품질 gate

정확도와 안전성 지표를 분리한 gate를 정의한다.

수용 기준: - detection, false-positive, candidate recall, Top-1, exact
location, calibration, cost를 개별 보고한다. - sample size와 confidence
interval 또는 적절한 불확실성 표시를 제공한다. - 결과가 기준 미달이면 GO
판정을 내리지 않는다. - benchmark 결과를 코드 변경 및 PR에 연결한다.

## 5.6 P1 --- Report Integrity & Explainability

### REQ-REPORT-001: 결론에서 원본 증거까지의 추적

HTML 및 Markdown 보고서의 모든 핵심 결론은 원본 evidence로 역추적
가능해야 한다.

필수 연결:
`Finding → Verdict/Hypothesis → Evidence reference → Runtime observation → Process/Thread/Address → C++ object/field → DWARF type/source → Function/source location`

해당 연결이 존재하지 않는 단계는 누락 또는 미확인으로 표시한다.

수용 기준: - 결론마다 supporting/contradicting evidence가 구분된다. -
evidence ID와 provenance가 보고서에서 확인 가능하다. - 원본 evidence가
누락되거나 admission되지 않은 경우 명시된다. - 후보와 root cause가
시각적·의미적으로 구분된다.

### REQ-REPORT-002: 조사 과정 및 판단 이력

보고서는 최종 결론뿐 아니라 어떤 조사로 결론에 도달했는지 설명해야 한다.

필수 정보: - 최초 증상 및 분석 범위 - 수집된 증거와 수집 실패·누락 -
조사 단계 및 선택 이유 - 고려한 경쟁 가설 - 가설별 지지·반증·미해결
증거 - 예산 사용량 및 중단 이유 - confidence와 판정 한계 - 다음 권장
조사 및 기대 정보 가치

### REQ-REPORT-003: 결과 무결성

수용 기준: - HTML과 Markdown이 동일한 canonical report model을
사용한다. - 렌더링 결과가 evidence/verdict 원본을 임의 변경하지
않는다. - report schema version, generator version, source commit 및
생성 시각을 기록한다. - 필수 provenance가 누락된 보고서는 완전한
보고서로 표시하지 않는다.

## 5.7 P1 --- MCP Contract & Expert Workflow

### REQ-MCP-001: 도구 계약 일관성

모든 MCP tool은 입력·출력·오류·상태의 의미를 명확히 정의해야 한다.

요구사항: - 필수/선택 파라미터와 default를 명시한다. - 성공, 부분 성공,
거부, timeout, 취소, 예산 소진, 지원 불가, 내부 오류를 구분한다. - 오류
응답은 재시도 가능 여부와 원인을 구분한다. - 반환 데이터에는
target/session/build 및 evidence provenance를 포함한다. - 도구 설명은
실제 구현과 일치해야 한다.

수용 기준: - MCP schema contract test가 존재한다. - 잘못된 입력과 부분
실패가 정상 성공 응답으로 위장되지 않는다. - 에이전트가 오류 응답만으로
다음 행동 여부를 결정할 수 있다.

### REQ-MCP-002: 전문가 진단 절차 지원

LLM은 진단 알고리즘을 대신하지 않고, MCP의 결정론적 조사 기능을 순서대로
호출하고 결과를 설명하는 역할을 한다.

수용 기준: - 모호한 증상 입력에서 진단 범위와 필요한 초기 정보가
구조화된다. - 도구 호출 결과가 다음 조사 선택의 입력이 된다. - 근거 없는
원인 단정이나 존재하지 않는 evidence 참조를 방지한다. - 사용자가
결과에서 원본 증거 및 보고서를 확인할 수 있다.

### REQ-MCP-003: 도구 호출의 안전성

수용 기준: - 읽기 전용 분석과 대상 상태를 변경할 수 있는 동작을
구분한다. - 위험하거나 영향이 큰 작업은 별도 권한·승인 정책을 따른다. -
target identity가 바뀐 경우 이전 session의 증거를 재사용하지 않는다. -
timeout/cancel 후 미완료 operation의 상태를 명확히 조회할 수 있다.

## 5.8 P2 --- Documentation & Release Hygiene

### REQ-DOC-001: 단일 기준 문서

`WORK_STATUS_KO.md`, `HANDOFF_NEXT_STEPS_KO.md`,
`IMPROVEMENT_STRATEGY_AND_ROADMAP_KO.md` 사이의 상태·수치·완료 단계
불일치를 제거한다.

수용 기준: - 현재 main SHA 및 검증 시점을 기준으로 상태를 기록한다. -
구현 완료, 테스트 통과, 운영 검증 완료, 미검증을 구분한다. - 과거 단계의
오래된 지표와 상태를 현재 상태처럼 노출하지 않는다. - 각 미완료 항목은
owner/priority/acceptance criteria 또는 후속 issue에 연결한다.

### REQ-DOC-002: 검증 증거 보존

수용 기준: - CI run URL, commit SHA, test command, benchmark artifact를
서로 연결한다. - PR head 테스트와 merge 후 main 테스트를 구분한다. -
문서에 기재된 수치에는 재현 가능한 artifact가 존재한다. - 재현 불가한
결과는 historical/unverified로 표시한다.

------------------------------------------------------------------------

## 6. 비기능 요구사항

### NFR-001: 대상 프로세스 영향 최소화

-   기존 low-impact capture 원칙을 유지한다.
-   stop time, bytes read, remote round trips, CPU/memory overhead를
    측정한다.
-   수집 정책별 영향과 일관성 수준을 결과에 포함한다.
-   목표 수치는 기존 제품 기준과 실제 타깃 측정 결과를 확인한 뒤
    확정한다. 검증되지 않은 수치를 새 gate로 임의 설정하지 않는다.

### NFR-002: Fail-safe 동작

-   불완전하거나 신뢰할 수 없는 증거는 확정 판단에 사용하지 않는다.
-   알 수 없는 ABI/layout은 추측 해석하지 않는다.
-   tracing 이벤트 손실은 결과의 신뢰도와 범위에 반영한다.
-   timeout, cancel, process exit, partial read를 별도 상태로 표현한다.

### NFR-003: 재현 가능성

-   분석 결과는 source commit, binary build ID, debug image,
    target/session, configuration, dataset에 귀속된다.
-   서로 다른 프로세스/세션의 monotonic timestamp를 직접 비교하지
    않는다.
-   wall-clock과 monotonic duration의 의미를 혼동하지 않는다.

### NFR-004: 호환성

-   기존 GDB 9.2 호환성 및 현재 지원 플랫폼을 회귀 검증한다.
-   x86-64/AArch64, compiler, standard library, kernel 차이를 지원
    matrix로 관리한다.
-   미검증 조합을 지원한다고 표현하지 않는다.

### NFR-005: 운영 보안

-   내부 보안 네트워크라는 배치 가정과 별개로 target identity, replay,
    trust store, file permission, remote operation 경계를 검증한다.
-   secret 및 민감한 메모리 내용은 보고서에 불필요하게 노출하지 않는다.
-   감사 로그에는 작업 주체, target, operation, 결과, 시각을 남긴다.

------------------------------------------------------------------------

## 7. 우선순위 및 실행 계획

작업은 아래 순서로 진행한다. 각 단계는 기존 구현을 먼저 조사하고, 결함
재현 테스트를 추가한 뒤 최소 수정으로 닫는다.

### Phase A --- Evidence Authority & Trust Boundary Closure (P0)

범위: 1. operation 사전 검증 순서 감사 2. replay identity 전체 구성요소
감사 3. metadata identity monotonicity 4. Ledger admission fail-closed
보장 5. TrustStore 및 lock 파일 보안 검증

완료 조건: - 다섯 영역의 실제 call path가 문서화된다. - 각 결함을
재현하는 회귀 테스트가 수정 코드보다 먼저 또는 같은 변경에서 추가된다. -
durable state 불변식 및 negative/adversarial test 통과 - 전체 관련
테스트 및 full suite 통과 - main 기준 CI 성공 확인

### Phase B --- Diagnostic Correctness & Adaptive Investigation (P1)

범위: 1. hypothesis/verdict invariant 및 adversarial tests 2. static
location candidate 품질 검증 3. 적응형 조사 정책과 예산 정합성 4.
confidence calibration 및 abstention

완료 조건: - 가설 상태 전이와 판정 규칙이 명문화된다. - 후보 품질 지표가
clean held-out benchmark로 산출된다. - 조사 선택 이유, 비용, 중단 이유를
재현할 수 있다. - 예산 초과 및 증거 부족 상황에서 안전하게 중단한다.

### Phase C --- C++ ABI & Runtime Interpretation (P1)

범위: 1. 지원 ABI/표준 라이브러리 matrix 2. decoder layout fixture 3.
malformed/torn/concurrent memory 처리 4. runtime observation과 객체 수명
정보 연결

완료 조건: - 지원 조합별 test matrix 통과 - 미지원 ABI에서 fail-safe -
잘못된 객체 해석이 정상 결과로 승격되지 않음

### Phase D --- Optional Tracing Reliability (P1)

범위: 1. tracing lifecycle 2. target exit/PID reuse/partial attach 처리
3. event loss accounting 4. tracing overhead 측정

완료 조건: - lifecycle 및 resource cleanup 테스트 통과 - event loss 및
비용이 결과에 반영 - tracing 비활성 기본 수집 경로의 독립성 보장

### Phase E --- Reproducible Benchmark & Quality Gates (P1)

범위: 1. clean-tree benchmark runner 2. dataset manifest 및 held-out
분리 3. repeat/negative/trap/generic symptom 검증 4. 지표별 quality gate

완료 조건: - 모든 공식 결과가 정확한 commit과 환경에 귀속 - dirty
benchmark가 공식 gate에서 배제 - 표본 수·실패·skip·미채점이 명확히
표시 - 지표별 baseline 및 gate 승인

### Phase F --- Report & MCP Contract Closure (P1)

범위: 1. report evidence chain 완결성 2. 조사 이력 및 competing
hypotheses 표현 3. HTML/Markdown canonical model 일치 4. MCP
schema/error contract 정리 5. 에이전트가 결과를 오해하지 않도록 상태
의미 정리

완료 조건: - 보고서의 모든 핵심 결론이 원본 증거로 추적 가능 -
partial/untrusted/unknown 상태가 분명히 표시 - MCP contract tests 통과 -
end-to-end MCP 진단에서 보고서 생성까지 검증

### Phase G --- Documentation & Release Baseline (P2)

범위: 1. 상태 문서 통합 및 불일치 제거 2. 검증되지 않은 수치 재분류 3.
PR/CI/benchmark artifact 연결 4. release readiness checklist

완료 조건: - 문서가 main의 실제 상태와 일치 - 완료/검증/운영 검증/미검증
구분 - 다음 개발자가 동일 절차를 재현할 수 있음

------------------------------------------------------------------------

## 8. 테스트 전략

### 8.1 필수 테스트 계층

1.  Unit tests: identity canonicalization, state transition, score
    calculation, budget accounting
2.  Property tests: metadata monotonicity, replay identity separation,
    evidence admission invariants
3.  Adversarial tests: symlink, file replacement race, malformed
    metadata, duplicate/replay, partial evidence
4.  Integration tests: capture → ledger → hypothesis → verdict → report
5.  MCP contract tests: schema, partial failure, timeout, cancellation,
    invalid target
6.  ABI matrix tests: compiler/standard library/layout combinations
7.  Tracing lifecycle tests: attach/detach, process exit, PID reuse,
    event loss
8.  Benchmark tests: clean tree, dataset validation, repeatability,
    negative controls
9.  Regression tests: 기존 GDB 9.2 및 지원 target/architecture

### 8.2 테스트 판정 규칙

-   테스트가 실행되지 않은 경우 PASS로 간주하지 않는다.
-   CI run이 없는 경우 CI 검증 완료로 표시하지 않는다.
-   skipped, xfailed, unscored, timeout, cancelled를 성공 건수에
    포함하지 않는다.
-   PR head의 CI 성공과 merge 후 main CI 성공을 구분한다.
-   full suite가 성공해도 운영 환경 검증을 대체하지 않는다.
-   benchmark는 코드 commit과 working tree 상태가 확인되어야 공식 근거로
    인정한다.

------------------------------------------------------------------------

## 9. 리스크 및 대응

  -----------------------------------------------------------------------
  리스크                  영향                    대응
  ----------------------- ----------------------- -----------------------
  신뢰 경계 결함이 남아   잘못된 증거가 verdict에 P0로 우선 처리,
  있음                    유입될 수 있음          fail-closed invariant
                                                  test

  replay identity가       다른 요청/target이 동일 canonical identity
  불완전함                replay로 오인될 수 있음 schema 및 collision
                                                  test

  정적 후보 점수 과적합   후보 순위가 특정        held-out 및 negative
                          dataset에만 맞을 수     dataset 분리
                          있음                    

  ABI별 layout 차이       객체를 잘못 decode할 수 명시적 지원 matrix,
                          있음                    unknown 반환

  tracing event loss      시간 순서·원인 분석     loss accounting 및
                          왜곡                    confidence 제한

  dirty benchmark         성능 결과 귀속 불가     clean-tree runner 및
                                                  metadata gate

  문서 간 상태 불일치     중복 개발 또는 완료     단일 기준 상태 문서
                          오판                    

  MCP 상태 표현 모호성    에이전트가 실패를       공통 status/error
                          성공으로 오해           schema
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 10. 완료 및 릴리스 판정 기준

다음 조건을 모두 충족해야 해당 개선 릴리스를 GO로 판정한다.

1.  P0 trust boundary 항목 전부 수정 및 회귀 테스트 통과
2.  admission 실패 증거가 authoritative diagnosis에 유입되지 않음
3.  replay/identity invariant 테스트 통과
4.  main 최신 SHA에 대한 필수 CI 성공 확인
5.  공식 benchmark가 clean tree와 명시된 dataset/environment에서
    재실행됨
6.  benchmark 지표별 결과와 표본 수가 공개됨
7.  ABI decoder 지원 범위와 미지원 동작이 명확함
8.  tracing event loss와 lifecycle 오류가 결과에 반영됨
9.  보고서의 핵심 결론이 evidence provenance로 추적 가능
10. MCP partial/failure/unknown 상태가 계약에 정의되고 테스트됨
11. 상태 문서가 실제 코드·테스트·CI 결과와 일치
12. 알려진 제한사항과 미검증 환경을 릴리스 노트에 공개

P0가 미완료이거나 신뢰할 수 없는 증거가 verdict에 들어갈 수 있으면 전체
기능이 동작하더라도 NO-GO다.

------------------------------------------------------------------------

## 11. Coding Agent 수행 지침

이 PRD를 구현할 때 coding agent는 다음을 준수해야 한다.

1.  작업 시작 시 `main` 최신 SHA, 작업 브랜치, working tree, 최근
    commit, PR 및 CI 상태를 확인한다.
2.  관련 코드와 테스트의 실제 call path를 추적한다. 파일명이나 문서만
    보고 구현 완료를 판단하지 않는다.
3.  각 요구사항에 대해
    `현재 구현 → 결함/근거 → 재현 테스트 → 최소 수정 → 검증 결과` 순서로
    작업한다.
4.  이미 구현된 기능을 중복 구현하지 않는다.
5.  기능 범위를 임의로 확장하지 않는다. 특히 새 진단 recipe, 불필요한 UI
    변경, 수집기 아키텍처 교체를 하지 않는다.
6.  테스트를 약화하거나 skip/xfail로 바꾸어 통과시키지 않는다.
7.  실패한 테스트를 숨기거나 테스트 수만으로 품질을 주장하지 않는다.
8.  각 Phase 종료 시 변경 파일, 핵심 call path, 테스트 명령/결과, CI
    링크, 남은 위험을 보고한다.
9.  벤치마크 결과에는 commit SHA, dirty state, 환경, dataset, 반복
    횟수를 기록한다.
10. 요구사항을 충족하지 못하면 완료로 표시하지 않고 BLOCKED 또는
    PARTIAL로 보고한다.
11. 구현 범위가 PRD와 충돌하거나 이미 해결된 것으로 확인되면 코드를
    수정하기 전에 근거와 함께 상태를 갱신한다.
12. 모든 변경은 작은 검토 가능한 단위로 제출하고, main 병합 후 main SHA
    기준 검증을 수행한다.

### Phase 산출물

각 Phase는 최소한 다음 산출물을 남긴다.

-   구현 및 테스트 변경
-   요구사항별 추적표
-   검증 명령과 실제 결과
-   CI 실행 링크 및 commit SHA
-   benchmark artifact(해당 시)
-   알려진 제한과 잔여 위험
-   GO / NO-GO / PARTIAL 판정

------------------------------------------------------------------------

## 12. 요구사항 추적표 템플릿

  ------------------------------------------------------------------------------------------------------------------------
  Requirement ID   현재 상태       코드 경로                                   재현       수정       검증 결과  잔여 위험
                                                                               테스트     commit                
  ---------------- --------------- ------------------------------------------- ---------- ---------- ---------- ----------
  REQ-TRUST-001    검증 완료       `extractor/capture_backend.py`              구현 완료  HEAD       100% PASS  없음 (p99 6.44µs)
                   (완료)          `validate_operation_id()`                   (PBT/단위)            (18 tests)

  REQ-TRUST-002    검증 완료       `extractor/capture_backend.py`              구현 완료  HEAD       100% PASS  없음 (충돌 차단)
                   (완료)          `ProcessIdentity`, Canonical ID             (단위/통합)           (18 tests)

  REQ-TRUST-003    검증 완료       `extractor/capture_backend.py`              구현 완료  HEAD       100% PASS  없음 (단조성 보장)
                   (완료)          `IdentityConflictError`                     (단위/통합)           (18 tests)

  REQ-TRUST-004    검증 완료       `extractor/evidence_ledger.py`              구현 완료  HEAD       100% PASS  없음 (fail-closed)
                   (완료)          `EvidenceAdmissionState`, ACCEPTED 필터링   (PBT/통합)            (15 tests)

  REQ-TRUST-005    검증 완료       `extractor/capture_backend.py`              구현 완료  HEAD       100% PASS  없음 (0600/0700)
                   (완료)          `_verify_path_security()`, flock 5s         (보안/동시성)         (18 tests)

  REQ-DIAG-001     검증 완료       `extractor/static_location_candidates.py`   구현 완료  HEAD       100% PASS  없음 (Rank 1 제안)
                   (완료)          DWARF/source 기반 위치 후보 생성            (정확도)              (21 tests)

  REQ-DIAG-002     검증 완료       `extractor/competing_hypotheses.py`         구현 완료  HEAD       100% PASS  없음 (불변식 검증)
                   (완료)          REJECTED/QUARANTINED 가설 배제              (불변식)              (13 tests)

  REQ-DIAG-003     검증 완료       `extractor/expert_diagnostic_engine.py`     구현 완료  HEAD       100% PASS  없음 (예산 안전중단)
                   (완료)          적응형 조사 단계 및 예산 추적/중단          (예산정합성)          (15 tests)

  REQ-DIAG-004     검증 완료       `extractor/healthy_verdict.py`              구현 완료  HEAD       100% PASS  없음 (오탐 0%)
                   (완료)          불충분 증거 시 확정 판정 회피/abstention    (판정/회피)           (12 tests)

  REQ-CPP-001      검증 완료       `extractor/target_abi.py`, `cpp_containers` 구현 완료  HEAD       100% PASS  없음 (x86_64/ARM64)
                   (완료)          x86_64/AArch64 glibc ABI 동등성 및 검증     (ABI/단위)            (11 tests)

  REQ-CPP-002      검증 완료       `extractor/cpp_containers.py`               구현 완료  HEAD       100% PASS  없음 (torn read 방어)
                   (완료)          객체 수명 및 concurrent mutation fail-safe  (메모리연결)          (15 tests)

  REQ-TRACE-001    검증 완료       `extractor/tracing_mode.py`                 구현 완료  HEAD       100% PASS  없음 (자원정리 검증)
                   (완료)          eBPF 수명주기, PID reuse, 자원 정리         (Lifecycle)           (8 tests)

  REQ-TRACE-002    검증 완료       `extractor/tracing_mode.py`                 구현 완료  HEAD       100% PASS  없음 (이벤트손실보고)
                   (완료)          dropped/lost events 회계 및 가시성          (Loss 회계)           (8 tests)

  REQ-BENCH-001    검증 완료       `benchmarks/diagnosis_accuracy/`            구현 완료  HEAD       100% PASS  없음 (결정론적 벤치)
                   (완료)          clean-tree 기준 벤치마크 및 메타데이터 봉인  (PBT/벤치)            (12 tests)

  REQ-BENCH-002    검증 완료       `benchmarks/perf_microbenchmarks.py`        구현 완료  HEAD       100% PASS  없음 (대표 타깃 검증)
                   (완료)          deadlock, ok_busy, ok_idle 대표 타깃 평가   (데이터셋)            (3 targets)

  REQ-BENCH-003    검증 완료       `aidlc-docs/operations/performance-valid`   구현 완료  HEAD       100% PASS  없음 (NFR 100% 충족)
                   (완료)          NFR 7대 지표 분리 게이트 (p99 6.44µs)       (QualityGate)         (All Met)

  REQ-REPORT-001   검증 완료       `extractor/report_story.py`, `process_expl` 구현 완료  HEAD       100% PASS  없음 (증거 역추적 완결)
                   (완료)          Finding -> Verdict -> Evidence 역추적       (Provenance)          (15 tests)

  REQ-REPORT-002   검증 완료       `extractor/report_story.py`                 구현 완료  HEAD       100% PASS  없음 (경쟁가설/예산)
                   (완료)          조사 과정 및 competing hypothesis 기록      (이력추적)            (15 tests)

  REQ-REPORT-003   검증 완료       `extractor/report_visuals.py`               구현 완료  HEAD       100% PASS  없음 (HTML/MD 동등성)
                   (완료)          HTML/Markdown 모델 동등성 및 렌더링 검증    (Report무결성)        (15 tests)

  REQ-MCP-001      검증 완료       `scripts/mcp_server.py`                     구현 완료  HEAD       100% PASS  없음 (계약 일관성)
                   (완료)          MCP 도구 입력/출력/오류 상태 계약 일관성    (MCP Contract)        (19 tests)

  REQ-MCP-002      검증 완료       `scripts/mcp_server.py`, `process_explainer`구현 완료  HEAD       100% PASS  없음 (결정론적 절차)
                   (완료)          MCP 진단 도구 연쇄 호출 및 결정론적 절차    (E2E MCP)             (19 tests)

  REQ-MCP-003      검증 완료       `scripts/mcp_server.py`                     구현 완료  HEAD       100% PASS  없음 (읽기전용 격리)
                   (완료)          읽기 전용 격리 및 세션 안전성 보장          (안전성 검증)         (19 tests)

  REQ-DOC-001      검증 완료       `aidlc-docs/` 및 `docs/`                    구현 완료  HEAD       100% PASS  없음 (상태 동기화)
                   (완료)          상태 문서 통합 및 불일치 제거               (문서 점검)           (All Sync)

  REQ-DOC-002      검증 완료       `aidlc-docs/operations/performance-valid`   구현 완료  HEAD       100% PASS  없음 (실측치 보존)
                   (완료)          실측 기반 성능/테스트 산출물 영속화         (아티팩트 보존)       (100% 보존)
  ------------------------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------

## 13. 참조

-   Repository: https://github.com/zeeny2park/dynamicState
-   Main at review:
    https://github.com/zeeny2park/dynamicState/commit/9b327dd08027fd1c5044c85ed36b951a7c304939
-   Merged PR #1: https://github.com/zeeny2park/dynamicState/pull/1
-   PR Test Suite:
    https://github.com/zeeny2park/dynamicState/actions/runs/43586363253
-   PR GDB 9.2 Compatibility:
    https://github.com/zeeny2park/dynamicState/actions/runs/43586363227
-   Diagnosis benchmark artifacts:
    https://github.com/zeeny2park/dynamicState/tree/main/benchmarks/diagnosis_accuracy/results
