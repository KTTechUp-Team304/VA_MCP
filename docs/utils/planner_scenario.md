# ScenarioPlanner / Scenario 레이어 상세 설계 문서

> **작성일**: 2026.05.11
> **작성자**: 최민준
> **버전**: 1.0.0
> **대상 코드**: `src/va_mcp/planner/`, `src/va_mcp/scenario/`, `src/va_mcp/core/`

---

## 1. 개요

본 문서는 VA-MCP 파이프라인에서 **ScenarioPlanner**와 **Scenario 레이어**가 어떤 기준으로 어떻게 판단을 내리는지 상세히 기술한다.

### 1.1 파이프라인에서의 위치

```
EndpointProfile
    → FeatureExtractor
    → FeatureSet
    → ScenarioPlanner       ← 이 문서 범위
    → ScenarioPlan
    → Scenario              ← 이 문서 범위
    → Orchestrator
    → Tools
    → ScenarioResult
    → EndpointReport
```

### 1.2 각 컴포넌트의 책임

| 컴포넌트 | 입력 | 출력 | 책임 |
|---|---|---|---|
| `ScenarioPlanner` | `FeatureSet` | `PlannerOutput` | OWASP 시나리오 후보 선정 및 실행할 tool_id 목록 결정 |
| `ScenarioPlanBuilder` | `PlannerOutput` + `EndpointProfile` | `list[ScenarioPlan]` | OWASP 카테고리별 실행 계획 수립 |
| `Scenario` | `ScenarioPlan` | `ScenarioResult` | Orchestrator에 위임 후 결과 수집 및 POC 생성 |
| `ScenarioRunner` | `PlannerOutput` + `EndpointProfile` | `EndpointReport` | 전체 파이프라인 조율 및 최종 결과 집계 |

---

## 2. ScenarioPlanner 판단 기준 (V3.1)

### 2.1 판단 원칙

- ScenarioPlanner는 **"실행 후보 선정"만** 담당한다. 취약 여부를 확정하지 않는다.
- 최종 판단 근거는 각 Tool이 반환하는 `ToolResult`다.
- FeatureSet이 `dataclass`이든 `dict`이든 동일하게 동작한다 (`_get()` 패턴).
- `need_more_context`는 Planner만 반환한다. Tool/Scenario는 `status=skipped`만 사용한다.

### 2.2 OWASP 카테고리별 선정 규칙

> **상세 도구 선정 기준**: `docs/utils/planner_tool_selection.md` 참고
> 각 카테고리 내 도구는 FeatureSet 신호별 개별 조건으로 선정된다.

#### A01 — Broken Access Control (접근 제어 취약점)

```
카테고리 선정: requires_auth = True

도구별 조건:
  idor_bola       : requires_auth AND has_resource_identifier AND auth_contexts >= 2
  bfla            : requires_auth AND (has_admin_feature OR has_role_restriction)
  rbac_check      : requires_auth AND (has_admin_feature OR has_role_restriction) AND auth_contexts >= 2
  forced_browsing : requires_auth (항상)
  http_method_tamper: requires_auth AND is_state_changing
  parameter_tamper: requires_auth AND (has_enum_input OR has_user_input)
  cors_check      : requires_auth (항상)

need_more_context: has_resource_identifier=True이지만 auth_contexts < 2인 경우
  → missing에 "auth_contexts" 추가
```

**매핑 툴**: `idor_bola`, `bfla`, `rbac_check`, `forced_browsing`, `http_method_tamper`, `parameter_tamper`, `cors_check`

---

#### A02 — Security Misconfiguration (보안 설정 오류) — Baseline

```
선정 조건: 조건 없음. 항상 선정.
```

**선정 이유**: 보안 헤더 누락, CORS 오설정, 민감 경로 노출, 디버그 엔드포인트 노출 등은 모든 API에서 기본적으로 확인해야 하는 항목이다.

**매핑 툴**: `security_headers`, `cors_misconfiguration`, `error_info_exposure`, `sensitive_path`, `directory_listing`, `debug_endpoint`, `default_config`

---

#### A03 — Software Supply Chain Failures (소프트웨어 공급망 실패)

```
선정 조건: has_dependency_exposure = True
```

**매핑 툴**: 현재 미구현 (placeholder)

---

#### A04 — Cryptographic Failures (암호화 실패)

```
도구별 조건:
  insecure_jwt           : has_secret_handling AND (is_login_endpoint OR requires_auth)
  cookie_security        : is_login_endpoint OR has_secret_handling
  sensitive_data_exposure: has_secret_handling OR returns_sensitive_data OR has_debug_feature
```

**매핑 툴**: `insecure_jwt`, `cookie_security`, `sensitive_data_exposure`

---

#### A05 — Injection (인젝션)

```
도구별 조건:
  sql_injection  : has_user_input AND (has_free_text_input OR has_enum_input)
  cmd_injection  : has_user_input AND has_free_text_input AND (has_debug_feature OR has_file_or_config_surface)
  xss_reflected  : has_user_input AND has_free_text_input
  ssti_injection : has_user_input AND has_free_text_input
  header_injection: has_user_input
  path_traversal : has_user_input AND (has_file_or_config_surface OR has_free_text_input)
```

**매핑 툴**: `sql_injection`, `cmd_injection`, `xss_reflected`, `ssti_injection`, `header_injection`, `path_traversal`

---

#### A06 — Insecure Design (불안전한 설계)

```
도구별 조건:
  rate_limit_check   : is_state_changing
  resource_exhaustion: is_state_changing AND has_user_input
  business_logic_check: is_state_changing AND has_state_field
```

**매핑 툴**: `rate_limit_check`, `resource_exhaustion`, `business_logic_check`

---

#### A07 — Authentication Failures (인증 실패)

```
도구별 조건:
  auth_bruteforce : is_login_endpoint OR has_credential_fields
  auth_lockout    : is_login_endpoint OR has_credential_fields
  auth_rate_limit : is_login_endpoint OR has_credential_fields
  auth_jwt        : requires_auth
  auth_session    : requires_auth
  auth_enum       : (is_login_endpoint OR has_credential_fields) AND auth_contexts >= 2
```

**매핑 툴**: `auth_bruteforce`, `auth_lockout`, `auth_rate_limit`, `auth_jwt`, `auth_session`, `auth_enum`

---

#### A08 — Software or Data Integrity Failures (소프트웨어 및 데이터 무결성 실패)

```
도구별 조건:
  http_method_tamper  : has_file_or_config_surface AND is_state_changing
  parameter_tamper    : has_file_or_config_surface AND has_user_input
  business_logic_check: has_file_or_config_surface AND is_state_changing
```

**매핑 툴**: `http_method_tamper`, `parameter_tamper`, `business_logic_check`

---

#### A09 — Security Logging and Alerting Failures (보안 로깅 및 알럿 실패)

```
선정 조건: has_logging_feature = True
```

**매핑 툴**: 현재 미구현 (placeholder)

---

#### A10 — Mishandling of Exceptional Conditions (예외 처리 부적절) — Baseline

```
선정 조건: 조건 없음. 항상 선정.
malformed_input: has_user_input=True 시 우선 실행.
```

**매핑 툴**: `stack_trace_exposure`, `timeout_handling`, `error_code_consistency`, `retry_handling`, `malformed_input`

---

### 2.3 need_more_context 계약

```
반환 주체: ScenarioPlanner만 반환. Scenario/Tool은 반환하지 않음.

발생 조건: A01 선정 시도 중 조건 미충족
  - requires_auth = True인데
  - has_resource_identifier = True이고
  - auth_contexts < 2인 경우

반환 구조:
  need_more_context = True
  missing = ["auth_contexts"]           # auth_contexts가 2 미만일 때

동작:
  - ScenarioRunner는 need_more_context=True 확인 시 Orchestrator를 호출하지 않고 즉시 반환
  - 사용자에게 부족한 정보를 보완해 재요청하도록 안내
```

### 2.4 tool_ids 중복 제거 및 순서 보존

A08의 `http_method_tamper`, `parameter_tamper`는 A01에도 포함되어 있고, `business_logic_check`는 A06과 A08에 모두 포함되어 있다. 여러 OWASP 카테고리가 동시에 선정될 때 동일한 tool_id가 중복될 수 있으므로, `_dedup()` 함수로 **삽입 순서를 유지하면서 중복을 제거**한다.

```python
def _dedup(ids: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for tid in ids:
        if tid not in seen:
            seen.add(tid)
            result.append(tid)
    return result
```

---

## 3. Scenario 레이어 동작 기준

### 3.1 ScenarioPlanBuilder

PlannerOutput의 `owasp_candidates`를 순회하며 OWASP 카테고리별로 `ScenarioPlan`을 1개씩 생성한다.

```
입력: PlannerOutput(owasp_candidates=["A02","A01","A07"], ...) + EndpointProfile
출력: [
  ScenarioPlan(owasp="A02", tool_ids=["security_headers",...], endpoint=profile),
  ScenarioPlan(owasp="A01", tool_ids=["idor_bola",...],   endpoint=profile),
  ScenarioPlan(owasp="A07", tool_ids=["auth_bruteforce",...], endpoint=profile),
]
```

각 계획의 `tool_ids`는 `PlannerOutput.tool_ids`를 그대로 사용한다. Planner가 FeatureSet 신호별 개별 조건으로 선정한 도구 목록이 담겨 있다.

### 3.2 Scenario 실행 조건

```
tool_ids가 비어 있거나 endpoint가 None이면:
  → Orchestrator 미호출, 빈 ScenarioResult 반환 (A09 케이스)

그 외:
  → Orchestrator.run(tool_ids, endpoint) 호출
  → 결과로 POC 생성 후 ScenarioResult 반환
```

**Scenario는 판단하지 않는다.** 실행을 Orchestrator에 위임하고 결과를 수집·집계하는 역할만 한다.

### 3.3 POC 자동 생성

`ToolResult.status == "vulnerable"`인 결과가 있을 때 자동으로 재현 가능한 텍스트를 생성한다.

```
[A01] 취약점 2건 발견
- idor_bola: 다른 사용자 정보 조회 가능
  재현: GET /api/users/2 → HTTP 200
  근거: user_a 권한으로 user_b 데이터 조회됨
- bfla: 관리자 기능 접근 가능
  재현: DELETE /api/admin/users/3 → HTTP 200
  근거: 일반 사용자로 관리자 전용 기능 실행됨
```

취약점이 없으면 `poc = ""`로 반환한다.

### 3.4 ScenarioRunner 흐름

```
1. PlannerOutput.need_more_context 확인
   → True: EndpointReport(need_more_context=True, missing=[...]) 즉시 반환
   → False: 다음 단계 진행

2. ScenarioPlanBuilder.build() → list[ScenarioPlan]

3. 각 ScenarioPlan에 대해 Scenario.run() 실행

4. 모든 ScenarioResult를 EndpointReport로 집계하여 반환
```

---

## 4. 핵심 데이터 구조

### PlannerOutput

```python
@dataclass
class PlannerOutput:
    owasp_candidates: list[str]   # 선정된 OWASP 카테고리 목록
    tool_ids: list[str]           # 실행할 tool_id 목록 (중복 제거, 순서 보존)
    need_more_context: bool       # 추가 정보 필요 여부
    missing: list[str]            # 부족한 입력 키 목록
```

### ScenarioPlan

```python
@dataclass
class ScenarioPlan:
    owasp: str                      # OWASP 카테고리 코드
    tool_ids: list[str]             # 해당 카테고리의 tool_id 목록
    endpoint: EndpointProfile | None  # 대상 엔드포인트
```

### ScenarioResult

```python
@dataclass
class ScenarioResult:
    owasp: str                       # OWASP 카테고리 코드
    tool_results: list[ToolResult]   # 각 Tool 실행 결과
    poc: str                         # POC 텍스트 (취약점 발견 시 자동 생성)
```

### EndpointReport

```python
@dataclass
class EndpointReport:
    profile: EndpointProfile           # 분석 대상 엔드포인트
    scenario_results: list[ScenarioResult]  # OWASP별 결과 목록
    need_more_context: bool            # 추가 정보 필요 여부
    missing: list[str]                 # 부족한 입력 키 목록
    generated_at: str                  # 분석 시각 (ISO-8601 UTC 자동 기록)
```

---

## 5. 서비스 계층 연동 (endpoint_analysis.py)

```python
# 실행 흐름
raw_input (dict)
    → parse_endpoint_profile()     # EndpointProfile 파싱·정규화·검증
    → FeatureExtractor.extract()   # FeatureSet 자동 추출
    → ScenarioPlanner.plan()       # OWASP 후보 선정

# 반환 케이스
1. invalid_input   : EndpointProfile 파싱 실패 (base_url 누락 등)
2. need_more_context: A01 조건 미충족 (auth_contexts 부족 등)
3. analyzed        : 정상 분석 완료 → owasp_candidates, tool_ids 반환
```

---

## 6. 파일 구조

```
src/va_mcp/
├── core/
│   ├── planner_output.py     # PlannerOutput 타입 정의
│   ├── scenario_plan.py      # ScenarioPlan 타입 정의
│   ├── scenario_result.py    # ScenarioResult 타입 정의
│   └── endpoint_report.py    # EndpointReport 타입 정의
├── planner/
│   ├── planner.py            # ScenarioPlanner (판단 로직)
│   ├── rules.py              # OWASP_TOOL_MAP (카테고리 → tool_id 매핑)
│   ├── baseline.py           # A02/A10 baseline tool_id 상수
│   └── __init__.py
└── scenario/
    ├── scenario.py           # Scenario (실행 위임 + POC 생성)
    ├── builder.py            # ScenarioPlanBuilder
    ├── runner.py             # ScenarioRunner (파이프라인 진입점)
    ├── _types.py             # OrchestratorProtocol 인터페이스
    └── __init__.py
```