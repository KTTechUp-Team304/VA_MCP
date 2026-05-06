# VA-MCP 구현 가이드

이 문서는 [MCP_ARCHITECTURE_V3.md](./MCP_ARCHITECTURE_V3.md)를 코드로 옮기기 위한 **구체적인 구현 순서·계약·디렉터리 가이드**이다. 출력 구조(`ToolResult` 등)는 기존 공통 스키마를 유지하고, 엔진 레이어(FeatureExtractor → Planner → Orchestrator)를 추가한다.

> **작성일**: 2026.05.05 
> **작성자**: 이윤재
> **버전**: 1.2.0

---

## 1. 목적 및 범위

| 구분 | 내용 |
|------|------|
| 목적 | Endpoint 입력 → Feature → OWASP/도구 후보 → Tool 실행 → 리포트까지의 파이프라인을 구현 가능한 단위로 쪼갠다 |
| 전제 | `ToolInput` / `ToolResult`는 `va_mcp.core.schemas`를 그대로 사용한다 |
| Planner만 반환 | `need_more_context`는 Planner 단계에서만 반환한다. Tool은 `status=skipped`만 사용한다 |

---

## 2. 패키지 배치 (본 프로젝트 기준)

레이어별 패키지로 구성한다. [MCP_ARCHITECTURE_V3.md](./MCP_ARCHITECTURE_V3.md) 파이프라인과 폴더명을 맞춘다. 패키지명은 하이픈 대신 **스네이크 케이스**를 사용한다 (`feature_extractor`, `planner`, …).

### 공통 타입 위치: 모두 `core` 아래로 통합

**별도 최상위 패키지 `models/`는 두지 않는다.** 기존에 `models`로 설계했던 엔진 계약 타입은 **`va_mcp.core`로 이동**하여, Tool 공통 스키마(`ToolInput`, `ToolResult` 등)와 **같은 패키지 안에서** 스키마·enum을 관리한다.

- 예: `core/endpoint_profile.py`, `core/feature_set.py`, `core/planner_output.py` 등 모듈로 분리하거나, 팀 규칙에 맞게 파일명만 조정한다.
- `EndpointProfile` 등은 `ToolInput`/`ApiRequest`와 **역할이 다르므로** 타입명과 모듈 경로만 명확히 구분한다.
- 순환 import는 모듈 분리로 회피한다.

### 디렉터리 구조 (코드 레이아웃)

`feature_extractor`, `planner`, `scenario`, `orchestrator` 등을 **레이어별 디렉터리로 나눈 이유**는 다음이다.

- **책임 분리:** 각 단계의 변경이 다른 레이어에 새지 않게 한다.
- **컴포넌트화:** 단위 테스트·교체(예: Planner 규칙만 교체)가 쉽다.
- **디버깅 용이:** 호출 스택과 패키지 경로가 파이프라인 단계와 대응된다.

```text
src/va_mcp/
├── core/                    # 모든 공통 타입·스키마·enum (Tool + 엔진 계약)
├── feature_extractor/
│   └── ...
├── planner/
│   └── ...
├── scenario/
│   └── ...
├── orchestrator/
│   └── ...
├── registry/
│   └── tool_registry.py
├── tools/
└── app.py / server 진입점
```

`scenario`가 MVP에서 얇으면, 처음에는 planner 출력을 orchestrator가 바로 도구 목록으로 넘기고, 시나리오 조합은 이후에 채워도 된다.

엔진 계약 타입(`EndpointProfile`, `FeatureSet`, `PlannerOutput` 등)은 **`va_mcp.core` 하위 모듈에만** 정의한다.

---

## 3. Phase 0 — 계약(타입) 고정

구현 첫 작업은 **JSON 직렬화 가능한 데이터 클래스**(또는 Pydantic)로 아래를 한 파일에 모으는 것이다.

### 3.1 EndpointProfile

[MCP_ARCHITECTURE_V3.md](./MCP_ARCHITECTURE_V3.md) §2와 동일한 필드를 유지한다.

- `auth_contexts`는 **`None` 또는 리스트**만 허용하고, Python에서는 `list | None = None` + 사용 시 `profile.auth_contexts or []` 패턴을 쓴다. **mutable default(`= []`)는 금지**한다.

### 3.2 FeatureSet

v3 §3의 필드 전체 + 문서에 정의된 보강 플래그(`has_dependency_exposure`, `has_secret_handling`, `has_file_or_config_surface` 등)를 포함한다.

### 3.3 Planner 출력 (권장 스키마)

Planner가 반환하는 객체는 최소한 아래를 갖춘다.

```text
PlannerOutput (필수 권장 필드)
├── need_more_context: bool
├── owasp_runs: list[str]           # "A01", "A02", … 선택 결과 (로깅·리포트용)
├── tool_ids: list[str]             # 실행할 tool_id (snake_case, Registry의 tool_id와 일치)
├── missing: list[str]              # need_more_context True일 때 부족한 입력 키
└── notes: str | None               # 디버그용 옵션
```

선택적으로 두면 운영·디버깅에 유리한 필드:

```text
(선택 필드)
├── rules_version: str              # Planner 규칙 세트 버전 (문서/코드 동기화·재현성)
├── warnings: list[str]             # 부분 실행·가정 적용 등 경고
├── blocking_reason: str | None     # need_more_context일 때 사람이 읽기 쉬운 한 줄 이유
├── tool_hints: dict[str, dict]     # tool_id별 Orchestrator 힌트 (예: auth 순서, extra 키)
└── features_snapshot: FeatureSet | None  # planner 입력 스냅샷 (리포트·감사용)
```

- `need_more_context is True`이면 Orchestrator는 **Tool을 호출하지 않고** 이 결과만 MCP 클라이언트에 돌려준다. 이후 고도화에서는 `missing`/`blocking_reason`을 보완해 **같은 요청을 재시도**하는 흐름으로 다듬는다.
- `tool_ids`에 A02/A10 **baseline**에 해당하는 tool_id를 Planner가 항상 포함하도록 v3 규칙과 코드를 맞춘다. baseline 목록은 **상수**로 `planner/` 패키지 안의 전용 모듈(예: `baseline.py`, `constants.py`)에 둔다.

### 3.4 엔진 ↔ 기존 ToolInput 매핑

Orchestrator가 각 tool을 부를 때는 기존 `ToolInput`을 조립한다.

**사용자 입력(EndpointProfile)은 tools까지 내려가야 한다.** `FeatureSet`만으로는 HTTP 재현에 필요한 `method`, `path`, `body`, 실제 토큰 등이 없으므로, Tool 실행 단계에서는 **원본 `EndpointProfile`(또는 이와 동등한 요청 스냅샷)**을 유지한다. `FeatureSet`은 Planner 판단용이고, `ToolInput` 조립의 주 소스는 **항상 EndpointProfile + Planner의 tool별 힌트**다.

| 소스 | ToolInput 필드 |
|------|----------------|
| `EndpointProfile.base_url` | `TargetInfo.base_url` |
| method, path, headers, query, params, body | `ApiRequest` |
| `auth_contexts` | `AuthContext` 리스트 (도구별 순서 규약은 tools 문서에 따름) |
| 타임아웃 등 | `ToolOptions` |

도구마다 `auth[0]`/`auth[1]` 의미가 다르므로, **도구별 최소 입력 표**를 [TOOLS_DEV_GUIDE.md](../dev_docs/TOOLS_DEV_GUIDE.md) 또는 각 tool 모듈 상단 주석과 동일하게 유지한다.

---

## 4. Phase 1 — FeatureExtractor

**역할:** `EndpointProfile` → `FeatureSet` (순수 함수에 가깝게).

**구현 요령**

- body/query/params 존재 여부로 `has_user_input` 등을 계산한다.
- path는 **보조 신호**로만 사용한다 (예: `/admin`, `/debug` 키워드 → `has_admin_feature` 등). v3 원칙과 충돌하지 않게 주석으로 “보조”임을 명시한다.
- `description` 문자열에서 login, keyword/search 등 힌트가 있으면 Feature에 반영할지 팀 규칙으로 정한다 (MVP에서는 단순 키워드 매칭만 해도 된다).

**테스트:** 고정된 `EndpointProfile` 샘플 5~10개에 대해 기대 `FeatureSet`을 스냅샷 또는 assertion으로 검증한다.

---

## 5. Phase 2 — ScenarioPlanner

**역할:** `FeatureSet` (+ 필요 시 `EndpointProfile` 일부) → `PlannerOutput`.

**구현 요령**

- [MCP_ARCHITECTURE_V3.md](./MCP_ARCHITECTURE_V3.md) §4 Planner 기준과 §5 Scenario 실행 조건을 **동일한 조건식**으로 구현한다. 문서와 코드가 어긋나면 Planner 단위 테스트에서 바로 드러나게 한다.
- OWASP 코드마다 **매핑된 tool_id 목록**을 상수 테이블로 둔다 (예: `A01` → `idor_bola`, `bfla`, …). 초기에는 1:1로 시작해도 된다. 여기서 말하는 것은 **Registry가 도구에 “호출 번호”를 매기는 것이 아니라**, Planner 코드 안의 **문자열 상수 매핑**(OWASP 코드 → `tool_id` 리스트)이다. 실행 시에는 Registry가 **`tool_id`(문자열)** 로 등록된 `BaseTool` 인스턴스를 찾는다.
- `need_more_context`: 예를 들어 A01 시나리오가 `auth_contexts` 2개와 `resource_context`를 요구하는데 없으면 `missing`에 `"auth_contexts"`, `"resource_context"`를 넣는다. v3 §7 계약을 따른다.

**테스트:** FeatureSet 입력 조합 → 기대 `tool_ids` / `need_more_context` / `missing`을 표 기반으로 검증한다.

---

## 6. Phase 3 — Orchestrator

**역할:** `PlannerOutput` → 선택된 각 `BaseTool.run(ToolInput)` 호출 → `list[ToolResult]` 수집.

**구현 요령**

- `need_more_context`가 True면 **루프 없이** 즉시 반환한다.
- `tool_ids`를 순회하며 Registry에서 tool 인스턴스를 얻어 `run(tool_input)`을 호출한다. 동일 tool_id 중복은 제거할지 정책으로 정한다 (기본은 중복 제거 권장).
- 선택적으로 `ScenarioResult` / `EndpointReport` 집계 객체를 두되, MVP에서는 `ToolResult` 리스트만 반환해도 된다.

---

## 7. Phase 4 — MCP 어댑터

**역할:** MCP 클라이언트가 엔진을 호출할 수 있게 한다.

**본 프로젝트는 “단계 분리”만 채택한다.** 소스 레이어를 `feature_extractor` / `planner` / `scenario` / `orchestrator` 등으로 나눈 것과 같이, MCP에서도 **계획 조회**와 **도구 실행**을 분리해 책임을 나누고, 계획 단계만 재실행하거나 입력 보완 후 실행 단계만 다시 호출하기 쉽게 한다.

**MCP tool 구성 (고정):**

- `plan_endpoint` — 입력(dict/JSON)을 `EndpointProfile`로 파싱한 뒤 FeatureExtractor → ScenarioPlanner까지 수행하고, **`PlannerOutput`만** 반환한다.
- `run_tools` — 확정된 `tool_ids`와 `EndpointProfile`(및 필요 시 Planner의 `tool_hints`)을 받아 Orchestrator로 **`list[ToolResult]`** 를 반환한다.

**계약:** 클라이언트는 `plan_endpoint`에서 `need_more_context`이면 입력을 보완한 뒤 다시 `plan_endpoint`를 호출하거나, 보완된 프로필로 `run_tools`를 호출한다. 한 번의 MCP 호출로 전 파이프라인을 끝내는 **단일 entry MCP tool은 제공하지 않는다.**

---

## 8. Phase 5 — Tool 레지스트리 및 실무 체크

### 8.1 하위 패키지 등록

현재 `tool_registry`가 `va_mcp.tools` **직속 모듈만** 스캔한다면, `access_control/idor_bola.py` 같은 **중첩 패키지의 도구가 MCP에 노출되지 않을 수 있다**. 구현 시 다음 중 하나를 적용한다.

- `pkgutil.walk_packages` 등으로 **재귀적으로** `BaseTool` 서브클래스를 수집한다.
- 또는 도구를 한 모듈에서 re-export하는 방식을 쓴다.

### 8.2 baseline 도구와 문서 일치

A02/A10 baseline에 포함하는 `tool_id`는 Planner 상수와 실제 등록된 MCP tool 이름이 **완전히 일치**해야 한다.

### 8.3 출력 스키마

도구의 반환은 기존 `ToolResult` 규칙을 따른다. 엔진은 출력 형식을 바꾸지 않는다.

---

## 9. 테스트 전략 (요약)

| 레이어 | 최소 테스트 |
|--------|-------------|
| FeatureExtractor | 프로필 샘플 → FeatureSet 고정값 |
| ScenarioPlanner | FeatureSet/프로필 → PlannerOutput 표 검증 |
| Orchestrator | 모의 Registry 또는 실제 tool mock → 호출 순서/스킵 조건 |
| Registry | 중첩 패키지 도구가 discover되는지 스모크 |

---

## 10. 작업 순서 체크리스트

구현 시 아래 순서를 권장한다.

1. [ ] 공통 타입 정의 (`va_mcp.core` 하위 모듈): `EndpointProfile`, `FeatureSet`, `PlannerOutput`
2. [ ] `FeatureExtractor` + 단위 테스트
3. [ ] `ScenarioPlanner` + 단위 테스트 (v3 표와 동기화)
4. [ ] `Orchestrator` + 통합 테스트 (need_more_context 시 tool 미호출)
5. [ ] `tool_registry` 재귀 탐색(또는 동등 조치) 확인
6. [ ] MCP에 `plan_endpoint`, `run_tools` 등록 (단계 분리만)
7. [ ] baseline `tool_ids` 상수와 실제 도구 목록 대조

---

## 11. 관련 문서

- [MCP_ARCHITECTURE_V3.md](./MCP_ARCHITECTURE_V3.md) — 아키텍처·규칙의 단일 기준
- [TOOLS_DEV_GUIDE.md](../dev_docs/TOOLS_DEV_GUIDE.md) — 개별 tool 입출력·테스트
- [MCP_SCHEMAS.md](../utils/MCP_SCHEMAS.md) — Tool 공통 입출력 설명

---

한 줄 요약: **타입(계약)을 먼저 고정하고, Feature → Planner → Orchestrator 순으로 작게 구현한 뒤, MCP와 Tool Registry를 실제 동작에 맞춘다.**
