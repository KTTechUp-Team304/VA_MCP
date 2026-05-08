# EndpointProfile 구현 가이드 (분업 기준)

이 문서는 `EndpointProfile` 담당자가 구현해야 할 범위, 파일 구조, 상세 TODO, 그리고 FeatureExtractor/Planner/Orchestrator 팀과의 계약을 정리한다.

기준 문서:

- `docs/architecture/MCP_ARCHITECTURE_V3.md`
- `docs/architecture/MCP_IMPLEMENTATION_GUIDE.md`

---

## 1) 담당 범위와 원칙

- 담당 범위: `EndpointProfile` 타입 정의, 외부 입력 파싱, 내부 정규화, 검증, 직렬화 계약 고정
- 비담당 범위: `FeatureSet` 생성, hints 생성, OWASP 실행 후보 결정(Planner), Tool 실행(Orchestrator)
- 핵심 원칙:
  - 외부 입력은 유연하게 받는다.
  - 내부 전달은 엄격히 정규화된 `EndpointProfile`로 통일한다.
  - 하위 모듈에서 필드 의미를 헷갈리지 않도록 canonical format을 강제한다.

---

## 2) 디렉토리/파일 구조 (EndpointProfile 담당)

```
src/va_mcp/
├── endpoint_profile/
│   ├── __init__.py
│   ├── endpoint_profile.py              # EndpointProfile 스키마 / SideEffect enum
│   ├── endpoint_profile_parser.py      # 외부 입력 → EndpointProfile
│   ├── endpoint_profile_normalizer.py   # method / path / base_url / resource_context 정규화
│   ├── endpoint_profile_validator.py   # 필수·형식·정책 검증
│   └── logging_utils.py                 # DEBUG 단계별 입출력 로그 포맷
└── ...

tests/
└── endpoint_profile/
    ├── __init__.py
    ├── test_endpoint_profile.py
    ├── test_endpoint_profile_parser.py
    ├── test_endpoint_profile_normalizer.py
    └── test_endpoint_profile_validator.py

docs/
└── endpointProfile.md
```

테스트 공통: 프로젝트 루트 `tests/conftest.py`에서 `.env`의 `LOG_LEVEL`을 반영해 로깅을 초기화한다(`pyproject.toml`의 `log_cli` 설정 참고).

권장:

- 정규화와 검증을 분리해, 파싱 로직이 비대해지지 않게 유지한다.
- `FeatureSet`/`PlannerOutput`은 다른 담당자 모듈에서 관리한다.

현재 단계에서는 기존 `core/`가 tool 공통 계약에 가깝기 때문에 EndpointProfile은 별도 상위 모듈인 `endpoint_profile/`에서 구현한다.  
추후 core 리팩토링 시 `core/tools`, `core/common`, `endpoint_profile` 간 책임을 재정리할 수 있다.

---

## 3) EndpointProfile 계약 (고정 대상)

필수 필드:

- `base_url: str` — 검증 단계에서 **절대 URL**로 제한한다: 스킴은 `http` 또는 `https`, `netloc`(호스트) 비어 있지 않음. 스킴·호스트 없는 값(예: `example.com`만)은 거부한다.
- `method: str`
- `path: str`

선택 필드:

- `headers: dict = field(default_factory=dict)`
- `query: dict = field(default_factory=dict)`
- `params: dict = field(default_factory=dict)`
- `body: dict | None`
- `auth_required: bool = False`
- `auth_contexts: list = field(default_factory=list)` (mutable default 금지)
- `description: str = ""`
- `normal_request_example: dict | None = None`
- `normal_response_example: dict | None = None`
- `resource_context: dict | None = None`
- `side_effect: str = "read"` (`read/create/update/delete`)
- `returns_sensitive_data: bool = False`

---

## 4) 외부 입력 유연성 vs 내부 정규화 규칙

### 4.1 외부 입력 (유연하게 허용)

- `method`: `get`, `Get`, `GET` 모두 허용
- `path`: `users/1`, `/users/1` 모두 허용
- 빈 `headers/query/params/body`: 누락 허용
- `auth_contexts`: 누락/빈 리스트/`None` 모두 허용
- 확장 키(extra keys): 일단 허용하되 내부 계약에 없는 값은 별도 무시/로깅 정책 적용

### 4.2 내부 정규화 (엄격히 통일)

- `method`는 반드시 대문자 (`GET`, `POST`, ...)
- `path`는 반드시 `/`로 시작
- `base_url`은 trailing slash 정리
- `headers` key는 원본 보존 또는 표준화 정책 하나로 고정 (팀 공통)
- 내부 반환 타입은 아래처럼 고정한다:
  - `headers: dict = field(default_factory=dict)`
  - `query: dict = field(default_factory=dict)`
  - `params: dict = field(default_factory=dict)`
  - `body: dict | None = None`
  - `auth_contexts: list = field(default_factory=list)`
- `side_effect` 허용값 검증: `read/create/update/delete` 외 입력은 validation error

정규화 결과는 FeatureExtractor/Planner/Orchestrator가 모두 동일하게 참조하는 단일 입력이 된다.

### 4.3 resource_context 정규화 (필수)

`resource_context`를 자유 dict로 두면 하위 모듈에서 의미 해석이 달라져 신뢰 가능한 판단 신호로 쓰기 어렵다.  
따라서 내부에서는 최소 계약을 가진 정규화 구조로 강제한다.

권장 최소 스키마:

- `resource_type: str` (예: `user`, `order`, `project`)
- `resource_id_key: str` (예: `userId`, `orderId`)
- `owner_id_key: str | None` (예: `ownerId`, `createdBy`)
- `tenant_id_key: str | None` (멀티테넌시 식별자)
- `hierarchy_keys: list[str]` (상위 리소스 체인, 기본 `[]`)

정책:

- 외부 입력이 자유형이어도 parser 단계에서 위 스키마로 변환/정규화한다.
- 팀 고정 정책(구현):
  - **`parse_endpoint_profile(..., strict_resource_context=True)`(기본값)**: 최소 스키마로 맞출 수 없으면 `EndpointProfileValidationError`.
  - **`strict_resource_context=False`**: 맞출 수 없으면 `resource_context=None`으로 두고, 경고 로그(`warning`)를 남긴다.

### 4.4 base_url 검증 (구현 정책)

- 정규화: 앞뒤 공백 제거, **trailing slash 제거** (§4.2와 동일).
- 검증: `urllib.parse.urlsplit` 기준으로 `scheme in {"http", "https"}` 이고 `netloc`이 비어 있지 않아야 한다. 이는 실제 HTTP 클라이언트가 붙일 수 있는 베이스 URL을 강제하기 위함이다.

---

## 5) 구현 TODO (상세 체크리스트)

현재 코드베이스 기준으로 항목 1~6은 반영되었고, 항목 7은 아래 §5.1에 정리했다.

1. `endpoint_profile.py` 작성
   - `EndpointProfile` 타입 정의
   - `side_effect` 허용값 enum/상수 정의
   - mutable default 금지 점검 (`headers/query/params/auth_contexts`는 `default_factory`)

2. `endpoint_profile_parser.py` 작성
   - 외부 dict/JSON 문자열 → `EndpointProfile` 변환 (`parse_endpoint_profile`)
   - snake_case 입력 기준 + camelCase 별칭(`baseUrl` → `base_url` 등)

3. `endpoint_profile_normalizer.py` 작성
   - `normalize_method`, `normalize_path`, `normalize_base_url`
   - `normalize_optional_maps` (내부 반환 타입 고정 정책 반영)
   - `normalize_resource_context` (최소 스키마로 정규화)

4. `endpoint_profile_validator.py` 작성
   - 필수값 검증(`base_url`, `method`, `path`)
   - 값 범위 검증(`side_effect`), `base_url` 절대 URL 검증(§4.4)
   - 타입 검증(`headers/query/params/body/auth_contexts/resource_context`)
   - 에러 포맷 규격화 (`code`, `field`, `message`) — 예외: `EndpointProfileValidationError` + `ValidationIssue` 목록

5. `endpoint_profile/__init__.py` 정리
   - 외부에서 쓰는 import 경로 단순화(예: §5.2)

6. 테스트 작성
   - 최소 입력 성공
   - 풀 입력 성공
   - 정규화 동작 확인(method/path/base_url)
   - invalid `side_effect` 실패
   - `auth_contexts` 기본값 공유 방지
   - 직렬화 결과 키/shape 고정 검증
   - `resource_context` strict / lenient 동작

7. 핸드오프 문서화
   - §5.1 정규화 이후 보장 조건, §5.2 공개 API, §6 전달 계약을 기준으로 FeatureExtractor 팀과 공유한다.

---

## 5.1) 정규화·검증 이후 보장 조건 (contracts after normalization)

`parse_endpoint_profile()`이 정상 반환하거나, 직접 생성한 뒤 `validate_endpoint_profile()`을 통과한 `EndpointProfile`에 대해 다음을 보장한다.

- `method`: 대문자 HTTP 메서드 문자열.
- `path`: `/`로 시작하는 문자열.
- `base_url`: trailing `/` 없음; `http` 또는 `https` 스킴; 비어 있지 않은 host(`netloc`). §4.4 참고.
- `headers`, `query`, `params`: `dict` 타입(입력 누락 시 `{}`).
- `body`: `dict | None`.
- `auth_contexts`: `list` 타입(입력 `None`/누락 시 `[]`).
- `side_effect`: `read`, `create`, `update`, `delete` 중 하나.
- `resource_context`: `None`이거나 §4.3 최소 스키마를 만족하는 `dict`이며, 값이 있을 때 `resource_type`·`resource_id_key`는 비어 있지 않은 문자열; `owner_id_key`·`tenant_id_key`는 `str | None`; `hierarchy_keys`는 `list` (요소는 문자열로 정규화).
- 직렬화: `to_serializable_dict()`의 키 집합이 §3 필드와 동일한 shape를 갖는다.

실패 시: `EndpointProfileValidationError`가 발생하고, `issues`에 `ValidationIssue(code, field, message)`가 1건 이상 담긴다.

---

## 5.2) 공개 API (import)

```python
from va_mcp.endpoint_profile import (
    EndpointProfile,
    EndpointProfileValidationError,
    SideEffect,
    ValidationIssue,
    parse_endpoint_profile,
    validate_endpoint_profile,
)
```

디버깅 시 `LOG_LEVEL=DEBUG`와 패키지 로거(`va_mcp.endpoint_profile`)를 사용하면 파서·정규화·검증 단계별 입출력이 로그에 남는다.

## 6) FeatureExtractor 전달 계약 (중요)

`EndpointProfile` 담당자는 아래만 반환한다:

- 정규화/검증 완료된 `EndpointProfile` 객체(또는 dict)

반환하지 않는 것:

- hints
- FeatureSet
- OWASP 판단 결과

즉, `hints`는 EndpointProfile 단계가 아니라 **FeatureSet 단계(FeatureExtractor)** 에서 생성한다.

---

## 7) OWASP Top 10:2025 기준

아래는 요청한 OWASP Top 10:2025 분류 기준으로, EndpointProfile이 FeatureSet 판단에 제공해야 하는 입력 신호를 정리한 것이다.

- 1. Broken Access Control (접근제어취약점)
  - 전달 필드: `auth_required`, `auth_contexts`, `resource_context`, `path`, `params`, `method`
- 2. Security Misconfiguration (보안 설정 오류)
  - 전달 필드: `base_url`, `path`, `headers`, `description`, `normal_response_example`
- 3. Software Supply Chain Failures (소프트웨어 공급망 실패)
  - 전달 필드: `description`, `normal_response_example`, `path`
- 4. Cryptographic Failures (암호화 오류)
  - 전달 필드: `returns_sensitive_data`, `headers`, `normal_response_example`, `description`
- 5. Injection
  - 전달 필드: `query`, `params`, `body`, `description`, `path`
- 6. Insecure Design (보안취약설계)
  - 전달 필드: `description`, `side_effect`, `resource_context`, `normal_request_example`
- 7. Authentication Failures (인증 실패/인증 취약점)
  - 전달 필드: `auth_required`, `auth_contexts`, `headers`, `description`, `normal_request_example`
- 8. Software or Data Integrity Failures (데이터 무결성 문제)
  - 전달 필드: `body`, `headers`, `description`, `normal_response_example`
- 9. Security Logging and Alerting Failures (로그/알럿 실패)
  - 전달 필드: `path`, `description`, `normal_response_example`
- 10. Mishandling Of Exceptional Conditions (예외처리 부적절)
  - 전달 필드: `description`, `normal_response_example`, `path`, `headers`

주의:

- 위 항목은 EndpointProfile이 "판단"하는 규칙이 아니라, FeatureExtractor가 판단하기 위한 "입력 신호" 정리다.
- 실제 `FeatureSet` 플래그 계산과 OWASP 실행 선택은 FeatureExtractor/Planner 담당 범위다.

---

## 8) 팀 연동 시퀀스 (분업 기준)

1. EndpointProfile 담당
   - 타입/파싱/정규화/검증/테스트 완료
2. FeatureExtractor 담당
   - 정규화된 EndpointProfile 입력으로 FeatureSet + hints 생성
3. Planner+Scenario 담당
   - FeatureSet으로 OWASP 실행 후보 및 missing context 계산
4. Orchestrator+Tools 담당
   - EndpointProfile 원본 + Planner 결과로 ToolInput 조립/실행

---

## 9) 완료 기준 (Definition of Done)

- EndpointProfile 계약이 코드/문서/테스트에서 일치한다(§3, §4, §5.1).
- 외부 입력 변형이 들어와도 내부 표현이 단일 canonical format으로 정규화된다.
- 하위 모듈이 필드 의미를 혼동하지 않도록 입력 조건이 고정된다.
- FeatureExtractor/Planner/Orchestrator 연동과 `FeatureSet` 생성은 별도 기능 범위이며, 본 문서의 EndpointProfile 단계 완료와는 구분한다.
