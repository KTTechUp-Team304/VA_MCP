# VA-MCP 설계 문서 V3.1 (구현 기준 확정본)

> **작성일**: 2026.05.06
> **작성자**: 이윤재
> **버전**: 3.1.0

# 0. 시스템 정의

VA-MCP = OWASP 기반 API 취약점 분석 엔진 + MCP 인터페이스

핵심 원칙:

- Core Engine은 MCP에 종속되지 않는다
- MCP / REST / CLI는 adapter 계층이다
- 분석 로직은 Feature 기반으로 동작한다 (path는 보조 신호로만 사용)
- 불완전 입력을 허용하고 필요 시 추가 입력을 요구한다

---

# 1. 전체 아키텍처

EndpointProfile (입력)
→ FeatureExtractor
→ FeatureSet
→ ScenarioPlanner
→ ScenarioPlan
→ Scenario
→ Orchestrator
→ Tools
→ ScenarioResult
→ EndpointReport

---

# 2. 사용자 입력 구조 (EndpointProfile)

## 목적

엔드포인트의 “행위 / 권한 / 데이터 흐름”을 분석 가능한 수준으로 표현

## 스키마

class EndpointProfile:

    base_url: str  # 대상 서버 주소
    method: str    # HTTP method
    path: str      # API 경로

    headers: dict | None = None  # 요청 헤더
    query: dict | None = None    # query params
    params: dict | None = None   # path params
    body: dict | None = None     # request body

    auth_required: bool = False  # 인증 필요 여부
    auth_contexts: list | None = None
    # 구현 시 mutable default 금지:
    # dataclass면 field(default_factory=list) 사용

    description: str = ""        # 행위 + 주체 + 대상 포함 설명

    normal_request_example: dict | None = None
    normal_response_example: dict | None = None

    resource_context: dict | None = None
    # ownership 구조 포함

    side_effect: str = "read"  # read / create / update / delete
    returns_sensitive_data: bool = False

---

# 3. Feature 구조

Feature = 자동 추출 + 사용자 제공

class FeatureSet:

    # ===== 입력 =====
    has_user_input: bool
    # body/query/params 존재 여부

    has_free_text_input: bool
    # keyword/search/text 입력 여부

    has_enum_input: bool
    # status/type/role 등 제한된 값

    # ===== 권한 =====
    requires_auth: bool
    # 인증 필요 여부

    has_resource_identifier: bool
    # userId, courseId 등

    # ===== 상태 =====
    is_state_changing: bool
    # create/update/delete 여부

    has_state_field: bool
    # status/role 등 상태 변경 필드

    # ===== 인증 =====
    is_login_endpoint: bool
    # login API 여부

    has_credential_fields: bool
    # username/password 존재

    # ===== 시스템 =====
    has_admin_feature: bool
    # /admin 포함 여부

    has_debug_feature: bool
    # /debug 포함 여부

    has_logging_feature: bool
    # log/audit 관련

    # ===== A03/A04/A08 보강 =====
    has_dependency_exposure: bool
    # build-info, version, dependency 정보 노출 단서

    has_secret_handling: bool
    # token/secret/api-key/password reset 등 인증 비밀정보 처리 단서

    has_file_or_config_surface: bool
    # file upload/download, config export/import, delete 관련 단서

    # ===== 응답 =====
    returns_sensitive_data: bool

---

# 4. Planner 기준

A01: requires_auth + (resource_identifier or auth_contexts>=2)
A02: baseline 항상 수행 (admin/debug/sensitive는 우선순위 신호)
A03: has_dependency_exposure
A04: has_secret_handling
A05: has_user_input + (has_free_text_input or has_file_or_config_surface)
A06: is_state_changing + has_state_field
A07: is_login_endpoint or has_credential_fields or auth_required
A08: has_file_or_config_surface
A09: has_logging_feature or endpoint가 log/error/debug 태그 포함
A10: baseline 항상 수행

참고:

- Planner는 "최종 취약 확정"이 아니라 "실행 후보 선정" 역할이다.
- ToolResult가 최종 판단 근거다.

---

# 5. Scenario 실행 조건

A01:

- auth_contexts >= 2
- resource_context 존재

A02:

- baseline tool은 입력 최소 조건으로 수행
- base_url만 있으면 실행 가능, endpoint 입력은 선택

A03:

- has_dependency_exposure = True

A04:

- has_secret_handling = True

A05:

- has_user_input = True
- has_free_text_input=True 또는 file/config surface=True

A06:

- is_state_changing = True
- has_state_field = True

A07:

- login/credential/auth_required 중 하나 이상 True

A08:

- has_file_or_config_surface = True

A09:

- has_logging_feature=True 또는 log/error/debug 태그

A10:

- baseline tool은 항상 수행

조건 부족 시:
status = skipped

---

# 6. 실행 흐름

User Input
→ FeatureExtractor
→ Planner
→ Scenario 선택
→ Tool 실행
→ 결과 반환

---

# 7. need_more_context

Planner에서만 반환한다. (Tool/Scenario는 반환하지 않음)

{
"status": "need_more_context",
"missing": ["resource_context", "auth_contexts"]
}

계약:

- Planner 단계에서 실행 조건 평가 중 필수 입력이 부족하면 반환
- Tool 단계는 추가 입력 요구를 하지 않고 `status=skipped`만 반환
- Orchestrator는 need_more_context를 사용자 입력 보완 요청으로 전달

---

# 8. 설계 원칙

- Feature 기반 분석
- Scenario는 판단하지 않는다
- 입력은 불완전해도 된다
- Planner가 입력 부족을 먼저 식별한다
- POC 생성 필수

---

# 9. 핵심 요약

User Input → Feature → Planner → Scenario → Tool → Result

---

# 10. 팀 정의

"API를 입력받아 Feature 기반으로 OWASP 취약점을 자동 분석하는 엔진"
