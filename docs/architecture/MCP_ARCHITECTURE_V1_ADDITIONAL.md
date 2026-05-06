# VA-MCP 설계 문서 V1

> **작성일**: 2026.05.04
> **작성자**: 이윤재
> **버전**: 1.1.0

---

# 0. 시스템 정의

VA-MCP = OWASP 기반 API 취약점 분석 엔진 + MCP 인터페이스

핵심 원칙:

- Core Engine은 MCP에 종속되지 않는다
- MCP / REST / CLI는 adapter
- 분석 로직은 engine 중심

---

# 1. 전체 아키텍처

EndpointProfile
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

# 2. 사용자 입력 구조 (핵심)

## 목적

엔드포인트의 "행위"를 이해하기 위한 입력

## 스키마

class EndpointProfile:
base_url: str
method: str
path: str

    headers: dict | None
    query: dict | None
    params: dict | None
    body: dict | None

    auth_required: bool
    auth_contexts: list

    description: str

    normal_request_example: dict | None
    normal_response_example: dict | None

    resource_context: dict | None

    side_effect: str  # read / write
    returns_sensitive_data: bool

---

## 입력 예시

{
"base_url": "http://localhost:3000",
"method": "POST",
"path": "/api/enrollments",
"body": {
"userId": 1,
"courseId": 10,
"status": "enrolled"
},
"auth_required": true,
"description": "수강 신청 API",
"resource_context": {
"user_a_id": 1,
"user_b_id": 2
},
"side_effect": "write"
}

---

# 3. Feature 추출 기준

EndpointProfile → FeatureSet

## 주요 Feature

- has_user_input
- has_free_text_input
- has_enum_input
- has_resource_identifier
- requires_auth
- is_state_changing
- has_state_field
- is_login_endpoint
- has_credential_fields
- has_admin_feature
- has_debug_feature
- has_logging_feature
- returns_sensitive_data

---

## 추출 규칙

userId, courseId → resource_identifier  
keyword, search → free_text  
status, role → enum/state  
POST/PUT → state_change  
/admin → admin  
/debug → debug

---

# 4. Planner 판단 기준

## OWASP 매핑

A01: requires_auth + resource_identifier  
A02: admin/debug + sensitive  
A05: user_input  
A06: state_change + state_field  
A07: login/credential  
A09: logging  
A10: 항상 수행

---

## 예시

POST /api/enrollments

→ Feature

- user_input ✔
- resource_identifier ✔
- auth ✔
- state_change ✔

→ Scenario

- A01
- A05
- A06
- A10

---

# 5. 실행 흐름

User Input
→ FeatureExtractor
→ Planner
→ Scenario 선택
→ Tool 실행
→ 결과 반환

---

# 6. 설계 원칙

- 입력은 완벽하지 않아도 된다
- 부족하면 추가 정보 요청
- path 이름에 의존하지 않는다
- Feature 기반 판단
- Scenario는 판단하지 않는다

---

# 7. 핵심 요약

User Input → Feature → Planner → Scenario → Tool → Result

---

# 8. 팀 공유용 정의

"API를 입력받아 Feature로 변환하고,
Feature 기반으로 OWASP 취약점을 선택하여 자동 분석하는 엔진"
