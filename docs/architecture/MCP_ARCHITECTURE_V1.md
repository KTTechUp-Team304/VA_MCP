# VA-MCP 실제 구현 설계 문서

> **작성일**: 2026.05.04
> **작성자**: 이윤재
> **버전**: 1.0.0

## 🎯 시스템 정의

VA-MCP = OWASP 기반 API 취약점 분석 엔진 + MCP 인터페이스

핵심 원칙:

- Core Engine은 MCP에 종속되지 않는다
- MCP / REST / CLI는 adapter이다
- 분석 로직은 engine 내부에 집중한다

---

## 🧱 전체 아키텍처

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

## 📦 Core Layer

### 1. EndpointProfile

```python
@dataclass
class EndpointProfile:
    target: TargetInfo
    request: ApiRequest
    auth_contexts: list[AuthContext]
    sample_response: dict | None = None
```

---

### 2. FeatureSet

#### 폴더 위치: src/va_mcp/featureExtractor

```python
@dataclass
class FeatureSet:
    has_user_input: bool
    has_free_text_input: bool
    has_enum_input: bool
    requires_auth: bool
    has_resource_identifier: bool
    is_state_changing: bool
    has_state_field: bool
    is_login_endpoint: bool
    has_credential_fields: bool
    has_admin_feature: bool
    has_debug_feature: bool
    has_logging_feature: bool
    returns_sensitive_data: bool
```

---

### 3. FeatureExtractor

```python
class FeatureExtractor:
    def extract(self, profile: EndpointProfile) -> FeatureSet:
        ...
```

---

## 🧠 Planner

#### 폴더 위치: src/va_mcp/planner

### Rule Mapping

- A01: requires_auth + resource_identifier
- A02: admin/debug + sensitive data
- A05: user_input
- A06: state_change + state_field
- A07: login/credential
- A09: logging
- A10: 항상 검사

---

## 🧩 Scenario

#### 폴더 위치: src/va_mcp/scenario

역할:

- ToolTask 정의
- 결과 해석
- POC 생성

---

## ⚙️ Orchestrator

#### 폴더 위치: src/va_mcp/tools

역할:

- tool 중복 제거
- 실행 관리
- 결과 수집

---

## 🔧 Tools

#### 폴더 위치: src/va_mcp/tools

- HTTP 요청 실행
- 취약점 테스트 수행
- Evidence 생성

---

## 🧪 Evidence & POC

Tool → Evidence  
Scenario → POC 생성

---

## 📊 EndpointReport

최종 취약점 결과 집계

---

## 🧠 핵심 구조

Feature → Decision → Execution → Evidence → Report

---

## 🚀 구현 순서

1. FeatureExtractor
2. Planner
3. Scenario
4. Orchestrator
5. Tool 연결
6. Report
7. MCP 연결
