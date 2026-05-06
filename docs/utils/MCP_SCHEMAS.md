# Python MCP Tool 입출력 공통 스키마 설계

> **작성일**: 2026.04.24
> **작성자**: 이윤재
> **버전**: 1.0.0

## 1. 이 문서의 목적

취약점 분석 MCP에는 여러 개의 tool이 들어간다.

예를 들면:

```text
IDOR / BOLA Testing
SQL Injection Testing
CORS Testing
Security Header Analysis
Login Rate Limit Testing
Stack Trace Exposure Testing
```

각 tool은 하는 일이 다르지만, **입력과 출력 형식은 최대한 통일**해야 한다.

그래야 나중에 scenario가 여러 tool을 조합해서 실행하고, 최종 보고서를 만들기 쉽다.

---

## 2. 왜 공통 스키마가 필요한가?

만약 tool마다 결과 형식이 다르면 문제가 생긴다.

예를 들어 어떤 tool은 이렇게 반환하고:

```python
{
    "result": "danger",
    "url": "/api/users/2"
}
```

다른 tool은 이렇게 반환하면:

```python
{
    "is_vulnerable": True,
    "message": "CORS is too open"
}
```

나중에 scenario나 report 생성기가 모든 결과를 따로따로 해석해야 한다.

그래서 모든 tool은 아래처럼 같은 구조로 결과를 반환해야 한다.

```text
어떤 tool이 실행됐는가?
취약한가?
위험도는 어느 정도인가?
증거는 무엇인가?
어떤 OWASP 항목과 연결되는가?
어떻게 고쳐야 하는가?
```

---

## 3. 전체 구조

취약점 분석 MCP의 흐름은 다음과 같다.

```text
사용자 입력
  ↓
Tool 실행
  ↓
ToolResult 생성
  ↓
Scenario가 결과 조합
  ↓
OWASP / CWE 매핑
  ↓
최종 보고서 생성
```

---

## 4. Tool 공통 입력 구조

Tool은 분석을 위해 공통적으로 다음 정보를 받는다.

```text
1. 대상 서버 정보
2. 테스트할 API 요청 정보
3. 인증 정보
4. 옵션 정보
```

Python에서는 `dataclass` 또는 `pydantic`으로 표현할 수 있다.

초기 MVP에서는 이해하기 쉬운 `dataclass`를 사용해도 충분하다.

---

## 5. Python 입력 모델 예시

```python
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class TargetInfo:
    base_url: str
    openapi_url: Optional[str] = None


@dataclass
class ApiRequest:
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, Any] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    body: Optional[dict[str, Any]] = None


@dataclass
class AuthContext:
    role: str
    auth_type: str
    token: Optional[str] = None
    cookie: Optional[str] = None


@dataclass
class ToolOptions:
    timeout: int = 5000
    safe_mode: bool = True
    max_requests: int = 20
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolInput:
    target: TargetInfo
    request: Optional[ApiRequest] = None
    auth: list[AuthContext] = field(default_factory=list)
    options: ToolOptions = field(default_factory=ToolOptions)
```

---

## 6. 입력 예시

예를 들어 `/api/users/{userId}`에 대해 IDOR 테스트를 하고 싶다면 다음과 같은 입력을 만들 수 있다.

```python
tool_input = ToolInput(
    target=TargetInfo(
        base_url="https://test-api.example.com",
        openapi_url="https://test-api.example.com/swagger.json"
    ),
    request=ApiRequest(
        method="GET",
        path="/api/users/{userId}",
        params={"userId": "1"}
    ),
    auth=[
        AuthContext(
            role="user_a",
            auth_type="bearer",
            token="USER_A_TOKEN"
        ),
        AuthContext(
            role="user_b",
            auth_type="bearer",
            token="USER_B_TOKEN"
        ),
        AuthContext(
            role="admin",
            auth_type="bearer",
            token="ADMIN_TOKEN"
        )
    ],
    options=ToolOptions(
        timeout=5000,
        safe_mode=True,
        max_requests=10
    )
)
```

---

## 7. Tool 공통 출력 구조

모든 tool은 같은 형식으로 결과를 반환한다.

출력에는 다음 정보가 들어간다.

```text
1. tool 이름
2. 실행 상태
3. 위험도
4. 신뢰도
5. OWASP 매핑
6. CWE 매핑
7. 제목
8. 설명
9. 증거
10. 수정 권고
```

---

## 8. Python 출력 모델 예시

```python
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Evidence:
    request: dict[str, Any]            # method, path, headers, query, params, body
    response_status: int
    response_headers: dict[str, str]
    response_body_sample: str
    note: str


@dataclass
class ToolError:
    error_code: str                    # 예: "TIMEOUT", "INVALID_INPUT", "HTTP_FAILURE"
    error_message: str
    retryable: bool = False


@dataclass
class ToolResult:
    tool_id: str                       # 예: "idor_bola" (snake_case 고정)
    tool_name: str                     # 예: "IDOR / BOLA Testing" (표시용 이름)
    status: str
    severity: str
    confidence: str
    title: str
    description: str
    evidence: list[Evidence] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    recommendation: str = ""
    started_at: str = ""               # ISO-8601 UTC, 예: 2026-04-24T09:10:11Z
    ended_at: str = ""                 # ISO-8601 UTC
    duration_ms: int = 0
    tool_version: str = "0.1.0"
    metadata: dict[str, str] = field(default_factory=dict)
    errors: list[ToolError] = field(default_factory=list)
```

추가 규칙:

```text
tool_id는 저장/집계/필터링 키로 사용한다.
tool_name은 UI/보고서 표시용으로만 사용한다.
response_body_sample은 최대 2000자까지만 저장한다.
request.body 문자열 직렬화 시 최대 2000자까지만 저장한다.
토큰/쿠키/비밀번호는 마스킹 후 기록한다.
```

---

## 9. status 값 정의

`status`는 tool 실행 결과를 의미한다.

```text
passed      → 취약점이 발견되지 않음
vulnerable  → 취약점이 발견됨
skipped     → 필요한 입력이 부족해서 실행하지 않음
error       → tool 실행 중 오류 발생
```

추가 규칙:

```text
status=error 인 경우 severity는 "info"로 고정한다.
status=error 인 경우 confidence는 "low"로 고정한다.
status=skipped 인 경우 evidence는 빈 리스트로 둔다.
```

예시:

```python
status="vulnerable"
```

---

## 10. severity 값 정의

`severity`는 위험도를 의미한다.

```text
info      → 정보성
low       → 낮음
medium    → 중간
high      → 높음
critical  → 매우 높음
```

예시:

```python
severity="high"
```

---

## 11. confidence 값 정의

`confidence`는 탐지 결과의 신뢰도를 의미한다.

```text
low       → 추정 수준
medium    → 어느 정도 근거 있음
high      → 명확한 재현 증거 있음
```

예시:

```python
confidence="high"
```

---

## 12. IDOR Tool 결과 예시

```python
result = ToolResult(
    tool_name="IDOR / BOLA Testing",
    status="vulnerable",
    severity="high",
    confidence="high",
    title="다른 사용자의 정보 조회 가능",
    description="일반 사용자 토큰으로 다른 userId의 정보를 조회할 수 있습니다.",
    owasp=["A01 Broken Access Control"],
    cwe=["CWE-639"],
    evidence=[
        Evidence(
            request={
                "method": "GET",
                "path": "/api/users/2",
                "auth_role": "user_a"
            },
            response_status=200,
            response_body_sample="{\"id\":2,\"email\":\"user2@example.com\"}",
            note="user_a 권한으로 user_b의 정보가 조회됨"
        )
    ],
    recommendation="서버에서 현재 로그인 사용자와 요청한 userId가 일치하는지 검증해야 합니다."
)
```

---

## 13. CORS Tool 결과 예시

```python
result = ToolResult(
    tool_name="CORS Misconfiguration Testing",
    status="vulnerable",
    severity="medium",
    confidence="high",
    title="CORS 정책이 과도하게 허용됨",
    description="Access-Control-Allow-Origin이 모든 Origin을 허용하고 있습니다.",
    owasp=["A02 Security Misconfiguration"],
    cwe=["CWE-942"],
    evidence=[
        Evidence(
            request={
                "method": "OPTIONS",
                "path": "/api/users/me",
                "headers": {
                    "Origin": "https://attacker.example.com"
                }
            },
            response_status=204,
            response_body_sample="Access-Control-Allow-Origin: *",
            note="임의 Origin 요청이 허용됨"
        )
    ],
    recommendation="신뢰 가능한 Origin만 명시적으로 허용해야 합니다."
)
```

---

## 14. Tool 기본 인터페이스

모든 tool은 같은 방식으로 실행될 수 있어야 한다.

```python
from abc import ABC, abstractmethod


class BaseTool(ABC):
    name: str

    @abstractmethod
    def run(self, tool_input: ToolInput) -> ToolResult:
        pass
```

각 tool은 `BaseTool`을 상속받아 구현한다.

예시:

```python
class IdorBolaTestingTool(BaseTool):
    name = "IDOR / BOLA Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        # 1. 요청 정보 확인
        # 2. userId 또는 orderId 같은 파라미터 변경
        # 3. 다른 사용자 토큰으로 요청
        # 4. 응답 비교
        # 5. ToolResult 반환
        pass
```

---

## 15. Scenario에서 Tool을 사용하는 방식

Scenario는 여러 tool을 조합해서 실행한다.

예를 들어 Broken Access Control 시나리오는 다음 tool을 사용할 수 있다.

```text
Role-based Access Testing
IDOR / BOLA Testing
BFLA Testing
HTTP Method Tampering
Parameter Tampering
Response Comparison
```

Python 예시:

```python
class BrokenAccessControlScenario:
    def __init__(self, tools: list[BaseTool]):
        self.tools = tools

    def run(self, tool_input: ToolInput) -> list[ToolResult]:
        results = []

        for tool in self.tools:
            result = tool.run(tool_input)
            results.append(result)

        return results
```

---

## 16. 최종 보고서 생성 흐름

각 tool이 `ToolResult`를 반환하면, report 생성기는 이 결과들을 모아 최종 보고서를 만든다.

```text
ToolResult 목록
  ↓
OWASP 항목별 그룹화
  ↓
위험도 순 정렬
  ↓
Markdown / JSON 보고서 생성
```

예시 그룹화:

```text
A01 Broken Access Control
- IDOR 발견
- 일반 사용자 admin API 접근 가능

A02 Security Misconfiguration
- CORS 과도 허용
- Swagger 공개

A05 Injection
- SQL Injection 의심
- XSS Payload 반사
```

---

## 17. 팀원들이 기억해야 할 핵심

```text
Tool은 실제 검사를 수행한다.
Scenario는 여러 Tool을 조합한다.
ToolResult는 모든 Tool이 공통으로 반환하는 결과 형식이다.
Report는 ToolResult를 모아서 만든다.
```

한 줄로 정리하면:

```text
입력은 공통으로 받고, 결과도 공통으로 반환해야 MCP 전체 구조가 단순해진다.
```

---

## 18. 1차 MVP에서는 이렇게만 지키면 된다

1차 MVP에서는 복잡하게 만들지 말고, 아래 규칙만 지킨다.

```text
1. 모든 tool은 run() 메서드를 가진다.
2. 모든 tool은 ToolInput을 입력으로 받는다.
3. 모든 tool은 ToolResult를 반환한다.
4. ToolResult 안에는 증거와 수정 권고가 포함된다.
5. Scenario는 여러 ToolResult를 모은다.
6. 각 tool PR은 최소 3개 테스트를 포함한다.
   - 취약점 없음: status=passed
   - 취약점 발견: status=vulnerable + evidence 존재
   - 예외/입력오류: status=error + errors 존재
7. 분업 시작 전에 아래 5가지를 고정한다.
   - ToolInput / ToolResult / Evidence / ToolError 공통 모델 파일 위치
   - status, severity, confidence enum 정의 위치
   - tool_id 네이밍 규칙 문서화
   - 공통 유틸(마스킹, 시간 포맷, 에러 생성) 제공
   - PR 템플릿 DoD 체크박스 반영
```

이 구조만 지켜도 나중에 tool이 늘어나도 전체 구조가 무너지지 않는다.
