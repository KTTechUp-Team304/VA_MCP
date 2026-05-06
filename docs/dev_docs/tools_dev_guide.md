# VA-MCP Tool 개발 가이드

새 tool을 만들 때 아래의 가이드를 지켜주세요.
공통 스키마 / 상수 / 개발 절차 / 완성 기준입니다.

core 파일은 수정하시면 안됩니다. 수정이 필요하시면 PM에게 연락주세요.

> **작성일**: 2026.04.23
> **작성자**: 이윤재
> **버전**: 1.0.0

---

## 1. 프로젝트 구조 (핵심 경로)

```
src/va_mcp/
├── core/
│   ├── base.py          ← BaseTool 추상 클래스 (건드리지 않음)
│   ├── constants.py     ← ToolStatus, Severity, Confidence, ErrorCode, 길이 상수 (건드리지 않음)
│   ├── schemas.py       ← ToolInput, ToolResult, Evidence, ToolError 등 공통 스키마 (건드리지 않음)
│   └── utils.py         ← utc_now_iso, mask_sensitive, build_tool_error 등 공통 유틸 (건드리지 않음)
│
└── tools/
    ├── _template.py     ← 새 tool 시작 시 복사 기준 파일
    ├── health.py
    └── (팀원이 추가할 tool 파일들)

tests/
└── tools/
    └── <tool_id>/
        └── test_<tool_id>.py
```

`core/` 는 팀 전체 공용 라이브러리다. **절대 직접 수정하지 않는다.**

---

## 2. 필수 import 경로

`va_mcp.core` 패키지가 하위 모듈 전체를 re-export하므로, 아래처럼 단일 경로에서 임포트한다.
하위 모듈(base, constants, schemas)을 직접 임포트하지 않는다.

```python
from va_mcp.core import (
    BaseTool,
    ToolInput,
    ToolResult,
    Evidence,
    ToolError,
    AuthContext,
    ToolStatus,
    Severity,
    Confidence,
    ErrorCode,
)
from va_mcp.core.utils import (
    build_tool_error,
    utc_now_iso,
    mask_sensitive,
    sanitize_response_sample,
    sanitize_request_body,
)
```

주의: `va_mcp.core.utils`는 `__init__.py`에서 re-export하지 않으므로 직접 임포트한다.

---

## 3. 새 tool 만들기 (시작 순서)

**Step 1.** `src/va_mcp/tools/_template.py`를 복사해서 새 파일을 만든다.

```bash
cp src/va_mcp/tools/_template.py src/va_mcp/tools/idor_bola.py
```

**Step 2.** 클래스명 / `tool_id` / `tool_name`을 바꾼다.

```python
class IdorBolaTool(BaseTool):
    tool_id = "idor_bola"               # snake_case 고정
    tool_name = "IDOR / BOLA Testing"   # 표시용 이름
```

**Step 3.** `run()` 내부에 분석 로직을 구현한다.

**Step 4.** 테스트 파일을 작성한다. (아래 7번 참고)

---

## 4. 공통 상수 사용 규칙

모든 상태 / 위험도 / 신뢰도 값은 반드시 상수를 사용한다.
문자열 하드코딩 금지.

```python
# 올바른 사용
status=ToolStatus.VULNERABLE,
severity=Severity.HIGH,
confidence=Confidence.HIGH,

# 잘못된 사용 (하드코딩 금지)
status="vulnerable",
severity="high",
```

### 4.1 ToolStatus

| 값                      | 의미                               |
| ----------------------- | ---------------------------------- |
| `ToolStatus.PASSED`     | 취약점 미발견, 실행 성공           |
| `ToolStatus.VULNERABLE` | 취약점 발견, 실행 성공             |
| `ToolStatus.SKIPPED`    | 입력 부족 / 조건 미충족으로 미실행 |
| `ToolStatus.ERROR`      | 실행 중 예외 또는 내부 오류        |

### 4.2 Severity

| 값                  | 의미      |
| ------------------- | --------- |
| `Severity.INFO`     | 정보성    |
| `Severity.LOW`      | 낮음      |
| `Severity.MEDIUM`   | 중간      |
| `Severity.HIGH`     | 높음      |
| `Severity.CRITICAL` | 매우 높음 |

### 4.3 Confidence

| 값                  | 의미                  |
| ------------------- | --------------------- |
| `Confidence.LOW`    | 추정 수준             |
| `Confidence.MEDIUM` | 어느 정도 근거 있음   |
| `Confidence.HIGH`   | 명확한 재현 증거 있음 |

### 4.4 ErrorCode

| 값                         | 의미           |
| -------------------------- | -------------- |
| `ErrorCode.TIMEOUT`        | 요청 시간 초과 |
| `ErrorCode.INVALID_INPUT`  | 입력값 오류    |
| `ErrorCode.HTTP_FAILURE`   | HTTP 요청 실패 |
| `ErrorCode.INTERNAL_ERROR` | 내부 예외      |

---

## 5. tool별 추가 옵션 사용법 (extra 필드)

`core/schemas.py`를 수정하지 않고 각 tool에서 필요한 옵션을 자유롭게 추가할 수 있다.
`ToolOptions.extra` 딕셔너리를 사용한다.

```python
# tool 내부에서 꺼내 쓰는 방법
def run(self, tool_input: ToolInput) -> ToolResult:
    payload_list = tool_input.options.extra.get("payload_list", [])
    repeat_count = tool_input.options.extra.get("repeat_count", 5)
    interval_ms  = tool_input.options.extra.get("interval_ms", 500)
```

규칙:

```text
- core/schemas.py의 ToolOptions에 필드를 직접 추가하지 않는다.
- extra 키 이름은 각 tool 파일 상단 주석에 명시한다.
- 기본값은 .get("key", 기본값) 형태로 항상 지정한다.
```

---

## 6. 반환값 작성 규칙

### 6.1 status별 고정 규칙

```text
status=VULNERABLE  → severity와 confidence를 분석 결과에 맞게 설정
status=PASSED      → severity는 결과에 따라 선택 (아래 기준 참고), confidence는 자유
status=SKIPPED     → evidence=[] 고정
status=ERROR       → severity=INFO, confidence=LOW 고정  ← ERROR만 엄격히 고정
```

PASSED severity 기준:

```text
취약점이 전혀 없음 (완전 정상)    → severity=INFO
주의가 필요한 설정이 있음         → severity=LOW   (예: OPTIONS 헤더에 위험 메서드 노출)
명백한 문제이나 직접 취약점은 아님 → severity=MEDIUM
```

주의: severity=INFO 강제는 ERROR 상태에만 적용된다. PASSED를 INFO로 고정하면
"주의 필요" 수준의 결과를 전달할 방법이 없어진다.

### 6.2 Evidence 작성 규칙

```python
Evidence(
    request={
        "method": "GET",
        "url": "https://api.example.com/api/users/2",         # path 아닌 전체 URL 기록 (재현 가능성)
        "headers": mask_sensitive(request_headers),           # 민감 키 마스킹 필수
        "body": sanitize_request_body(request_body),          # 2000자 제한
    },
    response_status=200,
    response_headers={},
    response_body_sample=sanitize_response_sample(response_body),  # 2000자 제한
    note="user_a 권한으로 user_b 데이터 조회됨",
)
```

민감 정보 마스킹 규칙:

```text
headers 안의 Authorization, Cookie, Token, Password, Api-Key 값은
mask_sensitive() 를 반드시 통과시켜야 한다.
```

### 6.3 시간 기록 규칙

```python
started_at = utc_now_iso()   # run() 진입 직후 기록
# ... 분석 로직 ...
ended_at = utc_now_iso()     # return 직전 기록
```

---

## 7. 테스트 작성 규칙 (Definition of Done)

### 7.1 테스트 환경 단계

공격 대상 서버 없이도 단계별로 테스트를 작성할 수 있다.

| 단계  | 방법                 | 시점                                |
| ----- | -------------------- | ----------------------------------- |
| 1단계 | Mock (unittest.mock) | tool 구현 초기, 서버 없이 로직 검증 |
| 2단계 | httpbin.org          | 실제 HTTP 요청/응답 흐름 확인       |
| 3단계 | DVWA / Juice Shop    | 실제 취약점 탐지 정확도 검증        |

**지금 당장은 1단계(Mock)만으로 테스트 파일 완성 가능하다.**

### 7.2 필수 테스트 3종

tool PR을 올리기 전에 아래 3개 케이스가 반드시 있어야 한다.

```
tests/tools/<tool_id>/
└── test_<tool_id>.py
```

| 케이스            | 검증 내용                                            |
| ----------------- | ---------------------------------------------------- |
| `test_passed`     | 취약점 없을 때 `status=PASSED` 반환                  |
| `test_vulnerable` | 취약점 있을 때 `status=VULNERABLE` + `evidence` 존재 |
| `test_error`      | 예외 발생 시 `status=ERROR` + `errors` 존재          |

### 7.3 Mock 테스트 예시

```python
from unittest.mock import patch, MagicMock
from va_mcp.core.schemas import ToolInput, TargetInfo, ApiRequest, ToolOptions
from va_mcp.tools.brute_force import BruteForceTool


def make_tool_input(**extra_opts):
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(method="POST", path="/api/login"),
        options=ToolOptions(extra=extra_opts),
    )


def test_passed():
    mock_resp = MagicMock(status_code=429, text="Too Many Requests")
    with patch("requests.post", return_value=mock_resp):
        result = BruteForceTool().run(make_tool_input(repeat_count=5))
    assert result.status == "passed"


def test_vulnerable():
    mock_resp = MagicMock(status_code=200, text='{"token":"abc"}')
    with patch("requests.post", return_value=mock_resp):
        result = BruteForceTool().run(
            make_tool_input(payload_list=["admin"], repeat_count=1)
        )
    assert result.status == "vulnerable"
    assert len(result.evidence) > 0


def test_error():
    with patch("requests.post", side_effect=Exception("connection refused")):
        result = BruteForceTool().run(make_tool_input())
    assert result.status == "error"
    assert len(result.errors) > 0
```

### 7.4 추가 검증 체크리스트

```text
- [ ] tool_id가 snake_case인가?
- [ ] 상태값/위험도/신뢰도가 상수를 사용했는가?
- [ ] Evidence 안에 민감 정보 마스킹이 적용되었는가?
- [ ] response_body_sample이 2000자를 초과하지 않는가?
- [ ] started_at, ended_at이 ISO-8601 UTC 형식인가?
```

---

## 8. tool 구현 예시 (IDOR)

```python
from va_mcp.core import (
    BaseTool,
    Confidence,
    Evidence,
    Severity,
    ToolInput,
    ToolResult,
    ToolStatus,
)
from va_mcp.core.utils import mask_sensitive, sanitize_response_sample, utc_now_iso


class IdorBolaTool(BaseTool):
    tool_id = "idor_bola"
    tool_name = "IDOR / BOLA Testing"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        # 분석 결과 예시 (실제 로직으로 대체)
        is_vulnerable = True

        if is_vulnerable:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.VULNERABLE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="다른 사용자 정보 조회 가능",
                description="user_a 토큰으로 user_b 데이터를 조회할 수 있습니다.",
                owasp=["A01 Broken Access Control"],
                cwe=["CWE-639"],
                evidence=[
                    Evidence(
                        request={
                            "method": "GET",
                            "url": "https://api.example.com/api/users/2",
                            "headers": mask_sensitive({"Authorization": "Bearer TOKEN_A"}),
                        },
                        response_status=200,
                        response_body_sample=sanitize_response_sample(
                            '{"id":2,"email":"user2@example.com"}'
                        ),
                        note="user_a 권한으로 user_b 정보 조회됨",
                    )
                ],
                recommendation="서버에서 요청한 userId가 현재 로그인 사용자와 일치하는지 반드시 검증해야 합니다.",
                started_at=started_at,
                ended_at=ended_at,
            )

        ended_at = utc_now_iso()
        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.PASSED,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            title="IDOR 취약점 미발견",
            description="권한 외 리소스 접근이 차단되었습니다.",
            started_at=started_at,
            ended_at=ended_at,
        )
```

---

## 9. 자주 하는 실수

| 실수                                    | 올바른 방법                            |
| --------------------------------------- | -------------------------------------- |
| `status="error"` 하드코딩               | `status=ToolStatus.ERROR` 사용         |
| `tool_id = "IDOR-BOLA"`                 | `tool_id = "idor_bola"` (snake_case)   |
| `status=ERROR`인데 `severity=HIGH`      | `status=ERROR`면 `severity=INFO` 고정  |
| Evidence에 토큰 원문 그대로 기록        | `mask_sensitive()` 통과 필수           |
| `response_body_sample`에 전체 응답 저장 | `sanitize_response_sample()` 통과 필수 |
| `core/schemas.py`에 필드 직접 추가      | `ToolOptions.extra` 사용               |
| 테스트 없이 PR 올리기                   | passed / vulnerable / error 3종 필수   |
| 공격 서버 없다고 테스트 미작성          | Mock으로 지금 당장 작성 가능           |
