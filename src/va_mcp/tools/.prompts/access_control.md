# Access Control 도구 구현 전 결정사항

우리는 Python 기반 취약점 분석 도구를 구현한다. 이 문서는 Access Control 계열 도구(RBAC, IDOR/BOLA, BFLA, Forced Browsing, HTTP Method Tampering, Parameter Tampering)의 공통 기준을 정의한다.

---

## 1. VULNERABLE 판단 기준

취약 여부는 상태코드만으로 판단하지 않는다.

기본 판단 요소:

* 상태코드 비교
* 원본 응답과 테스트 응답의 body 비교
* confidence 수준 기록

권장 기준:

* `200`, `201`, `204` 성공 응답이 낮은 권한 사용자에게 발생하면 `VULNERABLE`
* 원본 권한 응답과 테스트 권한 응답이 동일/유사하면 `confidence=Confidence.HIGH`
* 상태코드는 같지만 body가 달라지면 `confidence=Confidence.MEDIUM`
* `401`, `403`은 일반적으로 `status=PASSED, severity=Severity.INFO`
* 애매한 경우 `status=PASSED, severity=Severity.LOW`

---

## 2. safe_mode 기준

`ToolOptions.safe_mode = True` 일 때 실제 데이터 변경 가능성이 있는 요청을 제한한다.

### safe_mode=True

허용 메서드:

* GET
* HEAD
* OPTIONS
* TRACE

### safe_mode=False

전체 허용:

* GET
* HEAD
* OPTIONS
* TRACE
* POST
* PUT
* PATCH
* DELETE

---

## 3. SKIPPED 처리 기준

필수 입력이 부족하면 실패가 아니라 `SKIPPED` 처리한다.

```python
if not tool_input.request:
    return ToolResult(status=ToolStatus.SKIPPED)
```

예시:

* request 없음
* auth 부족
* 필수 path 없음

---

# 도구별 구현 기준

## 1. RBAC 테스트

권한 계층은 `auth` 리스트 순서 기준으로 판단한다.

* `auth[0]` = 가장 낮은 권한
* `auth[-1]` = 가장 높은 권한

### 로직

1. 고권한 토큰으로 요청 성공 여부 확인
2. 저권한 토큰으로 동일 요청 수행
3. 저권한이 성공하면 취약
4. 응답 body 동일 시 confidence 상승

### SKIPPED 조건

* request 없음
* auth 2개 미만

---

## 2. IDOR / BOLA 테스트

타인의 리소스 접근 가능 여부 확인.

### 입력 규칙

* `auth[0]` = 공격자
* `auth[1]` = 리소스 소유자
* `request.path` = 소유자 리소스 경로

### 로직

1. 소유자 토큰으로 정상 접근 확인
2. 공격자 토큰으로 동일 경로 요청
3. 공격자가 성공하면 취약
4. 응답 동일 시 confidence 상승

### SKIPPED 조건

* request 없음
* auth 2개 미만

---

## 3. BFLA 테스트

낮은 권한 사용자가 관리자 기능 접근 가능한지 확인.

### 입력

* 기본 경로: `request.path`
* 추가 경로: `extra["additional_paths"]`

### 로직

* `200/201/204` → `status=VULNERABLE, severity=Severity.HIGH`
* `401/403` → `status=PASSED, severity=Severity.INFO`
* `302` → `status=PASSED, severity=Severity.LOW`

### SKIPPED 조건

* request 없음
* auth 1개 미만

---

## 4. 강제 브라우징 테스트

숨겨진 경로 노출 여부 확인.

### 기본 경로

```txt
/admin
/administrator
/api/admin
/dashboard
/backup
/config
/.env
/swagger
/api-docs
/actuator
/actuator/env
/health
/.git/config
```

### 추가 경로

```python
extra["paths"] = ["/custom/path"]
```

### 판단 기준

* `200` → `status=VULNERABLE, severity=Severity.HIGH`
* `403` → `status=PASSED, severity=Severity.INFO`
* `401` → `status=PASSED, severity=Severity.INFO`
* `404` → `status=PASSED, severity=Severity.INFO`
* `302` → `status=PASSED, severity=Severity.LOW`

---

## 5. HTTP 메서드 변조 테스트

허용되지 않아야 할 메서드가 열려 있는지 확인.

### safe_mode=True

```python
["GET", "HEAD", "OPTIONS", "TRACE"]
```

### safe_mode=False

```python
["GET", "HEAD", "OPTIONS", "TRACE", "POST", "PUT", "PATCH", "DELETE"]
```

### 추가 옵션

```python
extra["test_methods"] = ["DELETE", "PUT"]
```

### 판단 기준

* `200/201/204` → `status=VULNERABLE, severity=Severity.HIGH`
* TRACE 200 → `status=VULNERABLE, severity=Severity.MEDIUM`
* OPTIONS Allow 위험 메서드 포함 → `status=PASSED, severity=Severity.LOW`
* `401/403/405` → `status=PASSED, severity=Severity.INFO`

---

## 6. 파라미터 변조 테스트

권한 관련 파라미터 조작 가능 여부 확인.

### 자동 탐지 키워드

```txt
role
is_admin
admin
user_type
privilege
permission
access_level
group
scope
```

### 기본 페이로드

```txt
admin
administrator
superuser
root
true
1
0
-1
99999
```

### 명시 옵션

```python
extra["target_params"] = [
  {"key": "role", "values": ["admin", "superuser"]}
]
```

### 판단 기준

* 원본 `403` → 변조 후 `200` → `status=VULNERABLE, severity=Severity.HIGH, confidence=Confidence.HIGH`
* 상태코드 동일 + body 변화 → `status=VULNERABLE, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM`
* 변화 없음 → `status=PASSED, severity=Severity.INFO`

---

## 7. CORS 미설정 테스트

임의의 Origin 헤더를 포함한 요청을 보내고, 서버가 교차 출처 요청을 허용하는지 확인한다.

### 입력

* 기본 경로: `request.path` (없으면 `/` 사용)
* 인증: `auth[0]` (없으면 비인증 요청)

### 기본 테스트 Origin 목록

```txt
https://evil.example.com
https://attacker.com
null
```

### 추가 옵션

```python
extra["test_origins"] = ["https://custom-attacker.com"]
```

### 판단 기준

| 조건 | status | severity |
|------|--------|----------|
| ACAO: 공격자 Origin 반사 또는 `*` + ACAC: true | `VULNERABLE` | `CRITICAL` |
| ACAO: 공격자 Origin 반사 또는 `*` (크레덴셜 없음) | `VULNERABLE` | `HIGH` |
| ACAO: `null` 허용 | `VULNERABLE` | `MEDIUM` |
| 허용하지 않음 | `PASSED` | `INFO` |

* 여러 Origin 테스트 중 가장 높은 severity가 최종 결과에 반영된다.
* `Access-Control-Allow-Credentials: true` + ACAO 허용은 실제 세션 탈취로 이어질 수 있어 CRITICAL로 분류한다.

### SKIPPED 조건

* 없음 (target만 있으면 실행 가능)

---

# 공통 반환 구조

```python
ToolResult(
    tool_id=self.tool_id,
    tool_name=self.tool_name,
    status=ToolStatus.VULNERABLE,   # VULNERABLE | PASSED | SKIPPED | ERROR
    severity=Severity.HIGH,         # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence=Confidence.HIGH,     # HIGH | MEDIUM | LOW
    title="취약점 제목 (한 줄 요약)",
    description="취약점 상세 설명",
    owasp=["A01 Broken Access Control"],
    cwe=["CWE-284"],
    evidence=[...],
    recommendation="수정 권고 내용",
    started_at=started_at,
    ended_at=utc_now_iso(),
)
```

주의:
* `ToolStatus.INFO` 는 존재하지 않는다. `status=PASSED, severity=INFO` 로 표현한다.
* `message` 필드는 없다. `title` (한 줄 요약) + `description` (상세) 로 분리한다.
* `confidence` 는 반드시 `Confidence` enum을 사용한다. 문자열 하드코딩 금지.

---

# 최종 구현 원칙

1. 입력 검증
2. safe_mode 확인
3. 기준 요청 실행
4. 테스트 요청 실행
5. 상태코드 비교
6. 응답 body 비교
7. evidence 생성
8. ToolResult 반환
