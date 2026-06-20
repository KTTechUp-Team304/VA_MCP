tool_id: http_method_tamper
category: A01
설명: 허용되지 않아야 할 HTTP 메서드로 접근 가능한지 탐지.
실행 조건: auth_required=true, side_effect가 create/update/delete 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 허용되지 않아야 할 메서드로 접근
- GET / HEAD / OPTIONS / TRACE 순서대로 시도

PROBE-2: X-HTTP-Method-Override 헤더 삽입
- 원래 메서드로 요청 시 X-HTTP-Method-Override: DELETE 헤더 추가
- X-HTTP-Method-Override: PUT 헤더 추가

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 허용되지 않아야 할 메서드에서 200 / 201 / 204 반환 → VULNERABLE
- X-HTTP-Method-Override로 상태 변경 동작 시 → VULNERABLE
- 405 Method Not Allowed 반환 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| DELETE/PUT 동작 우회 성공                   | HIGH     | HIGH       |
| 비허용 메서드 200 반환                      | MEDIUM   | HIGH       |
| 405 반환                                    | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 필수 포함 항목
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 시도한 메서드 또는 Override 헤더값
- status_code + 응답 body 발췌
