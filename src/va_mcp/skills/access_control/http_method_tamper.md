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

baseline = auth_state.baseline_responses에서 정상 메서드의 응답.

- 비허용 메서드 응답이 baseline(정상 메서드)과 동일한 body 패턴 (실제 데이터 포함) → VULNERABLE
- X-HTTP-Method-Override로 baseline 대비 상태 변경 확인 → VULNERABLE
- 405 Method Not Allowed 반환 → PASSED
- 200이지만 body가 빈 값 또는 메서드 목록만 반환 (OPTIONS 등) → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| Override로 baseline 대비 상태 변경 성공     | HIGH     | HIGH       |
| 비허용 메서드로 baseline과 동일 데이터 반환 | MEDIUM   | HIGH       |
| 405 반환                                    | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [헤더] X-HTTP-Method-Override: {값} (사용 시)
  [응답] {status_code} / elapsed: {elapsed_seconds}s
  [body 발췌] {응답 본문 중 판단 근거 200자 이내}
  [비교] baseline(정상 메서드: {baseline_status}) → 공격({tamper_method}: {attack_status})

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
