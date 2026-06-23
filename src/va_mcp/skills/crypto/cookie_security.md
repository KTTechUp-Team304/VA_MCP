tool_id: cookie_security
category: A02
설명: 응답 쿠키의 보안 플래그 설정 여부 탐지.
실행 조건: 응답에 Set-Cookie 헤더 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 타깃 엔드포인트 정상 요청
- 응답 Set-Cookie 헤더에서 아래 플래그 확인:
  Secure, HttpOnly, SameSite
- Domain 값 확인 (상위 도메인 설정 여부)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- Secure 플래그 없음 → VULNERABLE
- HttpOnly 플래그 없음 → VULNERABLE
- SameSite 없음 또는 SameSite=None → VULNERABLE
- SameSite=Lax → INFO (GET 방식 CSRF 가능성)
- Domain=상위도메인 → INFO (서브도메인 쿠키 노출 가능)
- 세 플래그 모두 존재 + SameSite=Strict → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| Secure + HttpOnly 모두 없음                 | HIGH     | HIGH       |
| Secure 또는 HttpOnly 하나 없음              | MEDIUM   | HIGH       |
| SameSite=None                               | MEDIUM   | HIGH       |
| SameSite=Lax                                | INFO     | MEDIUM     |
| 모든 플래그 정상                            | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [응답] {status_code}
  [Set-Cookie] {Set-Cookie 헤더 전문}
  [누락 플래그] {누락된 플래그 목록}

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
