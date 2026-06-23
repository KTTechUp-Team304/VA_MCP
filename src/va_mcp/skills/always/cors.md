tool_id: cors
category: A02 / A05
설명: CORS 설정 오류 탐지. 인증 없는 상태와 토큰 첨부 상태 모두 검사.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 인증 없이 Origin 변조 요청 (3회)
- Origin: https://evil.example.com
- Origin: https://attacker.com
- Origin: null

PROBE-2: auth 토큰 첨부 상태로 동일 Origin 변조 요청 (auth_required=true 또는 returns_sensitive_data=true 인 경우)
- Authorization 헤더에 auth_state.tokens 중 최저 권한 토큰 첨부
- PROBE-1과 동일한 Origin 값으로 재요청

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- Access-Control-Allow-Origin이 요청한 Origin 값을 그대로 반영 → VULNERABLE
- Access-Control-Allow-Origin: * → VULNERABLE
- Access-Control-Allow-Credentials: true 동반 시 → CRITICAL로 상향
- 반영 없음, 또는 특정 도메인만 허용 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                      | severity | confidence |
|-------------------------------------------|----------|------------|
| ACAO 반영 + ACAC: true                    | CRITICAL | HIGH       |
| ACAO 와일드카드(*) + ACAC: true           | CRITICAL | HIGH       |
| ACAO 반영, ACAC 없음                      | HIGH     | HIGH       |
| ACAO 와일드카드(*), ACAC 없음             | MEDIUM   | HIGH       |
| 토큰 첨부 시에만 반영                     | HIGH     | MEDIUM     |
| 모든 PROBE PASSED                         | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [헤더] Origin: {사용한 Origin 값}
  [헤더] Authorization: Bearer {토큰} (PROBE-2 시)
  [응답] {status_code}
  [ACAO] Access-Control-Allow-Origin: {값}
  [ACAC] Access-Control-Allow-Credentials: {값} (존재 시)
  [비교] 인증 없음({ACAO값}) → 토큰 첨부({ACAO값}) (PROBE-2 실행 시)

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
