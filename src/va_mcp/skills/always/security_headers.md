tool_id: security_headers
category: A02
설명: 응답 헤더에서 필수 보안 헤더 누락 여부 탐지.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 타깃 엔드포인트에 정상 요청 전송
- 응답 헤더에서 아래 6개 항목 존재 여부 확인:
  Content-Security-Policy (CSP)
  Strict-Transport-Security (HSTS)
  X-Frame-Options
  X-Content-Type-Options
  Referrer-Policy
  Permissions-Policy

PROBE-2: CSP 존재 시 값 분석
- unsafe-inline 포함 여부
- unsafe-eval 포함 여부
- wildcard(*) 포함 여부

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 6개 중 3개 이상 누락 → VULNERABLE
- 1~2개 누락 → LOW
- CSP 존재하나 unsafe-inline / unsafe-eval / wildcard 포함 → LOW
- 6개 모두 존재, CSP 안전 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                              | severity | confidence |
|-----------------------------------|----------|------------|
| 3개 이상 누락                     | MEDIUM   | HIGH       |
| 1~2개 누락                        | LOW      | HIGH       |
| CSP unsafe-inline/eval/wildcard   | LOW      | HIGH       |
| 모두 존재, CSP 안전               | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 필수 포함 항목
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 누락된 헤더 목록
- CSP 값 전문 (존재 시)
