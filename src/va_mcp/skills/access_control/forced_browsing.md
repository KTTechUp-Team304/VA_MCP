tool_id: forced_browsing
category: A01
설명: 인증 없이 인증 필요 경로에 직접 접근 가능한지 탐지.
실행 조건: auth_required=true 또는 admin/config/internal 경로 패턴 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 인증 없이 타깃 엔드포인트 직접 접근
- Authorization 헤더 없이 요청

PROBE-2: 추론 경로에 인증 없이 접근
- 현재 경로 패턴 기반 추론:
  /admin, /config, /internal, /backup
  /api/v2 (버전 변경), /api/admin
  /manage, /dashboard, /private

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- status_code == 200 / 201 / 204 → VULNERABLE
- status_code == 401 / 403 → PASSED
- status_code == 302 → INFO (리다이렉트, 접근 가능성 확인 필요)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| 인증 없이 200 / 201 / 204 반환              | HIGH     | HIGH       |
| 302 리다이렉트 (로그인 페이지 외)           | INFO     | MEDIUM     |
| 401 / 403 반환                              | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 필수 포함 항목
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 접근 시도한 경로
- status_code + 응답 body 발췌
