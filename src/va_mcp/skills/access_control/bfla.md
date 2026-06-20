tool_id: bfla
category: A01
설명: BFLA(Broken Function Level Authorization) 탐지. 낮은 권한 토큰으로 관리자 기능 접근 가능한지 확인.
실행 조건: auth_state.role_hierarchy 2단계 이상, auth_state.tokens 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 관리자 경로 직접 접근
- auth_state.tokens 중 최저 권한 토큰 사용
- 아래 경로에 순서대로 요청:
  /admin, /admin/users, /admin/settings
  /api/admin, /api/management, /api/internal
  현재 경로 패턴 기반 추론 경로

PROBE-2: 관리자 전용 기능 직접 호출
- auth_state.role_hierarchy 최고 권한이 접근하는 엔드포인트에
- 최저 권한 토큰으로 동일 요청

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- status_code == 200 / 201 / 204 → VULNERABLE
- status_code == 403 / 401 → PASSED
- status_code == 404 → PASSED (경로 없음)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| 최저 권한으로 관리자 기능 실행 성공         | CRITICAL | HIGH       |
| 최저 권한으로 관리자 경로 접근 성공         | HIGH     | HIGH       |
| 403 / 401 반환                              | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 필수 포함 항목
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 사용한 토큰 role명
- 접근 시도한 경로
- status_code + 응답 body 발췌
