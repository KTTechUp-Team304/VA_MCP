tool_id: rbac_check
category: A01
설명: RBAC(Role-Based Access Control) 우회 탐지. 권한 계층 간 접근 제어가 올바르게 동작하는지 확인.
실행 조건: auth_state.role_hierarchy 2단계 이상, auth_state.tokens 2개 이상 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 최고 권한 토큰으로 정상 요청
- auth_state.role_hierarchy[0] 토큰 사용
- 응답 status_code + body 저장 (기준값)

PROBE-2: 최저 권한 토큰으로 동일 요청
- auth_state.role_hierarchy[-1] 토큰 사용
- 응답 status_code + body 저장

PROBE-3: 중간 권한 토큰으로 동일 요청 (3단계 이상 시)
- auth_state.role_hierarchy[1] 토큰 사용

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 최저 권한 응답 status_code == 최고 권한 응답 status_code + body 동일 → VULNERABLE
- 최저 권한 응답 status_code == 최고 권한 응답 status_code + body 다름 → MEDIUM
- 최저 권한 응답 status_code == 403 / 401 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                              | severity | confidence |
|---------------------------------------------------|----------|------------|
| 최저 권한으로 동일 응답 반환                      | HIGH     | HIGH       |
| 상태코드 같지만 body 다름                         | MEDIUM   | MEDIUM     |
| 최저 권한 403 / 401 반환                          | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 필수 포함 항목
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 최고 권한 응답 status_code + body 요약
- 최저 권한 응답 status_code + body 요약
- 두 응답의 차이점 명시
