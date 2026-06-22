tool_id: idor_bola
category: A01
설명: IDOR(Insecure Direct Object Reference) 탐지. 다른 사용자 소유 리소스에 무단 접근 가능한지 확인.
실행 조건: path에 숫자 ID 또는 UUID 존재, auth_state.tokens 2개 이상, auth_state.resource_ids 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 교차 접근 — auth_state 활용
- auth_state.tokens["userA"] 토큰으로
- auth_state.resource_ids["userB_owns"] 목록의 ID에 접근
- 예: GET /api/users/{userB_id}, GET /api/posts/{userB_post_id}

PROBE-2: ID 추측 접근
- 현재 경로의 ID를 ±1, ±2로 변조하여 요청
- auth_state.tokens 중 최저 권한 토큰 사용

PROBE-3: body 외래키 변조 (user_id, owner_id, sender_id 등 존재 시)
- 해당 필드를 다른 사용자 ID로 변조 후 요청

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- status_code == 200 + 다른 사용자 데이터 반환 → VULNERABLE
- status_code == 200 + body가 동일(자신의 데이터) → PASSED
- status_code == 403 / 401 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| 다른 사용자 민감 데이터 접근 성공           | CRITICAL | HIGH       |
| 다른 사용자 일반 데이터 접근 성공           | HIGH     | HIGH       |
| 403 / 401 반환                              | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 필수 포함 항목
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 사용한 토큰 role명
- 접근 시도한 리소스 ID
- 응답 body 발췌 (소유자 불일치 확인)
- status_code
