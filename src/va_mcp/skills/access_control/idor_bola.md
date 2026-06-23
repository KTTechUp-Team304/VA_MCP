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

baseline = auth_state.baseline_responses에서 자기 리소스 접근 시 응답.

- 교차 접근 응답이 baseline과 동일한 status_code + body에 다른 사용자 식별 데이터(user_id, owner_id 등) 포함 → VULNERABLE
- baseline과 동일한 status_code이지만 body가 자기 데이터만 반환 → PASSED (서버가 토큰 기준 필터링)
- baseline 대비 status_code가 403/401로 변화 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| baseline 대비 다른 사용자 민감 데이터 반환  | CRITICAL | HIGH       |
| baseline 대비 다른 사용자 일반 데이터 반환  | HIGH     | HIGH       |
| baseline 대비 4xx 변화                      | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL} (리소스 ID: {target_id})
  [헤더] Authorization: Bearer {토큰} (role: {role명})
  [응답] {status_code} / elapsed: {elapsed_seconds}s
  [body 발췌] {응답 본문 중 소유자 식별 필드 200자 이내}
  [비교] baseline(자기 리소스: {baseline_status}, owner={자기ID}) → 공격(타인 리소스: {attack_status}, owner={타인ID})

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
