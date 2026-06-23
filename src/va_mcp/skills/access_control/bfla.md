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

baseline = auth_state.baseline_responses에서 최고 권한 role의 정상 응답.

- 최저 권한 응답이 baseline(최고 권한)과 동일한 status_code + body 패턴 → VULNERABLE
- baseline 대비 status_code가 4xx로 변화하거나 body가 에러 응답 → PASSED
- status_code는 같지만 body 내용이 다름 (권한 필터링 존재) → INFO
- status_code == 404 → PASSED (경로 없음)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| baseline과 동일 응답 — 관리자 기능 실행 성공 | CRITICAL | HIGH       |
| baseline과 동일 응답 — 관리자 경로 접근 성공 | HIGH     | HIGH       |
| baseline 대비 4xx 변화                       | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [헤더] Authorization: Bearer {최저 권한 토큰} (role: {role명})
  [응답] {status_code} / elapsed: {elapsed_seconds}s
  [body 발췌] {응답 본문 중 판단 근거 200자 이내}
  [비교] baseline(최고 권한 {role명}: {baseline_status}) → 공격(최저 권한 {role명}: {attack_status})

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
