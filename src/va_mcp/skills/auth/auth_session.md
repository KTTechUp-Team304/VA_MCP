tool_id: auth_session
category: A07
설명: 로그아웃 후 토큰 재사용 가능한지 탐지. 세션 무효화 부재 확인.
실행 조건: auth.logout.path 명시, auth_state.tokens 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 로그아웃 전 토큰으로 정상 접근 확인
- auth_state.tokens 중 임의 토큰으로 인증 필요 엔드포인트 접근
- 200 응답 확인 (기준값)

PROBE-2: 로그아웃 수행
- auth.logout.path로 로그아웃 요청

PROBE-3: 로그아웃 후 동일 토큰으로 재접근
- PROBE-1과 동일한 토큰 + 동일한 엔드포인트 접근

PROBE-4: Refresh Token 재사용 (존재 시)
- 로그아웃 후 Refresh Token으로 새 Access Token 발급 시도

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- PROBE-3에서 200 반환 → VULNERABLE (세션 무효화 부재)
- PROBE-4에서 새 토큰 발급 성공 → VULNERABLE
- PROBE-3에서 401 / 403 반환 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| 로그아웃 후 토큰 재사용 성공               | HIGH     | HIGH       |
| Refresh Token 재사용 성공                  | HIGH     | HIGH       |
| 로그아웃 후 401 / 403 반환                 | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [PROBE-1] 로그아웃 전: {METHOD} {URL} → status={status_code}
  [PROBE-2] 로그아웃: {METHOD} {logout_path} → status={status_code}
  [PROBE-3] 로그아웃 후 재접근: {METHOD} {URL} → status={status_code}
  [body 발췌] {PROBE-3 응답 200자 이내}
  [비교] 로그아웃 전({status}) → 로그아웃 후({status})

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
