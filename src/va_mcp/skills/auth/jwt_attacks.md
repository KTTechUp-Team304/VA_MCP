tool_id: auth_jwt
category: A07
설명: JWT 토큰 검증 우회 탐지. 만료, 서명 변조, alg:none, Algorithm Confusion 순서로 수행.
실행 조건: auth_state.tokens 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 만료 토큰 사용
- auth_state.tokens 중 임의 토큰의 exp 클레임을 과거 시각으로 변조
- 변조된 토큰으로 인증 필요 엔드포인트 접근

PROBE-2: 잘못된 서명
- 토큰 signature 마지막 3글자 변경
- 변조된 토큰으로 인증 필요 엔드포인트 접근

PROBE-3: alg:none 변형
- 헤더의 alg 값을 아래 순서대로 변조 후 접근:
  none / None / NONE / nOnE
- signature 제거 후 전송

PROBE-4: Algorithm Confusion (RS256 사용 시)
- 원본 토큰 alg가 RS256인 경우
- 공개키를 HS256 시크릿으로 사용해 재서명 후 접근

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 변조된 토큰으로 200 반환 → VULNERABLE
- 401 / 403 반환 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| alg:none 우회 성공                          | CRITICAL | HIGH       |
| Algorithm Confusion 우회 성공               | CRITICAL | HIGH       |
| 만료 토큰 접근 성공                         | HIGH     | HIGH       |
| 잘못된 서명 접근 성공                       | HIGH     | HIGH       |
| 모든 PROBE 401 / 403                        | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [변조] {변조 방법} (alg: {원본} → {변조값})
  [헤더] Authorization: Bearer {변조된 토큰 앞 20자}...
  [응답] {status_code} / elapsed: {elapsed_seconds}s
  [body 발췌] {응답 200자 이내}

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
