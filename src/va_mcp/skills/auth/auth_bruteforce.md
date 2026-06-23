tool_id: auth_bruteforce
category: A07
설명: 계정 잠금 없이 연속 로그인 시도가 가능한지 탐지.
실행 조건: 로그인 엔드포인트, auth_state.tokens 2개 이상 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: accounts 목록으로 연속 로그인 시도
- 제공된 accounts 자격증명으로 순차 로그인 요청
- 응답 속도 및 status_code 변화 관찰

PROBE-2: 잘못된 자격증명으로 20회 연속 시도
- 존재하지 않는 비밀번호로 동일 계정에 20회 요청
- 응답 코드 / 메시지 변화 관찰

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1회차 응답을 baseline으로 저장하고, 이후 응답과 비교합니다.

- 20회 전 구간에서 baseline과 동일한 status_code·body·elapsed_seconds 유지 → VULNERABLE (잠금 없음)
- 특정 횟수 이후 baseline 대비 status_code 변화 또는 body에 차단 메시지 출현 → PASSED
- baseline 대비 elapsed_seconds가 점진적으로 증가 → PASSED (지연 기반 차단)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| 20회 연속 baseline과 동일 (잠금 없음)       | HIGH     | HIGH       |
| N회차 이후 baseline 대비 응답 변화 (차단됨) | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [1회차] status={status_code} / elapsed={elapsed_seconds}s / body 발췌: {발췌}
  [10회차] status={status_code} / elapsed={elapsed_seconds}s / body 발췌: {발췌}
  [20회차] status={status_code} / elapsed={elapsed_seconds}s / body 발췌: {발췌}
  [비교] baseline({1회차_status}) → 최종({20회차_status})

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
