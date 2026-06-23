tool_id: auth_enum
category: A07
설명: 사용자 열거 취약점 탐지. 유효/무효 자격증명 조합 응답 차이로 계정 존재 여부 추론 가능한지 확인.
실행 조건: accounts 2개 이상 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 유효 자격증명으로 요청
- 정상 ID + 정상 PW → 응답 기록

PROBE-2: 무효 ID + 유효 PW로 요청
- 존재하지 않는 ID + 정상 PW → 응답 기록

PROBE-3: 유효 ID + 무효 PW로 요청
- 정상 ID + 틀린 PW → 응답 기록

세 응답에서 아래 세 가지 비교:
1. status_code
2. 응답 메시지 (body)
3. elapsed_seconds

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- PROBE-2와 PROBE-3의 응답 메시지가 다름 → VULNERABLE (계정 존재 여부 열거 가능)
- elapsed_seconds 차이 > 0.5초 → VULNERABLE (타이밍 공격 가능)
- 세 응답 모두 동일 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| 응답 메시지 차이로 계정 열거 가능           | MEDIUM   | HIGH       |
| 타이밍 차이로 계정 열거 가능                | MEDIUM   | MEDIUM     |
| 세 응답 동일                                | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [PROBE-1] 유효ID+유효PW → status={status_code} / elapsed={elapsed_seconds}s / body: {발췌}
  [PROBE-2] 무효ID+유효PW → status={status_code} / elapsed={elapsed_seconds}s / body: {발췌}
  [PROBE-3] 유효ID+무효PW → status={status_code} / elapsed={elapsed_seconds}s / body: {발췌}
  [비교] PROBE-2 vs PROBE-3 body 차이: {차이점} / elapsed 차이: {차이}s

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
