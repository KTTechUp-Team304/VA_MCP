tool_id: rate_limit_check
category: A04
설명: 상태 변경 엔드포인트의 Rate Limit 부재 탐지.
실행 조건: POST / PUT / DELETE / PATCH 상태 변경 엔드포인트 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 동일 요청 10회 연속 전송
- 매 3회마다 status_code + elapsed_seconds 기록
- X-RateLimit-Remaining 헤더 존재 시 값 추적

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1회차 응답을 baseline으로 저장하고, 이후 응답과 비교합니다.

- 10회 전 구간에서 baseline과 동일한 status_code·body 패턴 유지 → VULNERABLE (차단 메커니즘 없음)
- 특정 횟수 이후 baseline과 다른 status_code(429, 403, 302 등) 또는 body 변화 발생 → PASSED
- X-RateLimit-Remaining이 감소하다 0에 도달 후 응답 변화 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| 10회 연속 baseline과 동일 (차단 없음)       | MEDIUM   | HIGH       |
| N회차 이후 baseline 대비 응답 변화 (차단됨) | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [1회차] status={status_code} / elapsed={elapsed_seconds}s
  [3회차] status={status_code} / elapsed={elapsed_seconds}s
  [6회차] status={status_code} / elapsed={elapsed_seconds}s
  [10회차] status={status_code} / elapsed={elapsed_seconds}s
  [헤더] X-RateLimit-Remaining: {값 변화} (존재 시)
  [비교] baseline({1회차_status}) → 최종({N회차_status})

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
