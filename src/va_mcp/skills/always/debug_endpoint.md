tool_id: debug_endpoint
category: A02
설명: 디버그 및 관리 엔드포인트 노출 여부 탐지.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 아래 경로에 GET 요청 순차 전송
- /api-docs
- /swagger
- /swagger-ui.html
- /swagger-ui/index.html
- /health
- /metrics
- /debug
- /actuator/env
- /actuator/beans
- /__debug__

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- status_code == 200 + 환경변수 / 전체 설정 / DB 접속 정보 노출 → CRITICAL
- status_code == 200 + API 명세 / 시스템 정보 노출 → HIGH
- status_code == 200 + 단순 {"status": "ok"} 수준 → INFO
- status_code == 401 / 403 (인증 필요) → INFO (엔드포인트 존재 확인)
- status_code == 404 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| 200 + 환경변수 / DB 접속 정보 노출          | CRITICAL | HIGH       |
| 200 + API 명세 / 시스템 정보 노출           | HIGH     | HIGH       |
| 200 + 단순 상태 정보                        | INFO     | HIGH       |
| 401 / 403 (엔드포인트 존재)                 | INFO     | MEDIUM     |
| 모든 경로 404                               | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] GET {URL} (경로: {탐지된 경로})
  [응답] {status_code} / elapsed: {elapsed_seconds}s
  [노출 수준] 환경변수 / API 명세 / 단순 상태
  [body 발췌] {노출된 정보 200자 이내}

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
