tool_id: sensitive_path
category: A02
설명: 민감한 파일 및 경로 노출 여부 탐지.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 아래 경로에 GET 요청 순차 전송
- /.env
- /.git/config
- /backup.sql
- /config.yml
- /docker-compose.yml
- /docker-compose.yaml
- /.DS_Store
- /web.config

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- status_code == 200 → VULNERABLE
- status_code == 200 + body에 API 키 / 비밀번호 / DB 접속 정보 포함 → CRITICAL로 상향
- status_code == 302 / 301 리다이렉트 → INFO (접근 가능성 있음)
- status_code == 403 / 404 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| 200 + 민감 정보(키/비밀번호/DB) 포함        | CRITICAL | HIGH       |
| 200 + 일반 설정 파일 노출                   | HIGH     | HIGH       |
| 302/301 리다이렉트                          | INFO     | MEDIUM     |
| 모든 경로 403/404                           | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] GET {URL} (경로: {탐지된 경로})
  [응답] {status_code} / elapsed: {elapsed_seconds}s
  [body 발췌] {노출된 민감 정보 200자 이내}

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
