tool_id: sql_injection
category: A03
설명: SQL Injection 탐지. 에러 기반, Boolean Blind, 시간 기반 순서로 수행.
실행 조건: body 또는 query에 파라미터 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 에러 기반 — 각 파라미터에 순서대로 삽입
페이로드: ["'", '"', ";", "--", "')", "' OR '1'='1", "' OR 1=1--"]

PROBE-2: Boolean Blind — 각 파라미터에 쌍으로 전송
- 참 조건: 파라미터 AND 1=1
- 거짓 조건: 파라미터 AND 1=2
- status_code, body 길이, 응답 토큰 수 비교

PROBE-3: 시간 기반 — 각 파라미터에 순서대로 삽입
페이로드:
- MySQL: '; SLEEP(3)--
- PostgreSQL: '; SELECT pg_sleep(3)--
- MSSQL: '; WAITFOR DELAY '0:0:3'--

WAF 우회 의심 시 추가 시도:
- URL 인코딩: %27, %22
- 주석 삽입: /**/, /*!*/
- 대소문자 혼합: SeLeCt, WaItFoR

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- body에 "ORA-", "syntax error", "SQL syntax", "mysql_fetch", "SQLSTATE", "unterminated" 포함 → VULNERABLE
- Boolean 참/거짓 응답에서 status_code 또는 body 길이 차이 발생 → VULNERABLE
- elapsed_seconds > 4.5 (시간 기반) → VULNERABLE
- 모든 PROBE에서 응답 변화 없음 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                              | severity | confidence |
|-----------------------------------|----------|------------|
| 에러 메시지 직접 노출             | CRITICAL | HIGH       |
| Boolean Blind 확인                | HIGH     | HIGH       |
| 시간 기반 지연 확인               | HIGH     | MEDIUM     |
| 응답 차이 애매함                  | MEDIUM   | LOW        |
| 모든 PROBE PASSED                 | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [페이로드] {파라미터명}={삽입한 페이로드}
  [응답] {status_code} / elapsed: {elapsed_seconds}s
  [시그니처] {탐지된 SQL 에러 문자열} (에러 기반 시)
  [Boolean] 참({status_code}, body 길이 {N}) → 거짓({status_code}, body 길이 {N}) (Blind 시)
  [body 발췌] {판단 근거가 되는 응답 부분 200자 이내}

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
