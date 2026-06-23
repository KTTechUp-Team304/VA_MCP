tool_id: path_traversal
category: A03
설명: Path Traversal 탐지. 경로 관련 파라미터에 디렉토리 탈출 페이로드 삽입.
실행 조건: file, path, doc, resource 등 경로 관련 파라미터 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 기본 페이로드 — 각 파라미터에 순서대로 삽입
페이로드:
- ../../../etc/passwd
- ..%2F..%2F..%2Fetc%2Fshadow
- ....//....//....//etc/passwd

PROBE-2: Null byte 우회
페이로드:
- ../../../etc/passwd%00.jpg
- ../../../etc/passwd%00.png

PROBE-3: Windows 환경 (X-Powered-By 또는 Server 헤더에서 Windows 징후 시)
페이로드:
- ..\..\..\windows\win.ini
- ..%5C..%5C..%5Cwindows%5Cwin.ini

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 응답 body에 "root:", "daemon:", "[extensions]", "/bin/bash" 포함 → VULNERABLE
- status_code == 200 + 파일 내용으로 보이는 응답 → VULNERABLE
- 모든 PROBE에서 403 / 404 / 400 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                  | severity | confidence |
|---------------------------------------|----------|------------|
| /etc/passwd 내용 노출                 | CRITICAL | HIGH       |
| 시스템 파일 내용 노출                 | HIGH     | HIGH       |
| 200 응답, 내용 불명확                 | MEDIUM   | LOW        |
| 모든 PROBE PASSED                     | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [페이로드] {파라미터명}={삽입한 페이로드}
  [응답] {status_code} / elapsed: {elapsed_seconds}s
  [body 발췌] {노출된 파일 내용 200자 이내}

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
