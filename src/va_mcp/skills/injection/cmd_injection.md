tool_id: cmd_injection
category: A03
설명: Command Injection 탐지. 시간 기반 및 출력 기반으로 수행.
실행 조건: file, path, dir, cmd, exec, command 등 파라미터 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 시간 기반 (안전) — 각 파라미터에 순서대로 삽입
페이로드:
- ; sleep 5
- | sleep 5
- && sleep 5
- `sleep 5`
- ; ping -c 5 127.0.0.1

기준: elapsed_seconds > 4.5

PROBE-2: 출력 기반 — 각 파라미터에 순서대로 삽입
페이로드:
- ; whoami
- | id
- && ls
- ; cat /etc/passwd

응답 body에 "uid=", "root:", "daemon:" 등 포함 여부 확인

PROBE-3: Windows 환경 (징후 발견 시)
페이로드:
- & dir
- | type C:\Windows\win.ini
- && ipconfig

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- elapsed_seconds > 4.5 → VULNERABLE
- 응답 body에 "uid=", "root:", "daemon:", "Volume", "[extensions]" 포함 → VULNERABLE
- 모든 PROBE에서 응답 변화 없음 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                  | severity | confidence |
|---------------------------------------|----------|------------|
| 출력 기반 명령 실행 확인              | CRITICAL | HIGH       |
| 시간 기반 지연 확인                   | HIGH     | MEDIUM     |
| 모든 PROBE PASSED                     | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [페이로드] {파라미터명}={삽입한 페이로드}
  [응답] {status_code} / elapsed: {elapsed_seconds}s
  [body 발췌] {명령 실행 출력 200자 이내} (출력 기반 시)

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
