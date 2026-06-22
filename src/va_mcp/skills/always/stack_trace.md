tool_id: stack_trace_exposure
category: A02
설명: 비정상 입력 시 스택 트레이스 및 내부 정보 노출 여부 탐지.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 빈 body 전송
- execute_probe(method, path, body={})

PROBE-2: null 값 삽입
- 각 body 필드에 null 값 삽입

PROBE-3: 과도하게 긴 문자열 삽입
- 각 body 필드에 1000자 문자열 삽입

PROBE-4: 타입 불일치 삽입
- 숫자 필드에 문자열, 문자열 필드에 배열 삽입

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

응답 body에 아래 시그니처 중 하나라도 포함 시 VULNERABLE:
- Traceback
- at line
- Exception in
- caused by
- stack trace
- NullPointerException
- SyntaxError
- /var/www/
- C:\Users\
- C:\

- 500 응답이나 시그니처 없음 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| 스택 트레이스 + 내부 경로 노출              | HIGH     | HIGH       |
| 스택 트레이스만 노출                        | MEDIUM   | HIGH       |
| 500 응답, 시그니처 없음                     | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 필수 포함 항목
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 사용한 페이로드
- 탐지된 시그니처 문자열
- 응답 body 발췌 (최대 500자)
- status_code + elapsed_seconds
