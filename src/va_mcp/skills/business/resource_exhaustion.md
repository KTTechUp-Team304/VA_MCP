tool_id: resource_exhaustion
category: A04
설명: 대용량 페이로드로 서버 리소스 고갈 가능한지 탐지.
실행 조건: POST / PUT / PATCH, 파일 업로드 또는 대용량 처리 엔드포인트 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 100KB 더미 페이로드 전송
- body의 문자열 필드에 "A" * 102400 삽입
- elapsed_seconds 측정

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- elapsed_seconds >= 10.0 → VULNERABLE
- status_code == 500 → VULNERABLE (처리 실패)
- status_code == 413 Payload Too Large → PASSED (크기 제한 정상)
- elapsed_seconds < 10.0 + 정상 응답 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| elapsed_seconds >= 10.0                     | HIGH     | MEDIUM     |
| 500 반환                                    | MEDIUM   | MEDIUM     |
| 413 반환                                    | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 필수 포함 항목
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 페이로드 크기
- elapsed_seconds
- status_code
