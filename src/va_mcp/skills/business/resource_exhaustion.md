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

baseline = auth_state.baseline_responses에서 정상 요청의 elapsed_seconds.

- 대용량 페이로드 응답의 elapsed_seconds가 baseline 대비 3배 이상 증가 → VULNERABLE
- status_code == 500 (baseline은 2xx) → VULNERABLE (처리 실패)
- status_code == 413 Payload Too Large → PASSED (크기 제한 정상)
- baseline 대비 elapsed_seconds 유의미한 차이 없음 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| baseline 대비 elapsed 3배 이상 증가         | HIGH     | MEDIUM     |
| baseline 대비 status_code 500 변화          | MEDIUM   | MEDIUM     |
| 413 반환                                    | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [페이로드] {필드명}에 {크기} 더미 데이터 삽입
  [응답] {status_code} / elapsed: {elapsed_seconds}s
  [비교] baseline(정상: {baseline_elapsed}s) → 공격(대용량: {attack_elapsed}s) — {배수}배 증가

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
