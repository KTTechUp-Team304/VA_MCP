tool_id: business_logic_check
category: A04
설명: 비즈니스 로직 우회 탐지. 흐름 건너뛰기, 상태 역행, 금액 변조 등.
실행 조건: state / status / step 등 흐름 제어 필드 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 중간 단계 건너뛰기
- step=1 요청 후 바로 step=3 직접 전송
- 응답 정상 처리 여부 확인

PROBE-2: 상태 역행
- status=completed → status=pending 으로 변조 요청
- 응답 정상 처리 여부 확인

PROBE-3: 금액/가격 변조 (price, balance, discount 등 존재 시)
페이로드:
- price=0
- price=-1
- discount=100
- amount=0.001

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

baseline = 정상 값으로 요청한 응답. 변조 응답과 비교합니다.

- 변조 응답이 baseline과 동일한 status_code + body에 변조된 값이 반영됨 → VULNERABLE
- baseline과 동일한 status_code이지만 body에 변조 값 미반영 (서버가 무시) → PASSED
- baseline 대비 status_code가 4xx로 변화 → PASSED (검증 정상)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| baseline 대비 변조 값 반영 — 금액 0/음수    | CRITICAL | HIGH       |
| baseline 대비 변조 값 반영 — 단계/상태 우회 | HIGH     | HIGH       |
| baseline 대비 4xx 변화 (검증 정상)          | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL}
  [페이로드] {변조한 필드}={변조한 값}
  [응답] {status_code} / elapsed: {elapsed_seconds}s
  [body 발췌] {응답 본문 중 변조 반영 여부 확인 200자 이내}
  [비교] baseline(정상 값: {baseline_status}) → 공격(변조 값: {attack_status})

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
