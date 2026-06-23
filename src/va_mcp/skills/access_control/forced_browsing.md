tool_id: forced_browsing
category: A01
설명: 인증 없이 인증 필요 경로에 직접 접근 가능한지 탐지.
실행 조건: auth_required=true 또는 admin/config/internal 경로 패턴 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 인증 없이 타깃 엔드포인트 직접 접근
- Authorization 헤더 없이 요청

PROBE-2: 추론 경로에 인증 없이 접근
- 현재 경로 패턴 기반 추론:
  /admin, /config, /internal, /backup
  /api/v2 (버전 변경), /api/admin
  /manage, /dashboard, /private

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

baseline = auth_state.baseline_responses에서 인증된 정상 요청의 응답.

- 인증 없이 보낸 응답이 baseline(인증된 응답)과 동일한 status_code + body 패턴 → VULNERABLE
- baseline 대비 status_code가 4xx로 변화하거나 body가 에러 응답 → PASSED
- status_code == 302 + Location이 로그인 페이지 → PASSED (정상 리다이렉트)
- status_code == 302 + Location이 로그인 페이지 외 → INFO (접근 가능성 확인 필요)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| baseline과 동일 응답 (인증 우회)             | HIGH     | HIGH       |
| 302 리다이렉트 (로그인 페이지 외)           | INFO     | MEDIUM     |
| baseline 대비 4xx 변화                       | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 작성 형식 (이 형식을 반드시 따르세요)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [요청] {METHOD} {URL} (인증 없이)
  [응답] {status_code} / elapsed: {elapsed_seconds}s
  [body 발췌] {응답 본문 중 판단 근거 200자 이내}
  [비교] baseline(인증됨: {baseline_status}) → 공격(인증 없음: {attack_status})

  ※ 추론 금지. 실제 execute_probe 결과만 기재.
