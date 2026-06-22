tool_id: xss_reflected
category: A03
설명: Reflected XSS 탐지. 입력값이 응답 body에 반사되는지 확인.
실행 조건: 입력값이 응답 body에 반사될 가능성 있는 파라미터 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 기본 페이로드 — 각 파라미터에 순서대로 삽입
페이로드:
- <script>alert(1)</script>
- "><script>alert(1)</script>
- '><svg onload=alert(1)>
- <img src=x onerror=alert(1)>

PROBE-2: 필터링 우회 시도 (PROBE-1에서 필터링 징후 발견 시)
페이로드:
- %3cscript%3ealert(1)%3c/script%3e
- &#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
- <ScRiPt>alert(1)</ScRiPt>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 페이로드가 응답 body에 이스케이프 없이 그대로 반사 → VULNERABLE
- 페이로드가 HTML 인코딩되어 반사 → PASSED (필터링 정상)
- 응답 body에 페이로드 없음 → PASSED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                  | severity | confidence |
|---------------------------------------|----------|------------|
| script 태그 그대로 반사               | HIGH     | HIGH       |
| 이벤트 핸들러(onerror 등) 반사        | HIGH     | HIGH       |
| 우회 페이로드로만 반사                | MEDIUM   | MEDIUM     |
| HTML 인코딩되어 반사                  | PASSED   | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 필수 포함 항목
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 사용한 페이로드 + 삽입한 파라미터명
- 응답 body에서 반사된 부분 발췌
- status_code
