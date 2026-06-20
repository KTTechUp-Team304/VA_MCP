tool_id: insecure_jwt
category: A02
설명: JWT 알고리즘 및 시크릿 강도 취약점 탐지.
실행 조건: auth_state.tokens 존재 시

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
실행 순서
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBE-1: 토큰 헤더 디코딩
- auth_state.tokens 중 임의 토큰의 헤더(Base64) 디코딩
- alg 필드 값 확인

PROBE-2: alg 값에 따른 추가 분석
- none / None / NONE: auth_jwt.md의 PROBE-3 결과와 교차 확인
- HS256: 시크릿 강도 추론 (짧거나 예측 가능한 경우 LOW 기록)
- RS256: auth_jwt.md의 Algorithm Confusion 결과와 교차 확인
- 알 수 없는 알고리즘: VULNERABLE 기록

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
판단 기준
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- alg=none → VULNERABLE
- alg=HS256 + 시크릿이 짧거나 예측 가능 → LOW
- alg=RS256 → INFO (Algorithm Confusion 가능성, auth_jwt 결과 참조)
- alg=RS256 + Algorithm Confusion 성공 → CRITICAL

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
severity 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 조건                                        | severity | confidence |
|---------------------------------------------|----------|------------|
| alg=none 사용                               | CRITICAL | HIGH       |
| Algorithm Confusion 성공 (RS256)            | CRITICAL | HIGH       |
| HS256 + 약한 시크릿 추정                   | LOW      | LOW        |
| RS256 정상 사용                             | INFO     | HIGH       |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
evidence 필수 포함 항목
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- 토큰 헤더 디코딩 값 (alg, typ)
- 시크릿 강도 추론 근거 (HS256 시)
