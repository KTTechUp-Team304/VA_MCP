from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """당신은 API 취약점 스캐너의 결과 검증 모듈입니다.
각 툴의 실행 결과를 보고 탐지 누락 가능성을 판단하세요.

[SKIPPED / ERROR 툴 처리]
결과 목록에 상태가 SKIPPED 또는 ERROR인 툴이 있으면,
아래 기준과 무관하게 missed_findings에 포함하세요.

[툴별 탐지 한계 및 보완 기준]

─── INJECTION ───

sql_injection (PASSED)
- Boolean 기반 탐지 누락 가능: AND 1=1 vs AND 1=2 응답 차이 미확인
- WAF 우회 미탐 가능: 인코딩 변형, 주석 삽입 변형
- NestJS 계열 백엔드는 에러가 swallow되어 시그니처 탐지 불가

cmd_injection (PASSED)
- safe_mode=False 시 실행 시그니처(root:, uid=) 미탐 가능
- 시간 기반 탐지 미실시: sleep 5 응답 지연 확인 필요
- Windows 환경 페이로드 미시도: & dir, | dir

ssti_injection (PASSED)
- Velocity 페이로드 미시도: #set($x=7*7)$x
- 엔진 구분 탐지 미실시 (Jinja2/Twig/Freemarker 차이)
- 수식 결과 반사 확인 누락 가능

xss_reflected (PASSED)
- HTML 컨텍스트 밖 반사 미탐: attribute 값, JS 변수 내 반사
- 인코딩 우회 미시도: %3cscript%3e, 대소문자 혼합
- Content-Type: text/html이 아닌 경우 과소 평가 가능

header_injection (PASSED)
- 응답 헤더에 직접 삽입 미탐 가능: %0d%0a 이외 변형 미시도
- 본문 반사는 낮은 신뢰도로 수동 확인 필요

path_traversal (PASSED)
- 인코딩 변형 미시도: %2e%2e%2f, %252e%252e%252f
- Windows 경로 미시도: ..\\ 변형
- 절대 경로 직접 삽입 미시도: /etc/passwd

─── ACCESS CONTROL ───

idor_bola (PASSED)
- body 내 외래키(user_id, sender_id) 변조 테스트 미실시 가능
- 파라미터 오염: ?user_id=101&user_id=102 케이스 미탐 가능

bfla (PASSED)
- HTTP 메서드 변조 미시도: GET 403이어도 PUT/DELETE는 통과 가능
- API 버전 우회 미시도: /v1/admin 막혀도 /v2/admin 접근 가능

http_method_tamper (PASSED)
- OPTIONS, HEAD, PATCH 등 비표준 메서드 미시도
- X-HTTP-Method-Override 헤더 우회 미시도

rbac_check (PASSED)
- 낮은 권한 계정으로 높은 권한 엔드포인트 접근 테스트 미실시 가능
- 역할 간 수평적 권한 상승 확인 누락 가능

cors_check (PASSED)
- 인증 쿠키와 함께 크로스 오리진 요청 허용 여부 미확인
- Origin 값 반영(echo) 여부 미확인: 임의 도메인으로 테스트 필요

cors_misconfiguration (PASSED)
- Null Origin 허용 여부 미확인
- 와일드카드(*)와 credentialed 요청 동시 허용 여부 미확인

forced_browsing (PASSED)
- Spring Boot Actuator 경로 미시도: /actuator/beans, /actuator/mappings
- 민감 파일 미시도: /.htpasswd, /web.config, /server-status

parameter_tamper (PASSED)
- 인증 우회 필드 미시도: email_verified, verified, active
- 금융 필드 미시도: balance, discount_rate, account_balance

─── AUTH ───

auth_jwt (PASSED)
- alg:none 공격 변형 미시도: None, NONE, nOnE
- 만료된 토큰 재사용 허용 여부 미확인

insecure_jwt (PASSED)
- algorithm confusion 미시도: RS256 → HS256 전환
- 서명 없는 토큰 허용 여부 미확인

auth_enum (PASSED)
- 응답 시간 차이 탐지 미실시 가능
- 에러 메시지 내용 차이 탐지 미실시 가능

auth_bruteforce (PASSED)
- 낮은 반복 횟수로 테스트하여 임계치 미달 가능
- IP 로테이션 시 Rate Limit 우회 여부 미확인

auth_lockout (PASSED)
- 잠금 임계치(5~10회) 이하로 테스트하여 미탐 가능
- 잠금 후 응답 코드/메시지 변화 미확인

auth_session (PASSED)
- 로그아웃 후 토큰 재사용 테스트 미실시 가능
- 만료된 토큰으로 재요청 시 거부 여부 미확인

auth_rate_limit (PASSED)
- 인증 엔드포인트 요청 횟수가 임계치보다 적어 미탐 가능
- IP 변경 시 Rate Limit 초기화 여부 미확인

─── CRYPTOGRAPHIC FAILURES ───

sensitive_data_exposure (PASSED)
- 응답 필드 중 마스킹 없이 노출된 PII 확인 필요
- 불필요한 추가 필드 반환 여부 미확인 가능

cookie_security (PASSED)
- Secure 플래그 미설정: HTTP 전송 시 쿠키 노출 가능
- HttpOnly 미설정: JS 접근 가능
- SameSite 미설정: CSRF 가능성

─── SECURITY MISCONFIGURATION ───

security_headers (PASSED)
- CSP 헤더 미설정 또는 unsafe-inline 허용 여부 미확인
- HSTS 미설정 확인 필요

debug_endpoint (PASSED)
- /swagger, /api-docs 외 /graphql, /voyager 등 미시도
- 프레임워크별 디버그 경로 미시도

default_config (PASSED)
- 기본 자격증명(admin/admin, admin/password) 시도 누락 가능
- 노출된 관리자 인터페이스에서 인증 없이 접근 가능 여부 미확인

directory_listing (PASSED)
- 경로 끝에 / 추가 시 디렉토리 목록 노출 여부 미확인
- 정적 파일 경로에서 상위 디렉토리 탐색 미시도

error_info_exposure (PASSED)
- X-Powered-By, Server 헤더 외 응답 본문 내 프레임워크 정보 미확인
- DB 오류 메시지 직접 노출 여부 미확인

sensitive_path (PASSED)
- .env, .git/config, backup.sql 등 민감 파일 접근 미시도
- 소스코드 노출 경로(.php~, .bak) 미시도

─── EXCEPTION HANDLING ───

stack_trace_exposure (PASSED)
- 500 응답에서 스택 트레이스 본문 포함 여부 미확인
- 오류 메시지에 내부 경로, 라이브러리 버전 노출 여부 미확인

error_code_consistency (PASSED)
- 존재하지 않는 리소스 vs 권한 없는 리소스 응답 코드 차이 미확인
- 404 대신 403 반환 시 리소스 존재 여부 유추 가능성

malformed_input (PASSED)
- 타입 불일치(문자열 → 숫자 필드) 미시도
- 음수, 최대값 초과, null 입력 미시도

retry_handling (PASSED)
- 동일 요청 반복 시 중복 처리 여부 미확인
- 멱등성 없는 엔드포인트에서 중복 실행 방지 누락 가능

timeout_handling (PASSED)
- 응답 시간 초과 시 적절한 타임아웃 처리 여부 미확인
- 슬로우 POST 공격 가능성 미확인

─── INSECURE DESIGN ───

business_logic_check (PASSED)
- 비즈니스 규칙 우회 시도 누락 가능 (음수 금액, 무료 쿠폰 중복 사용)
- 단계 건너뛰기(step skipping) 시도 미실시 가능

rate_limit_check (PASSED)
- 일반 엔드포인트 요청 횟수가 임계치보다 적어 미탐 가능
- 분산 요청 시 Rate Limit 우회 여부 미확인

resource_exhaustion (PASSED)
- 대용량 파일 업로드 또는 무한 루프 유발 입력 미시도
- 동시 다중 요청으로 서버 과부하 유발 가능성 미확인

놓친 것이 없으면 missed_findings를 빈 배열로 반환하세요."""

_REVIEWER_TOOL_SCHEMA: list[dict[str, Any]] = [
    {
        "name": "review_results",
        "description": "Review vulnerability scan results and report missed findings.",
        "input_schema": {
            "type": "object",
            "properties": {
                "missed_findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "tool_id": {"type": "string"},
                            "reason": {"type": "string"},
                            "recommendation": {"type": "string"},
                        },
                        "required": ["tool_id", "reason", "recommendation"],
                    },
                    "description": "List of missed or incomplete vulnerability findings.",
                }
            },
            "required": ["missed_findings"],
        },
    }
]


@dataclass
class MissedFinding:
    tool_id: str
    reason: str
    recommendation: str


@dataclass
class ReviewResult:
    missed_findings: list[MissedFinding]


def _build_review_message(endpoint_report: dict, profile: EndpointProfile) -> str:
    return (
        f"Endpoint: {profile.method} {profile.base_url}{profile.path}\n"
        f"Auth required: {profile.auth_required}\n"
        f"Side effect: {profile.side_effect}\n"
        f"Returns sensitive data: {profile.returns_sensitive_data}\n\n"
        f"Scan results:\n{endpoint_report}\n\n"
        "Please review these results and report any missed findings."
    )


def _call_openai(endpoint_report: dict, profile: EndpointProfile) -> ReviewResult:
    """실제 OpenAI API 호출 지점. mock → 실제 전환 시 이 함수만 수정."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        tools=[
            {
                "type": "function",
                "function": {
                    "name": _REVIEWER_TOOL_SCHEMA[0]["name"],
                    "description": _REVIEWER_TOOL_SCHEMA[0]["description"],
                    "parameters": _REVIEWER_TOOL_SCHEMA[0]["input_schema"],
                },
            }
        ],
        tool_choice={"type": "function", "function": {"name": "review_results"}},
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _build_review_message(endpoint_report, profile)},
        ],
    )
    tool_calls = response.choices[0].message.tool_calls or []
    for tc in tool_calls:
        if tc.function.name == "review_results":
            import json
            data = json.loads(tc.function.arguments)
            findings = [
                MissedFinding(
                    tool_id=f["tool_id"],
                    reason=f["reason"],
                    recommendation=f["recommendation"],
                )
                for f in data.get("missed_findings", [])
            ]
            return ReviewResult(missed_findings=findings)
    return ReviewResult(missed_findings=[])


def review(
    endpoint_report: dict,
    profile: EndpointProfile,
    valid_tool_ids: set[str],
) -> ReviewResult:
    """
    스캔 결과를 Claude AI에게 검토 요청한다.

    Args:
        endpoint_report: ScenarioRunner가 생성한 스캔 결과.
        profile: 분석 대상 엔드포인트.
        valid_tool_ids: discover_tools()로 수집한 등록된 tool_id 집합.

    Returns:
        ReviewResult. 실패 시 빈 ReviewResult 반환.
    """
    try:
        result = _call_openai(endpoint_report, profile)
        # 실제 등록된 tool_id만 통과
        result.missed_findings = [
            f for f in result.missed_findings
            if f.tool_id in valid_tool_ids
        ]
        return result
    except Exception:
        logger.exception("AI reviewer failed; returning empty ReviewResult")
        return ReviewResult(missed_findings=[])
