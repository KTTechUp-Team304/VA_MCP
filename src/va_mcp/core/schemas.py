from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from va_mcp.core.constants import Confidence, Severity, ToolStatus


@dataclass
class TargetInfo:
    """
    스캔 대상 서버 정보.

    ToolInput.target에 사용한다.

    사용 예시:
        TargetInfo(base_url="https://api.example.com")
        TargetInfo(base_url="https://api.example.com", openapi_url="https://api.example.com/swagger.json")
    """

    base_url: str                  # 스캔 대상 서버의 기본 URL (trailing slash 없이)
    openapi_url: str | None = None  # OpenAPI / Swagger JSON URL (있을 경우 엔드포인트 자동 탐지에 활용)


@dataclass
class ApiRequest:
    """
    테스트할 단일 API 요청 정보.

    ToolInput.request에 사용한다.
    tool이 실제로 보낼 HTTP 요청의 기본 틀이 된다.

    사용 예시:
        ApiRequest(
            method="GET",
            path="/api/users/1",
            headers={"Accept": "application/json"},
            params={"userId": "1"},
        )
    """

    method: str                              # HTTP 메서드 (GET, POST, PUT, DELETE 등)
    path: str                                # 요청 경로 (예: /api/users/1)
    headers: dict[str, str] = field(default_factory=dict)   # HTTP 요청 헤더
    query: dict[str, Any] = field(default_factory=dict)     # URL 쿼리 파라미터 (?key=value)
    params: dict[str, Any] = field(default_factory=dict)    # 경로 파라미터 ({userId} 등)
    body: dict[str, Any] | None = None                      # 요청 바디 (POST/PUT 등)


@dataclass
class AuthContext:
    """
    단일 인증 컨텍스트.

    ToolInput.auth 리스트의 원소로 사용한다.
    IDOR/BFLA 같이 여러 역할의 요청을 비교해야 하는 tool에서 복수 개를 전달한다.

    사용 예시:
        AuthContext(role="user_a", auth_type="bearer", token="TOKEN_A")
        AuthContext(role="admin",  auth_type="bearer", token="ADMIN_TOKEN")
    """

    role: str                    # 이 인증 컨텍스트의 역할 이름 (예: "user_a", "admin")
    auth_type: str               # 인증 방식 (예: "bearer", "cookie", "api_key", "none")
    token: str | None = None     # Bearer 토큰 또는 API 키 값
    cookie: str | None = None    # 쿠키 기반 인증 시 쿠키 문자열


@dataclass
class ToolOptions:
    """
    tool 실행 옵션.

    ToolInput.options에 사용한다.
    공통 옵션은 필드로 고정하고, tool별 추가 옵션은 extra에 넣는다.

    사용 예시:
        ToolOptions(timeout=3000, safe_mode=True)
        ToolOptions(extra={"payload_list": ["admin", "password"], "repeat_count": 10})
    """

    timeout: int = 5000      # HTTP 요청 타임아웃 (밀리초)
    safe_mode: bool = True   # True면 실제 변조/파괴 요청을 보내지 않음 (읽기 전용 테스트)
    max_requests: int = 20   # tool 1회 실행당 최대 HTTP 요청 횟수

    extra: dict[str, Any] = field(default_factory=dict)
    """
    tool별 추가 옵션을 자유롭게 담는 확장 필드.

    core/schemas.py를 수정하지 않고 각 tool에서 독립적으로 사용한다.
    키 이름은 각 tool 파일 상단 주석에 반드시 명시한다.
    기본값은 .get("key", 기본값) 형태로 항상 지정한다.

    자주 쓰이는 키 예시:
        extra["payload_list"]   = ["admin", "password", "123456"]
        extra["repeat_count"]   = 10       # 반복 요청 횟수
        extra["interval_ms"]    = 500      # 요청 간 대기 시간 (밀리초)
        extra["wordlist_path"]  = "/path"  # 외부 wordlist 파일 경로
    """


@dataclass
class ToolInput:
    """
    tool 실행에 필요한 전체 입력 구조.

    모든 tool의 run() 메서드가 이 타입을 인자로 받는다.
    discovery 단계가 완성되기 전까지는 테스트 코드에서 직접 생성해서 사용한다.

    사용 예시:
        ToolInput(
            target=TargetInfo(base_url="https://api.example.com"),
            request=ApiRequest(method="GET", path="/api/users/1"),
            auth=[AuthContext(role="user", auth_type="bearer", token="TOKEN")],
            options=ToolOptions(extra={"repeat_count": 5}),
        )
    """

    target: TargetInfo                                           # 스캔 대상 서버 정보
    request: ApiRequest | None = None                           # 테스트할 API 요청 정보
    auth: list[AuthContext] = field(default_factory=list)       # 인증 컨텍스트 목록 (복수 역할 지원)
    options: ToolOptions = field(default_factory=ToolOptions)   # 실행 옵션


@dataclass
class Evidence:
    """
    취약점 발견 시 첨부하는 증거 데이터.

    ToolResult.evidence 리스트의 원소로 사용한다.
    재현 가능한 요청/응답 정보를 담아 리포트에서 증거로 활용된다.

    주의사항:
        - request의 headers는 반드시 mask_sensitive()를 통과시킨다.
        - response_body_sample은 sanitize_response_sample()로 2000자 제한을 적용한다.
        - request body는 sanitize_request_body()로 2000자 제한을 적용한다.

    사용 예시:
        Evidence(
            request={
                "method": "GET",
                "path": "/api/users/2",
                "headers": mask_sensitive({"Authorization": "Bearer TOKEN_A"}),
            },
            response_status=200,
            response_body_sample=sanitize_response_sample(response_body),
            note="user_a 권한으로 user_b 데이터가 조회됨",
        )
    """

    request: dict[str, Any]                                       # 전송한 HTTP 요청 정보 (method, path, headers, body)
    response_status: int                                          # 응답 HTTP 상태 코드
    response_headers: dict[str, str] = field(default_factory=dict)  # 응답 헤더
    response_body_sample: str = ""                                # 응답 바디 샘플 (최대 2000자)
    note: str = ""                                                # 이 증거에 대한 설명


@dataclass
class ToolError:
    """
    tool 실행 중 발생한 오류 정보.

    ToolResult.errors 리스트의 원소로 사용한다.
    직접 생성하는 대신 build_tool_error() 유틸을 사용한다.

    사용 예시:
        build_tool_error(ErrorCode.TIMEOUT, "요청이 5초 안에 완료되지 않았습니다.", retryable=True)
    """

    error_code: str          # 오류 유형 코드 (ErrorCode enum 값 사용)
    error_message: str       # 사람이 읽을 수 있는 오류 설명
    retryable: bool = False  # True면 재시도 시 성공 가능성이 있음을 의미


@dataclass
class ToolResult:
    """
    tool 실행 결과 전체 구조.

    모든 tool의 run() 메서드가 이 타입을 반환한다.
    scenario는 이 결과들을 모아 최종 리포트를 생성한다.

    필수 규칙:
        - status, severity, confidence는 반드시 각 enum의 .value 또는 enum 자체를 사용한다.
        - status=ERROR 이면 severity=INFO, confidence=LOW 고정
        - status=SKIPPED 이면 evidence=[] 고정
        - started_at, ended_at은 utc_now_iso()로 기록한다.

    사용 예시:
        ToolResult(
            tool_id="idor_bola",
            tool_name="IDOR / BOLA Testing",
            status=ToolStatus.VULNERABLE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="다른 사용자 정보 조회 가능",
            description="...",
            owasp=["A01 Broken Access Control"],
            cwe=["CWE-639"],
            evidence=[Evidence(...)],
            recommendation="...",
            started_at=started_at,
            ended_at=ended_at,
        )
    """

    tool_id: str    # tool 식별자 (snake_case 고정, 저장/집계/필터링 키로 사용)
    tool_name: str  # tool 표시 이름 (UI/보고서용, 예: "IDOR / BOLA Testing")

    status: str = ToolStatus.PASSED.value      # 실행 결과 상태 (ToolStatus enum 사용)
    severity: str = Severity.INFO.value        # 취약점 위험도 (Severity enum 사용)
    confidence: str = Confidence.LOW.value     # 탐지 신뢰도 (Confidence enum 사용)

    title: str = ""                            # 취약점 제목 (한 줄 요약)
    description: str = ""                      # 취약점 상세 설명

    evidence: list[Evidence] = field(default_factory=list)  # 취약점 증거 목록
    owasp: list[str] = field(default_factory=list)          # 연관 OWASP 항목 (예: ["A01 Broken Access Control"])
    cwe: list[str] = field(default_factory=list)            # 연관 CWE 항목 (예: ["CWE-639"])
    recommendation: str = ""                                # 수정 권고 내용

    started_at: str = ""        # tool 실행 시작 시각 (ISO-8601 UTC, utc_now_iso() 사용)
    ended_at: str = ""          # tool 실행 종료 시각 (ISO-8601 UTC, utc_now_iso() 사용)
    duration_ms: int = 0        # 실행 소요 시간 (밀리초, 필요 시 직접 계산)
    tool_version: str = "0.1.0" # tool 버전 (기본값 유지, 변경 필요 시 각 tool에서 오버라이드)

    metadata: dict[str, str] = field(default_factory=dict)   # 디버깅/추적용 부가 정보
    errors: list[ToolError] = field(default_factory=list)     # 실행 중 발생한 오류 목록
