from __future__ import annotations

from enum import Enum


class ToolStatus(str, Enum):
    """
    tool 실행 결과 상태값.

    모든 tool의 ToolResult.status는 반드시 이 enum 값만 사용한다.
    문자열 하드코딩 금지.

    사용 예시:
        status=ToolStatus.VULNERABLE

    주의사항:
        - ERROR 시 severity=Severity.INFO, confidence=Confidence.LOW 고정
        - SKIPPED 시 evidence=[] 고정
    """

    PASSED = "passed"          # 취약점 미발견, 정상 실행 완료
    VULNERABLE = "vulnerable"  # 취약점 발견, 정상 실행 완료
    SKIPPED = "skipped"        # 입력 부족 / 조건 미충족으로 실행하지 않음
    ERROR = "error"            # 실행 중 예외 또는 내부 오류 발생


class Severity(str, Enum):
    """
    취약점 위험도.

    ToolResult.severity에 사용한다.
    OWASP / CVSS 기준을 참고하여 팀 내 기준으로 통일한다.

    사용 예시:
        severity=Severity.HIGH

    주의사항:
        - status=ERROR 인 경우 반드시 Severity.INFO로 고정한다.
    """

    INFO = "info"          # 정보성 (취약점 아님, 참고용)
    LOW = "low"            # 낮음 (악용 가능성 낮음)
    MEDIUM = "medium"      # 중간 (조건부 악용 가능)
    HIGH = "high"          # 높음 (직접 악용 가능)
    CRITICAL = "critical"  # 매우 높음 (즉각적인 피해 가능)


class Confidence(str, Enum):
    """
    탐지 결과의 신뢰도.

    ToolResult.confidence에 사용한다.
    재현 가능한 증거가 있을수록 높은 값을 사용한다.

    사용 예시:
        confidence=Confidence.HIGH

    주의사항:
        - status=ERROR 인 경우 반드시 Confidence.LOW로 고정한다.
    """

    LOW = "low"        # 추정 수준 (패턴 매칭, 간접 증거)
    MEDIUM = "medium"  # 어느 정도 근거 있음 (응답 분석 기반)
    HIGH = "high"      # 명확한 재현 증거 있음 (실제 응답으로 확인됨)


class ErrorCode(str, Enum):
    """
    tool 실행 중 발생한 오류 유형 코드.

    ToolError.error_code에 사용한다.
    build_tool_error() 유틸과 함께 사용한다.

    사용 예시:
        build_tool_error(ErrorCode.TIMEOUT, "요청이 5초 안에 완료되지 않았습니다.")
    """

    TIMEOUT = "TIMEOUT"                # HTTP 요청 시간 초과
    INVALID_INPUT = "INVALID_INPUT"    # 필수 입력값 누락 또는 형식 오류
    HTTP_FAILURE = "HTTP_FAILURE"      # HTTP 요청 자체 실패 (연결 오류 등)
    INTERNAL_ERROR = "INTERNAL_ERROR"  # 위 분류에 해당하지 않는 내부 예외


# Evidence 본문 샘플 최대 저장 길이 (응답 body)
# sanitize_response_sample() 함수가 이 값을 기준으로 자른다.
MAX_BODY_SAMPLE_CHARS = 2000

# Evidence 요청 body 최대 저장 길이
# sanitize_request_body() 함수가 이 값을 기준으로 자른다.
MAX_REQUEST_BODY_CHARS = 2000
