from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from va_mcp.core.constants import MAX_BODY_SAMPLE_CHARS, MAX_REQUEST_BODY_CHARS
from va_mcp.core.schemas import ToolError


# Evidence 기록 시 값을 마스킹할 민감 키 목록 (소문자 기준으로 비교)
# 이 키에 해당하는 값은 "***"으로 대체된다.
SENSITIVE_KEYS = {"authorization", "cookie", "token", "password", "api_key"}


def utc_now_iso() -> str:
    """
    현재 UTC 시각을 ISO-8601 형식 문자열로 반환한다.

    ToolResult.started_at / ended_at 기록 시 반드시 이 함수를 사용한다.
    직접 datetime.now()를 호출하면 타임존 정보가 빠질 수 있으므로 사용 금지.

    반환 예시:
        "2026-04-24T09:10:11.123456Z"
    """
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def truncate_text(text: str, max_chars: int) -> str:
    """
    텍스트를 최대 길이로 자르고 잘렸음을 표시한다.

    직접 호출하는 대신 sanitize_response_sample() / sanitize_request_body()를 사용한다.

    Args:
        text:      원본 문자열
        max_chars: 최대 허용 문자 수

    반환 예시:
        "abcde...(truncated)"  ← max_chars=5이고 text가 더 길 경우
    """
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}...(truncated)"


def sanitize_response_sample(body: str) -> str:
    """
    응답 바디를 Evidence에 기록하기 전에 길이 제한을 적용한다.

    MAX_BODY_SAMPLE_CHARS(2000자)를 초과하면 잘린다.
    Evidence.response_body_sample에 저장하기 전에 반드시 이 함수를 통과시킨다.

    사용 예시:
        Evidence(
            response_body_sample=sanitize_response_sample(response.text),
            ...
        )
    """
    return truncate_text(body, MAX_BODY_SAMPLE_CHARS)


def sanitize_request_body(body: Any) -> str:
    """
    요청 바디를 Evidence에 기록하기 전에 문자열로 변환하고 길이 제한을 적용한다.

    MAX_REQUEST_BODY_CHARS(2000자)를 초과하면 잘린다.
    dict, list 등 어떤 타입이든 str()로 변환 후 처리한다.

    사용 예시:
        Evidence(
            request={
                "body": sanitize_request_body(request_payload),
                ...
            }
        )
    """
    rendered = str(body) if body is not None else ""
    return truncate_text(rendered, MAX_REQUEST_BODY_CHARS)


def mask_sensitive(data: dict[str, Any]) -> dict[str, Any]:
    """
    딕셔너리에서 민감한 키의 값을 "***"으로 마스킹한다.

    Evidence.request.headers처럼 인증 정보가 포함된 딕셔너리를 기록하기 전에
    반드시 이 함수를 통과시킨다.

    마스킹 대상 키 (대소문자 무관):
        authorization, cookie, token, password, api_key

    중첩 딕셔너리도 재귀적으로 처리한다.

    사용 예시:
        Evidence(
            request={
                "headers": mask_sensitive({"Authorization": "Bearer TOKEN"}),
            }
        )
        # 결과: {"Authorization": "***"}
    """
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in SENSITIVE_KEYS:
            sanitized[key] = "***"
        elif isinstance(value, dict):
            sanitized[key] = mask_sensitive(value)
        else:
            sanitized[key] = value
    return sanitized


def build_tool_error(
    error_code: str,
    error_message: str,
    retryable: bool = False,
) -> ToolError:
    """
    표준 ToolError 객체를 생성한다.

    tool의 except 블록에서 ToolError를 직접 생성하는 대신 이 함수를 사용한다.
    error_code는 반드시 ErrorCode enum 값을 사용한다.

    Args:
        error_code:    오류 유형 코드 (ErrorCode enum 값, 예: ErrorCode.TIMEOUT)
        error_message: 사람이 읽을 수 있는 오류 설명
        retryable:     True면 재시도 시 성공 가능성이 있음을 의미

    사용 예시:
        except TimeoutError:
            return ToolResult(
                ...
                status=ToolStatus.ERROR,
                errors=[build_tool_error(ErrorCode.TIMEOUT, "5초 안에 응답이 오지 않았습니다.", retryable=True)],
            )
    """
    return ToolError(
        error_code=error_code,
        error_message=error_message,
        retryable=retryable,
    )
