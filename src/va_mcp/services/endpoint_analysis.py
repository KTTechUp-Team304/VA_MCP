from __future__ import annotations

from typing import Any

from va_mcp.endpoint_profile import EndpointProfileValidationError, parse_endpoint_profile


def analyze_endpoint(raw_input: dict[str, Any]) -> dict[str, Any]:
    """
    raw 입력을 EndpointProfile로 파싱한다.

    성공 시 직렬화된 프로필과 다음 단계 안내를 반환하고,
    실패 시 code/field/message 규격의 errors 배열을 반환한다.
    """
    try:
        profile = parse_endpoint_profile(raw_input)
        return {
            "status": "parsed",
            "endpoint_profile": profile.to_serializable_dict(),
            "next_stage": "FeatureExtractor not implemented yet",
        }
    except EndpointProfileValidationError as e:
        return {
            "status": "invalid_input",
            "errors": [
                {"code": issue.code, "field": issue.field, "message": issue.message}
                for issue in e.issues
            ],
        }
