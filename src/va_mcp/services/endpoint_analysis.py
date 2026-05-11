from __future__ import annotations

from typing import Any

from va_mcp.endpoint_profile import EndpointProfileValidationError, parse_endpoint_profile
from va_mcp.feature_extractor import FeatureExtractor, FeatureSet
from dataclasses import asdict

_extractor = FeatureExtractor()


def analyze_endpoint(raw_input: dict[str, Any]) -> dict[str, Any]:
    """
    raw 입력을 EndpointProfile로 파싱한 뒤 FeatureExtractor로 분석 신호를 추출한다.

    성공 시 직렬화된 프로필과 FeatureSet을 반환하고,
    실패 시 code/field/message 규격의 errors 배열을 반환한다.
    """
    try:
        profile = parse_endpoint_profile(raw_input)
        feature_set: FeatureSet = _extractor.extract(profile)
        return {
            "status": "analyzed",
            "endpoint_profile": profile.to_serializable_dict(),
            "feature_set": asdict(feature_set),
        }
    except EndpointProfileValidationError as e:
        return {
            "status": "invalid_input",
            "errors": [
                {"code": issue.code, "field": issue.field, "message": issue.message}
                for issue in e.issues
            ],
        }
