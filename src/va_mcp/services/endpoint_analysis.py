from __future__ import annotations

from dataclasses import asdict
from typing import Any

from va_mcp.endpoint_profile import EndpointProfileValidationError, parse_endpoint_profile
from va_mcp.feature_extractor import FeatureExtractor, FeatureSet
from va_mcp.planner.planner import ScenarioPlanner

_extractor = FeatureExtractor()
_planner = ScenarioPlanner()


def analyze_endpoint(raw_input: dict[str, Any]) -> dict[str, Any]:
    """
    EndpointProfile 파싱 → FeatureExtractor → ScenarioPlanner 순으로 실행한다.

    need_more_context=True이면 missing 키와 함께 반환한다.
    성공 시 프로필, FeatureSet, PlannerOutput을 반환한다.
    실패 시 code/field/message 규격의 errors 배열을 반환한다.
    """
    try:
        profile = parse_endpoint_profile(raw_input)
        feature_set: FeatureSet = _extractor.extract(profile)
        planner_output = _planner.plan(feature_set, profile)

        if planner_output.need_more_context:
            return {
                "status": "need_more_context",
                "missing": planner_output.missing,
                "endpoint_profile": profile.to_serializable_dict(),
                "feature_set": asdict(feature_set),
            }

        return {
            "status": "analyzed",
            "endpoint_profile": profile.to_serializable_dict(),
            "feature_set": asdict(feature_set),
            "owasp_candidates": planner_output.owasp_candidates,
            "tool_ids": planner_output.tool_ids,
        }
    except EndpointProfileValidationError as e:
        return {
            "status": "invalid_input",
            "errors": [
                {"code": issue.code, "field": issue.field, "message": issue.message}
                for issue in e.issues
            ],
        }
