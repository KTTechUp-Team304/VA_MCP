from __future__ import annotations

# OWASP Top 10 2025 기준

from typing import Any

from va_mcp.core.planner_output import PlannerOutput
from va_mcp.planner.baseline import A02_BASELINE_TOOL_IDS, A10_BASELINE_TOOL_IDS
from va_mcp.planner.rules import OWASP_TOOL_MAP


def _get(obj: Any, attr: str, default: Any = False) -> Any:
    """FeatureSet이 dict이든 dataclass든 동일하게 속성을 읽는다."""
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


def _dedup(ids: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for tid in ids:
        if tid not in seen:
            seen.add(tid)
            result.append(tid)
    return result


class ScenarioPlanner:
    """
    FeatureSet을 분석해 OWASP 시나리오 후보를 선정하고 PlannerOutput을 반환한다.

    판단 규칙 (OWASP Top 10 2025 기준):
      A01: requires_auth + (has_resource_identifier or auth_contexts >= 2)
      A02: baseline 항상 수행 (Security Misconfiguration)
      A03: has_dependency_exposure (Software Supply Chain Failures)
      A04: has_secret_handling (Cryptographic Failures)
      A05: has_user_input + (has_free_text_input or has_file_or_config_surface)
      A06: is_state_changing + has_state_field (Insecure Design)
      A07: is_login_endpoint or has_credential_fields or requires_auth
      A08: has_file_or_config_surface (Software or Data Integrity Failures)
      A09: has_logging_feature (Security Logging and Alerting Failures)
      A10: baseline 항상 수행 (Mishandling of Exceptional Conditions)

    주의:
      - 이 클래스는 "실행 후보 선정"만 담당한다. 취약점을 확정하지 않는다.
      - need_more_context=True일 때 A01은 candidates에서 제외된다.
      - A02/A10 tool_ids는 조건 무관하게 항상 포함된다.
    """

    def plan(self, feature_set: Any, endpoint: Any = None) -> PlannerOutput:
        candidates: list[str] = []
        missing: list[str] = []
        tool_ids: list[str] = []

        # A02 — Security Misconfiguration, baseline 항상
        candidates.append("A02")
        tool_ids.extend(A02_BASELINE_TOOL_IDS)

        # A01: Broken Access Control
        # requires_auth + (has_resource_identifier or auth_contexts >= 2)
        if _get(feature_set, "requires_auth"):
            has_resource = _get(feature_set, "has_resource_identifier")
            auth_count = _get(feature_set, "auth_contexts", 0)
            resource_ctx = _get(feature_set, "resource_context")

            if has_resource or auth_count >= 2:
                candidates.append("A01")
                tool_ids.extend(OWASP_TOOL_MAP["A01"])
            else:
                # 조건 충족 불가 → need_more_context
                if auth_count < 2:
                    missing.append("auth_contexts")
                if not resource_ctx:
                    missing.append("resource_context")

        # A03: Software Supply Chain Failures
        if _get(feature_set, "has_dependency_exposure"):
            candidates.append("A03")
            tool_ids.extend(OWASP_TOOL_MAP["A03"])

        # A04: Cryptographic Failures
        if _get(feature_set, "has_secret_handling"):
            candidates.append("A04")
            tool_ids.extend(OWASP_TOOL_MAP["A04"])

        # A05: Injection
        # has_user_input 단독으로 선정하지 않음 (과탐 방지)
        if _get(feature_set, "has_user_input") and (
            _get(feature_set, "has_free_text_input")
            or _get(feature_set, "has_file_or_config_surface")
        ):
            candidates.append("A05")
            tool_ids.extend(OWASP_TOOL_MAP["A05"])

        # A06: Insecure Design
        if _get(feature_set, "is_state_changing") and _get(feature_set, "has_state_field"):
            candidates.append("A06")
            tool_ids.extend(OWASP_TOOL_MAP["A06"])

        # A07: Authentication Failures
        if (
            _get(feature_set, "is_login_endpoint")
            or _get(feature_set, "has_credential_fields")
            or _get(feature_set, "requires_auth")
        ):
            candidates.append("A07")
            tool_ids.extend(OWASP_TOOL_MAP["A07"])

        # A08: Software or Data Integrity Failures
        if _get(feature_set, "has_file_or_config_surface"):
            candidates.append("A08")
            tool_ids.extend(OWASP_TOOL_MAP["A08"])

        # A09: Security Logging and Alerting Failures
        if _get(feature_set, "has_logging_feature"):
            candidates.append("A09")
            tool_ids.extend(OWASP_TOOL_MAP["A09"])

        # A10 — Mishandling of Exceptional Conditions, baseline 항상
        candidates.append("A10")
        tool_ids.extend(A10_BASELINE_TOOL_IDS)

        return PlannerOutput(
            owasp_candidates=candidates,
            tool_ids=_dedup(tool_ids),
            need_more_context=bool(missing),
            missing=missing,
        )
