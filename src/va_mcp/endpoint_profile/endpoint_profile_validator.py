from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile, SideEffect
from va_mcp.endpoint_profile.logging_utils import log_stage_io

logger = logging.getLogger(__name__)


@dataclass
class ValidationIssue:
    """규격화된 검증 오류 한 건."""

    code: str
    field: str
    message: str


class EndpointProfileValidationError(ValueError):
    """EndpointProfile 검증 실패."""

    def __init__(self, issues: list[ValidationIssue]):
        self.issues = issues
        detail = "; ".join(f"{i.field}: {i.message}" for i in issues)
        super().__init__(detail)


def _is_non_empty_str(v: Any) -> bool:
    return isinstance(v, str) and bool(v.strip())


def validate_endpoint_profile(profile: EndpointProfile) -> None:
    """
    필수값, 값 범위, 타입을 검증한다. 실패 시 EndpointProfileValidationError.
    """
    log_stage_io(
        logger,
        "validate.entry",
        input_data=profile.to_serializable_dict(),
        output_data=None,
    )
    issues: list[ValidationIssue] = []

    if not _is_non_empty_str(profile.base_url):
        issues.append(
            ValidationIssue("REQUIRED", "base_url", "base_url은 비어 있지 않은 문자열이어야 합니다")
        )
    else:
        parts = urlsplit(profile.base_url.strip())
        if parts.scheme not in ("http", "https") or not parts.netloc:
            issues.append(
                ValidationIssue(
                    "INVALID_BASE_URL",
                    "base_url",
                    "base_url은 http(s) 스킴과 호스트를 가진 URL이어야 합니다",
                )
            )

    if not _is_non_empty_str(profile.method):
        issues.append(
            ValidationIssue("REQUIRED", "method", "method는 비어 있지 않은 문자열이어야 합니다")
        )

    if not _is_non_empty_str(profile.path):
        issues.append(
            ValidationIssue("REQUIRED", "path", "path는 비어 있지 않은 문자열이어야 합니다")
        )
    elif not profile.path.startswith("/"):
        issues.append(
            ValidationIssue(
                "NORMALIZATION",
                "path",
                "정규화 후 path는 '/'로 시작해야 합니다",
            )
        )

    allowed = {e.value for e in SideEffect}
    if profile.side_effect not in allowed:
        issues.append(
            ValidationIssue(
                "INVALID_SIDE_EFFECT",
                "side_effect",
                f"side_effect는 {sorted(allowed)} 중 하나여야 합니다",
            )
        )

    if not isinstance(profile.headers, dict):
        issues.append(
            ValidationIssue("TYPE", "headers", "headers는 dict이어야 합니다")
        )
    if not isinstance(profile.query, dict):
        issues.append(ValidationIssue("TYPE", "query", "query는 dict이어야 합니다"))
    if not isinstance(profile.params, dict):
        issues.append(ValidationIssue("TYPE", "params", "params는 dict이어야 합니다"))
    if profile.body is not None and not isinstance(profile.body, dict):
        issues.append(ValidationIssue("TYPE", "body", "body는 dict | None이어야 합니다"))

    if not isinstance(profile.auth_contexts, list):
        issues.append(
            ValidationIssue("TYPE", "auth_contexts", "auth_contexts는 list이어야 합니다")
        )

    if profile.resource_context is not None:
        if not isinstance(profile.resource_context, dict):
            issues.append(
                ValidationIssue("TYPE", "resource_context", "resource_context는 dict | None이어야 합니다")
            )
        else:
            rc = profile.resource_context
            for key in ("resource_type", "resource_id_key"):
                if key not in rc or not _is_non_empty_str(rc.get(key)):
                    issues.append(
                        ValidationIssue(
                            "RESOURCE_CONTEXT",
                            "resource_context",
                            f"resource_context에 비어 있지 않은 {key}가 필요합니다",
                        )
                    )
            if "hierarchy_keys" in rc and not isinstance(rc["hierarchy_keys"], list):
                issues.append(
                    ValidationIssue(
                        "TYPE",
                        "resource_context.hierarchy_keys",
                        "hierarchy_keys는 list이어야 합니다",
                    )
                )

    for field_name in ("normal_request_example", "normal_response_example"):
        val = getattr(profile, field_name)
        if val is not None and not isinstance(val, Mapping):
            issues.append(
                ValidationIssue("TYPE", field_name, f"{field_name}는 dict | None이어야 합니다")
            )

    if issues:
        log_stage_io(
            logger,
            "validate.failed",
            input_data=None,
            output_data={
                "issues": [
                    {"code": i.code, "field": i.field, "message": i.message}
                    for i in issues
                ]
            },
        )
        raise EndpointProfileValidationError(issues)
    log_stage_io(
        logger,
        "validate.ok",
        input_data=None,
        output_data={"ok": True, "issue_count": 0},
    )
