from __future__ import annotations

import pytest

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.endpoint_profile.endpoint_profile_validator import (
    EndpointProfileValidationError,
    validate_endpoint_profile,
)


def test_validate_missing_base_url():
    p = EndpointProfile(base_url="", method="GET", path="/p")
    with pytest.raises(EndpointProfileValidationError) as ei:
        validate_endpoint_profile(p)
    assert any(i.code == "REQUIRED" and i.field == "base_url" for i in ei.value.issues)


def test_validate_invalid_base_url_scheme():
    p = EndpointProfile(base_url="ftp://x.com", method="GET", path="/p")
    with pytest.raises(EndpointProfileValidationError) as ei:
        validate_endpoint_profile(p)
    assert any(i.code == "INVALID_BASE_URL" for i in ei.value.issues)


def test_validate_ok_minimal():
    p = EndpointProfile(base_url="https://x.com", method="GET", path="/p")
    validate_endpoint_profile(p)


def test_validation_issue_has_code_field_message():
    p = EndpointProfile(base_url="", method="GET", path="/p")
    with pytest.raises(EndpointProfileValidationError) as ei:
        validate_endpoint_profile(p)
    issue = ei.value.issues[0]
    assert issue.code
    assert issue.field
    assert issue.message


def test_validate_resource_context_idor_still_requires_fields():
    """회귀 확인: IDOR 입력은 여전히 resource_type/resource_id_key를 요구한다."""
    p = EndpointProfile(
        base_url="https://x.com",
        method="GET",
        path="/p",
        resource_context={"owner_id_key": "ownerId"},
    )
    with pytest.raises(EndpointProfileValidationError) as ei:
        validate_endpoint_profile(p)
    assert any(i.code == "RESOURCE_CONTEXT" for i in ei.value.issues)


def test_validate_resource_context_a03_mode_skips_idor_fields():
    """dependencies만 있는 A03 입력은 resource_type/resource_id_key 없이도 통과한다."""
    p = EndpointProfile(
        base_url="https://x.com",
        method="GET",
        path="/",
        resource_context={"runtime": "node", "dependencies": {"lodash": "4.17.11"}},
    )
    validate_endpoint_profile(p)