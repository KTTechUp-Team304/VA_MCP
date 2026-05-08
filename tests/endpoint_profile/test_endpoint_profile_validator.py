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
