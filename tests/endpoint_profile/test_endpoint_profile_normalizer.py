from __future__ import annotations

import pytest

from va_mcp.endpoint_profile.endpoint_profile_normalizer import (
    normalize_base_url,
    normalize_method,
    normalize_path,
    normalize_resource_context,
)


@pytest.mark.parametrize(
    ("inp", "out"),
    [("get", "GET"), ("Get", "GET"), ("  post  ", "POST")],
)
def test_normalize_method(inp, out):
    assert normalize_method(inp) == out


@pytest.mark.parametrize(
    ("inp", "out"),
    [("users/1", "/users/1"), ("/u", "/u")],
)
def test_normalize_path(inp, out):
    assert normalize_path(inp) == out


@pytest.mark.parametrize(
    ("inp", "out"),
    [
        ("https://x.com/", "https://x.com"),
        ("https://x.com///", "https://x.com"),
    ],
)
def test_normalize_base_url(inp, out):
    assert normalize_base_url(inp) == out


def test_normalize_resource_context_minimal():
    ctx, warns = normalize_resource_context(
        {"resource_type": "u", "resource_id_key": "id"}, strict=True
    )
    assert warns == []
    assert ctx == {
        "resource_type": "u",
        "resource_id_key": "id",
        "owner_id_key": None,
        "tenant_id_key": None,
        "hierarchy_keys": [],
        "access_type": None,
    }


def test_normalize_resource_context_strict_invalid():
    with pytest.raises(ValueError):
        normalize_resource_context({}, strict=True)


def test_normalize_resource_context_access_type_preserved():
    """O-6: access_type 필드가 정규화 후에도 보존되어야 한다."""
    ctx, warns = normalize_resource_context(
        {
            "resource_type": "file",
            "resource_id_key": "fileId",
            "access_type": "private",
        },
        strict=True,
    )
    assert warns == []
    assert ctx["access_type"] == "private"


def test_normalize_resource_context_access_type_camel():
    """O-6: accessType(camelCase) 입력도 access_type으로 정규화된다."""
    ctx, warns = normalize_resource_context(
        {
            "resource_type": "enrollment",
            "resource_id_key": "enrollmentId",
            "accessType": "private",
        },
        strict=False,
    )
    assert ctx["access_type"] == "private"
    assert warns == []
