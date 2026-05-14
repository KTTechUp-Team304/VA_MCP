from __future__ import annotations

from copy import deepcopy

import pytest

from va_mcp.endpoint_profile import EndpointProfile, SideEffect, parse_endpoint_profile
from va_mcp.endpoint_profile.endpoint_profile_validator import EndpointProfileValidationError


def test_minimal_input_success():
    p = parse_endpoint_profile(
        {
            "base_url": "https://api.example.com/",
            "method": "get",
            "path": "users/1",
        }
    )
    assert p.base_url == "https://api.example.com"
    assert p.method == "GET"
    assert p.path == "/users/1"
    assert p.headers == {}
    assert p.query == {}
    assert p.params == {}
    assert p.body is None
    assert p.auth_contexts == []
    assert p.side_effect == SideEffect.READ.value
    assert p.resource_context is None


def test_full_input_success():
    p = parse_endpoint_profile(
        {
            "base_url": "https://api.example.com",
            "method": "POST",
            "path": "/orders",
            "headers": {"X-Test": "1"},
            "query": {"a": "1"},
            "params": {"id": "x"},
            "body": {"k": "v"},
            "auth_required": True,
            "auth_contexts": [{"role": "u"}],
            "description": "desc",
            "normal_request_example": {"m": 1},
            "normal_response_example": {"ok": True},
            "resource_context": {
                "resource_type": "order",
                "resource_id_key": "orderId",
                "owner_id_key": "ownerId",
                "tenant_id_key": "tenantId",
                "hierarchy_keys": ["orgId"],
            },
            "side_effect": "create",
            "returns_sensitive_data": True,
        }
    )
    assert p.auth_required is True
    assert p.body == {"k": "v"}
    assert p.resource_context is not None
    assert p.resource_context["resource_type"] == "order"
    assert p.resource_context["hierarchy_keys"] == ["orgId"]
    assert p.returns_sensitive_data is True
    assert p.side_effect == "create"


def test_camel_case_aliases():
    raw = {
        "baseUrl": "https://x.com/",
        "method": "GET",
        "path": "/p",
        "authRequired": True,
        "authContexts": [],
        "resourceContext": {
            "resourceType": "user",
            "resourceIdKey": "userId",
        },
    }
    p = parse_endpoint_profile(raw)
    assert p.base_url == "https://x.com"
    assert p.auth_required is True
    assert p.resource_context == {
        "resource_type": "user",
        "resource_id_key": "userId",
        "owner_id_key": None,
        "tenant_id_key": None,
        "hierarchy_keys": [],
    }


def test_json_string_input():
    p = parse_endpoint_profile(
        '{"baseUrl":"https://a.com","method":"get","path":"/z"}'
    )
    assert p.method == "GET"
    assert p.base_url == "https://a.com"


def test_invalid_side_effect_fails():
    with pytest.raises(EndpointProfileValidationError) as ei:
        parse_endpoint_profile(
            {
                "base_url": "https://a.com",
                "method": "GET",
                "path": "/p",
                "side_effect": "oops",
            }
        )
    assert any(i.code == "INVALID_SIDE_EFFECT" for i in ei.value.issues)


def test_credential_fields_preserved():
    p = parse_endpoint_profile(
        {
            "base_url": "https://api.example.com",
            "method": "POST",
            "path": "/login",
            "credential_fields": {"username": "email", "password": "passwd"},
        }
    )
    assert p.credential_fields == {"username": "email", "password": "passwd"}


def test_credential_fields_camel_case_alias():
    p = parse_endpoint_profile(
        {
            "baseUrl": "https://api.example.com",
            "method": "POST",
            "path": "/login",
            "credentialFields": {"username": "userId", "password": "secret"},
        }
    )
    assert p.credential_fields == {"username": "userId", "password": "secret"}


def test_credential_fields_invalid_type_fails():
    with pytest.raises(EndpointProfileValidationError) as ei:
        parse_endpoint_profile(
            {
                "base_url": "https://a.com",
                "method": "GET",
                "path": "/p",
                "credential_fields": ["username"],
            }
        )
    assert any(i.field == "credential_fields" for i in ei.value.issues)


def test_auth_contexts_not_shared_between_profiles():
    a = parse_endpoint_profile(
        {"base_url": "https://a.com", "method": "GET", "path": "/x"}
    )
    b = parse_endpoint_profile(
        {"base_url": "https://a.com", "method": "GET", "path": "/y"}
    )
    assert a.auth_contexts is not b.auth_contexts
    a.auth_contexts.append(1)
    assert b.auth_contexts == []


def test_serialization_keys_fixed():
    p = parse_endpoint_profile(
        {"base_url": "https://a.com", "method": "GET", "path": "/p"}
    )
    d = p.to_serializable_dict()
    assert set(d.keys()) == {
        "base_url",
        "method",
        "path",
        "headers",
        "query",
        "params",
        "body",
        "auth_required",
        "auth_contexts",
        "description",
        "normal_request_example",
        "normal_response_example",
        "resource_context",
        "side_effect",
        "returns_sensitive_data",
        "credential_fields",
    }
    clone = deepcopy(d)
    parsed = parse_endpoint_profile(clone)
    assert parsed.base_url == p.base_url


def test_lenient_resource_context_demotes_to_none():
    p = parse_endpoint_profile(
        {
            "base_url": "https://a.com",
            "method": "GET",
            "path": "/p",
            "resource_context": {},
        },
        strict_resource_context=False,
    )
    assert p.resource_context is None


def test_strict_resource_context_invalid_fails():
    with pytest.raises(EndpointProfileValidationError):
        parse_endpoint_profile(
            {
                "base_url": "https://a.com",
                "method": "GET",
                "path": "/p",
                "resource_context": {},
            },
            strict_resource_context=True,
        )
