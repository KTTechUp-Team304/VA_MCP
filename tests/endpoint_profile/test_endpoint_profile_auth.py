from __future__ import annotations

import pytest

from va_mcp.endpoint_profile import parse_endpoint_profile
from va_mcp.endpoint_profile.endpoint_profile_validator import EndpointProfileValidationError
from va_mcp.feature_extractor import FeatureExtractor
from va_mcp.planner import ScenarioPlanner


def test_parse_v4_auth_and_required_roles():
    p = parse_endpoint_profile(
        {
            "base_url": "http://localhost:4000",
            "method": "GET",
            "path": "/api/enrollments/me",
            "auth_required": True,
            "required_roles": ["student"],
            "auth": {
                "login": {
                    "path": "/api/auth/login",
                    "method": "POST",
                    "credential_fields": {
                        "username": "username",
                        "password": "passwordHash",
                    },
                    "token_json_path": "accessToken",
                },
                "logout": {
                    "path": "/api/auth/logout",
                    "method": "POST",
                    "refresh_cookie_name": "refreshToken",
                },
                "accounts": [
                    {"username": "a", "password": "p1", "role": "student"},
                    {"username": "b", "password": "p2", "role": "student"},
                ],
            },
        }
    )
    assert p.required_roles == ["student"]
    assert p.auth is not None
    assert p.auth.login is not None
    assert p.auth.login.path == "/api/auth/login"
    assert p.auth.login.credential_fields == {
        "username": "username",
        "password": "passwordHash",
    }
    assert len(p.auth.accounts) == 2
    assert p.auth.logout is not None
    assert p.auth.logout.path == "/api/auth/logout"
    assert p.auth.logout.refresh_cookie_name == "refreshToken"
    assert p.credential_fields["password"] == "passwordHash"


def test_logout_without_login_fails():
    with pytest.raises(EndpointProfileValidationError) as exc:
        parse_endpoint_profile(
            {
                "base_url": "http://localhost:4000",
                "method": "GET",
                "path": "/api/x",
                "auth": {"logout": {"path": "/api/auth/logout"}},
            }
        )
    assert any(i.field == "auth" for i in exc.value.issues)


def test_accounts_without_login_fails():
    with pytest.raises(EndpointProfileValidationError) as exc:
        parse_endpoint_profile(
            {
                "base_url": "http://localhost:4000",
                "method": "GET",
                "path": "/api/x",
                "auth": {
                    "accounts": [{"username": "a", "password": "p", "role": "user"}],
                },
            }
        )
    assert any(i.field == "auth" for i in exc.value.issues)


def test_feature_extractor_auth_signals():
    p = parse_endpoint_profile(
        {
            "base_url": "http://localhost:4000",
            "method": "GET",
            "path": "/api/users/1",
            "auth_required": True,
            "required_roles": ["admin"],
            "auth": {
                "login": {
                    "path": "/api/auth/login",
                    "credential_fields": {"username": "email", "password": "passwd"},
                    "token_json_path": "token",
                },
                "accounts": [
                    {"username": "u1", "password": "x", "role": "admin"},
                ],
            },
        }
    )
    fs = FeatureExtractor().extract(p)
    assert fs.has_role_restriction is True
    assert fs.has_auth_accounts is True
    assert fs.auth_account_count == 1


def test_planner_uses_auth_accounts_for_idor():
    from va_mcp.endpoint_profile import EndpointProfile
    from va_mcp.endpoint_profile.auth_config import AccountCredential, AuthConfig, LoginConfig

    profile = EndpointProfile(
        base_url="http://localhost:4000",
        method="GET",
        path="/api/users/{userId}",
        auth_required=True,
        resource_context={"resource_type": "user", "resource_id_key": "userId"},
        auth=AuthConfig(
            login=LoginConfig(path="/api/auth/login"),
            accounts=[
                AccountCredential(username="a", password="p", role="u1"),
                AccountCredential(username="b", password="p", role="u2"),
            ],
        ),
    )
    fs = FeatureExtractor().extract(profile)
    out = ScenarioPlanner().plan(fs, profile)
    assert "idor_bola" in out.tool_ids
