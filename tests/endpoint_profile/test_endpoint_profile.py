from __future__ import annotations

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile


def test_endpoint_profile_defaults_are_isolated():
    p = EndpointProfile(base_url="https://a.com", method="GET", path="/")
    q = EndpointProfile(base_url="https://a.com", method="GET", path="/")
    p.headers["k"] = "1"
    assert q.headers == {}
    p.credential_fields["username"] = "email"
    assert q.credential_fields == {}
