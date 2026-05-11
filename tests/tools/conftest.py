# tests/conftest.py

import pytest
from va_mcp.core.schemas import AuthContext
from va_mcp.core.resolvers.auth_resolver import (
    parse_credentials as _orig_parse,
    resolve_auth_headers as _orig_resolve,
)

@pytest.fixture(autouse=True)
def mock_auth_resolvers(monkeypatch):
    """
    모든 테스트에 아래 fake resolver를 자동 적용합니다.
    - basic: token="user:pass" → {"username":"user","password":"pass"}
    - bearer: token="XYZ"      → {"Authorization":"Bearer XYZ"}
    - cookie: cookie="SID=123" → {"Cookie":"SID=123"}
    - api_key: token="KEY"     → {"X-API-Key":"KEY"}
    """
    def fake_parse(ctx: AuthContext) -> dict[str, str]:
        t = getattr(ctx, "token", "") or ""
        if getattr(ctx, "auth_type", "").lower() == "basic" and ":" in t:
            user, pwd = t.split(":", 1)
            return {"username": user, "password": pwd}
        # 나머진 그대로 토큰만 리턴
        return {"token": t}

    def fake_resolve(ctx: AuthContext) -> dict[str, str]:
        a = getattr(ctx, "auth_type", "").lower()
        if a == "bearer" and getattr(ctx, "token", None):
            return {"Authorization": f"Bearer {ctx.token}"}
        if a == "cookie" and getattr(ctx, "cookie", None):
            return {"Cookie": ctx.cookie}
        if a == "api_key" and getattr(ctx, "token", None):
            return {"X-API-Key": ctx.token}
        return {}

    monkeypatch.setattr(
        "va_mcp.core.resolvers.auth_resolver.parse_credentials",
        fake_parse,
    )
    monkeypatch.setattr(
        "va_mcp.core.resolvers.auth_resolver.resolve_auth_headers",
        fake_resolve,
    )

    yield