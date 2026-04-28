import pytest
from va_mcp.core.schemas import (
    ToolInput,
    ApiRequest,
    TargetInfo,
    AuthContext,
    ToolOptions,
)

class DummyResponse:
    def __init__(self, status_code, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text

@pytest.fixture
def base_input():
    return ToolInput(
        target=TargetInfo(base_url="https://example.com"),
        request=ApiRequest(
            method="POST",
            path="/login",
            headers={"Accept": "application/json"},
            body={}
        ),
        auth=[
            AuthContext(role="user1", auth_type="bearer", token="user1:pass1"),
            AuthContext(role="user2", auth_type="bearer", token="user2:pass2"),
        ],
        options=ToolOptions(timeout=5000, extra={"wait": 0}),
    )