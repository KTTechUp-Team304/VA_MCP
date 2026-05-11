import pytest
from va_mcp.core.schemas import ToolInput, ApiRequest, TargetInfo, ToolOptions


@pytest.fixture
def base_input():
    return ToolInput(
        target=TargetInfo(base_url="http://test.com"),
        request=ApiRequest(
            method="POST",
            path="/update",
            headers={},
            query={"user_id": "1", "role": "user"},  # ⭐ 중요
            body={"user_id": "1", "role": "user"}    # ⭐ 중요
        ),
        auth=[{"auth_type": "bearer", "token": "abc"}],
        options=ToolOptions(
            timeout=5000,
            max_requests=5,
            safe_mode=False,
            extra={}
        ),
    )