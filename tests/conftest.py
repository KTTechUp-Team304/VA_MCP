import pytest
from va_mcp.core.schemas import ToolInput, ToolOptions, ApiRequest, TargetInfo


class DummyResponse:
    def __init__(self, status=200, headers=None, text="ok"):
        self.status_code = status
        self.headers = headers or {}
        self.text = text


@pytest.fixture
def mock_requests(monkeypatch):
    def _mock(status=200, text="ok"):
        def fake_request(*args, **kwargs):
            return DummyResponse(status=status, text=text)

        monkeypatch.setattr("requests.request", fake_request)
        monkeypatch.setattr("requests.get", fake_request)
        return fake_request

    return _mock


@pytest.fixture
def base_input():
    return ToolInput(
        target=TargetInfo(base_url="http://test.com"),
        request=ApiRequest(
            method="GET",
            path="/admin",
            headers={},
            query={"id": "1"},
            body={}
        ),
        auth=[{"auth_type": "bearer", "token": "abc"}],
        options=ToolOptions(
            timeout=5000,
            max_requests=5,
            safe_mode=False,
            extra={}
        ),
    )