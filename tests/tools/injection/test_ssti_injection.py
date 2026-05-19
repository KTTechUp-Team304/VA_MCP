from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.constants import Confidence, Severity, ToolStatus
from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.injection.ssti_injection import SstiInjectionTool


def make_tool_input(
    method: str = "GET",
    path: str = "/api/render",
    query: dict | None = None,
    body: dict | None = None,
    headers: dict | None = None,
    safe_mode: bool = False,      # ← 기본을 False 로 변경
    timeout: int = 5000,
    max_requests: int = 5,
    **extra_opts,
) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(
            method=method,
            path=path,
            headers=headers or {},
            query=query or {},
            body=body,
        ),
        options=ToolOptions(
            timeout=timeout,
            max_requests=max_requests,
            safe_mode=safe_mode,
            extra=extra_opts,
        ),
        auth=[],
    )


def make_resp(text="ok", status=200):
    m = MagicMock()
    m.status_code = status
    m.text = text
    m.headers = {}
    # elapsed 분기 방지
    m.elapsed = MagicMock()
    m.elapsed.total_seconds.return_value = 0.0
    return m


def test_passed():
    with patch("va_mcp.tools.injection.ssti_injection.requests.get",
               return_value=make_resp("safe output")):
        result = SstiInjectionTool().run(
            make_tool_input(query={"tpl": "hello"})
        )
    assert result.status == ToolStatus.PASSED.value


def test_vulnerable():
    with patch("va_mcp.tools.injection.ssti_injection.requests.get",
               return_value=make_resp("49")):
        result = SstiInjectionTool().run(
            make_tool_input(query={"tpl": "{{7*7}}"})
        )
    assert result.status == ToolStatus.VULNERABLE.value
    assert result.severity == Severity.CRITICAL.value


def test_vulnerable_post():
    with patch("va_mcp.tools.injection.ssti_injection.requests.request",
               return_value=make_resp("49")):
        result = SstiInjectionTool().run(
            make_tool_input(method="POST",
                            body={"tpl": "{{7*7}}"})
        )
    assert result.status == ToolStatus.VULNERABLE.value
    assert result.severity == Severity.CRITICAL.value