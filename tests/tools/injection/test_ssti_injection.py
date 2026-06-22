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
    params: dict | None = None,
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
            params=params or {},
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


def test_vulnerable_path_param_fallback():
    """query/body 없는 path-param 전용 엔드포인트에서 SSTI payload와 카나리 검증 모두
    경로 세그먼트로 percent-encode되어 전달되는지 확인한다 (T-23)."""
    with patch("va_mcp.tools.injection.ssti_injection.requests.get",
               side_effect=[make_resp("49"), make_resp("safe output")]) as mock_get:
        result = SstiInjectionTool().run(
            make_tool_input(
                path="/api/courses/2",
                params={"courseId": "2"},
                max_requests=2,
                payload_list=[{"payload": "{{7*7}}", "expected": "49"}],
            )
        )
    assert result.status == ToolStatus.VULNERABLE.value
    assert mock_get.call_count == 2
    payload_call_url = mock_get.call_args_list[0][0][0]
    canary_call_url = mock_get.call_args_list[1][0][0]
    assert "/api/courses/2" not in payload_call_url
    assert "%7B%7B" in payload_call_url
    assert "SSTI_CANARY_98765" in canary_call_url