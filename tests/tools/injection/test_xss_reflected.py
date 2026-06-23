"""Reflected XSS Tool 테스트 (1단계: Mock)"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.constants import Confidence, Severity, ToolStatus
from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.injection.xss_reflected import XssReflectedTool


def make_tool_input(
    method: str = "GET",
    path: str = "/api/search",
    query: dict | None = None,
    body: dict | None = None,
    headers: dict | None = None,
    params: dict | None = None,
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
        options=ToolOptions(extra=extra_opts),
    )


def test_passed():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"results": [], "query": "sanitized_input"}'

    with patch("requests.get", return_value=mock_resp):
        result = XssReflectedTool().run(
            make_tool_input(
                query={"q": "hello"},
                payload_list=["<script>alert(1)</script>"],
            )
        )

    assert result.status == ToolStatus.PASSED.value
    assert result.severity == Severity.INFO.value


def test_vulnerable():
    payload = "<script>alert(1)</script>"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = f"<html>{payload}</html>"

    with patch("requests.get", return_value=mock_resp):
        result = XssReflectedTool().run(
            make_tool_input(
                query={"q": "hello"},
                payload_list=[payload],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert result.severity == Severity.HIGH.value
    assert len(result.evidence) > 0
    assert "반사" in result.evidence[0].note


def test_vulnerable_img_tag():
    payload = '<img src=x onerror=alert(1)>'

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = f"<html>{payload}</html>"

    with patch("requests.get", return_value=mock_resp):
        result = XssReflectedTool().run(
            make_tool_input(
                query={"q": "hello"},
                payload_list=[payload],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert len(result.evidence) > 0


# ── path param fallback (T-23) ─────────────────────────────

def test_vulnerable_path_param_fallback():
    """query/body 없는 path-param 전용 엔드포인트에서 XSS payload가 경로 세그먼트로
    percent-encode되어 전달되는지 확인한다 (T-23)."""
    payload = "<script>alert(1)</script>"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = f"<html>{payload}</html>"

    with patch("requests.get", return_value=mock_resp) as mock_get:
        result = XssReflectedTool().run(
            make_tool_input(
                path="/api/users/36",
                params={"userId": "36"},
                payload_list=[payload],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    called_url = mock_get.call_args[0][0]
    assert "/api/users/36" not in called_url
    assert "%3C" in called_url


# ── ERROR ──────────────────────────────────────────────────

def test_error():
    with patch("requests.get", side_effect=Exception("connection refused")):
        result = XssReflectedTool().run(
            make_tool_input(
                query={"q": "hello"},
                payload_list=["<script>alert(1)</script>"],
            )
        )

    assert result.status == ToolStatus.ERROR.value
    assert result.severity == Severity.INFO.value
    assert result.confidence == Confidence.LOW.value
    assert len(result.errors) > 0


# ── SKIP ───────────────────────────────────────────────────

def test_skipped_no_params():
    result = XssReflectedTool().run(
        make_tool_input(query={})
    )
    assert result.status == ToolStatus.SKIPPED.value
    assert result.evidence == []


# ── POST ───────────────────────────────────────────────────

def test_vulnerable_post():
    payload = "<script>alert(1)</script>"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = f"<html>입력값: {payload}</html>"

    with patch("requests.request", return_value=mock_resp):
        result = XssReflectedTool().run(
            make_tool_input(
                method="POST",
                path="/api/comment",
                body={"content": "hello"},
                payload_list=[payload],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert len(result.evidence) > 0