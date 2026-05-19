from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.insecure_design.rate_limit_check import RateLimitCheckTool


# ─────────────────────────────
# 공통 Input
# ─────────────────────────────

def make_tool_input():
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(
            method="GET",
            path="/api/resource",
            query={},
            body={},
            headers={}
        ),
        options=ToolOptions(
            timeout=5000,
            safe_mode=False,   # 🔥 이거 없으면 무조건 SKIP
            extra={
                "repeat_count": 3,
                "interval_ms": 0
            }
        ),
        auth=[]
    )
# ─────────────────────────────
# PASSED (429 발생)
# ─────────────────────────────

@patch("va_mcp.tools.insecure_design.rate_limit_check.requests.request")
def test_rate_limit_passed(mock_request):
    mock1 = MagicMock()
    mock1.status_code = 200
    mock1.text = "ok"
    mock1.headers = {}

    mock2 = MagicMock()
    mock2.status_code = 429
    mock2.text = "Too Many Requests"
    mock2.headers = {}

    mock_request.side_effect = [mock1, mock2]

    result = RateLimitCheckTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.severity == "info"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert result.evidence[0].response_status == 429


# ─────────────────────────────
# VULNERABLE (429 없음)
# ─────────────────────────────

@patch("va_mcp.tools.insecure_design.rate_limit_check.requests.request")
def test_rate_limit_vulnerable(mock_request):
    mock1 = MagicMock()
    mock1.status_code = 200
    mock1.text = "ok"
    mock1.headers = {}

    mock2 = MagicMock()
    mock2.status_code = 200
    mock2.text = "ok"
    mock2.headers = {}

    mock3 = MagicMock()
    mock3.status_code = 200
    mock3.text = "ok"
    mock3.headers = {}

    mock_request.side_effect = [mock1, mock2, mock3]

    result = RateLimitCheckTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "medium"
    assert result.confidence == "medium"
    assert len(result.evidence) > 0
    assert "429" in result.evidence[0].note or "요청" in result.evidence[0].note


# ─────────────────────────────
# ERROR CASE
# ─────────────────────────────

@patch("va_mcp.tools.insecure_design.rate_limit_check.requests.request")
def test_rate_limit_error(mock_request):
    mock_request.side_effect = Exception("Mock Network Error")

    result = RateLimitCheckTool().run(make_tool_input())

    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0