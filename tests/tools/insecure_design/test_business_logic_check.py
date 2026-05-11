from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.insecure_design.business_logic_check import BusinessLogicCheckTool


# ─────────────────────────────
# 공통 Input (완전 안전 버전)
# ─────────────────────────────

def make_tool_input():
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(
            method="POST",
            path="/api/payment",
            query={},
            body={"amount": 1000},
            headers={}
        ),
        options=ToolOptions(
            timeout=5000,
            safe_mode=False,   # 🔥 핵심 추가
            extra={
                "test_field": "amount",
                "invalid_values": [-1, 0]
            }
        ),
        auth=[]
    )
# ─────────────────────────────
# PASSED (400/422만)
# ─────────────────────────────

@patch("va_mcp.tools.insecure_design.business_logic_check.requests.request")
def test_business_logic_passed(mock_request):
    mock1 = MagicMock()
    mock1.status_code = 400
    mock1.text = "Invalid"
    mock1.headers = {}

    mock2 = MagicMock()
    mock2.status_code = 422
    mock2.text = "Invalid"
    mock2.headers = {}

    mock_request.side_effect = [mock1, mock2]

    result = BusinessLogicCheckTool().run(make_tool_input())

    assert result.status == "passed"
    assert result.severity == "info"
    assert result.confidence == "high"
    assert len(result.evidence) > 0


# ─────────────────────────────
# VULNERABLE (200 허용)
# ─────────────────────────────

@patch("va_mcp.tools.insecure_design.business_logic_check.requests.request")
def test_business_logic_vulnerable(mock_request):
    mock1 = MagicMock()
    mock1.status_code = 200
    mock1.text = "success"
    mock1.headers = {}

    mock2 = MagicMock()
    mock2.status_code = 200
    mock2.text = "success"
    mock2.headers = {}

    mock_request.side_effect = [mock1, mock2]

    result = BusinessLogicCheckTool().run(make_tool_input())

    assert result.status == "vulnerable"
    assert result.severity == "high"
    assert result.confidence == "high"
    assert len(result.evidence) > 0
    assert result.evidence[0].note != ""


# ─────────────────────────────
# ERROR CASE
# ─────────────────────────────

@patch("va_mcp.tools.insecure_design.business_logic_check.requests.request")
def test_business_logic_error(mock_request):
    mock_request.side_effect = Exception("Mock Network Error")

    result = BusinessLogicCheckTool().run(make_tool_input())

    assert result.status == "error"
    assert result.severity == "info"
    assert result.confidence == "low"
    assert len(result.errors) > 0