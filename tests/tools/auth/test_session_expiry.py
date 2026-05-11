from va_mcp.tools.auth.session_expiry import SessionExpiryTool


def test_session_expiry(base_input, mock_requests):
    mock_requests(status=200)

    tool = SessionExpiryTool()
    result = tool.run(base_input)

    assert result.status in ["vulnerable", "passed", "skipped", "error"]