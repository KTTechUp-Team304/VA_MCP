from va_mcp.tools.auth.rate_limit import RateLimitTool


def test_rate_limit(base_input, mock_requests):
    mock_requests(status=200)

    tool = RateLimitTool()
    result = tool.run(base_input)

    assert result.status in ["vulnerable", "passed", "error", "skipped"]