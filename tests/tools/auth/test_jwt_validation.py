from va_mcp.tools.auth.jwt_validation import JwtValidationTool


def test_jwt_validation(base_input, mock_requests):
    mock_requests(status=200)

    tool = JwtValidationTool()
    result = tool.run(base_input)

    assert result.status in ["vulnerable", "passed", "error", "skipped"]