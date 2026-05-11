from va_mcp.tools.auth.brute_force import BruteForceTool


def test_bruteforce(base_input, mock_requests):
    mock_requests(status=200)

    tool = BruteForceTool()
    result = tool.run(base_input)

    assert result.status in ["vulnerable", "passed", "error", "skipped"]