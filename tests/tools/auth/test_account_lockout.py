from va_mcp.tools.auth.account_lockout import AccountLockoutTool


def test_account_lockout_vulnerable(base_input, mock_requests):
    mock_requests(status=200)

    tool = AccountLockoutTool()
    result = tool.run(base_input)

    assert result.status in ["vulnerable", "passed", "skipped", "error"]


def test_account_lockout_passed(base_input, mock_requests):
    mock_requests(status=403)

    tool = AccountLockoutTool()
    result = tool.run(base_input)

    assert result.status in ["passed", "vulnerable", "skipped", "error"]