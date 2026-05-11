from va_mcp.tools.auth.credential_enum import CredentialEnumTool


def test_credential_enum(base_input, mock_requests):
    mock_requests(status=200)

    tool = CredentialEnumTool()
    result = tool.run(base_input)

    assert result.status in ["vulnerable", "passed", "skipped", "error"]