"""OS Command Injection Tool 테스트 (1단계: Mock)"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.constants import Confidence, Severity, ToolStatus
from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.cmd_injection import CmdInjectionTool


def make_tool_input(
    method: str = "GET",
    path: str = "/api/run",
    query: dict | None = None,
    body: dict | None = None,
    headers: dict | None = None,
    **extra_opts,
) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(
            method=method,
            path=path,
            headers=headers or {},
            query=query or {},
            body=body,
        ),
        options=ToolOptions(extra=extra_opts),
    )


def test_passed():
    """명령어 실행 시그니처 없는 정상 응답 → PASSED"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"result": "ok"}'
    mock_resp.headers = {"Content-Type": "application/json"}

    with patch("va_mcp.tools.cmd_injection.http_client.get", return_value=mock_resp):
        result = CmdInjectionTool().run(
            make_tool_input(
                query={"cmd": "status"},
                payload_list=["; ls", "| whoami"],
            )
        )

    assert result.status == ToolStatus.PASSED.value
    assert result.severity == Severity.INFO.value


def test_vulnerable():
    """명령어 실행 시그니처 감지 → VULNERABLE + evidence"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    mock_resp.headers = {"Content-Type": "text/plain"}

    with patch("va_mcp.tools.cmd_injection.http_client.get", return_value=mock_resp):
        result = CmdInjectionTool().run(
            make_tool_input(
                query={"cmd": "status"},
                payload_list=["; cat /etc/passwd"],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert result.severity == Severity.CRITICAL.value
    assert len(result.evidence) > 0


def test_error():
    """예외 발생 → ERROR + errors"""
    with patch(
        "va_mcp.tools.cmd_injection.http_client.get",
        side_effect=Exception("connection refused"),
    ):
        result = CmdInjectionTool().run(
            make_tool_input(
                query={"cmd": "status"},
                payload_list=["; ls"],
            )
        )

    assert result.status == ToolStatus.ERROR.value
    assert result.severity == Severity.INFO.value
    assert result.confidence == Confidence.LOW.value
    assert len(result.errors) > 0


def test_skipped_no_params():
    """파라미터 없으면 SKIPPED"""
    result = CmdInjectionTool().run(
        make_tool_input(query={})
    )
    assert result.status == ToolStatus.SKIPPED.value
    assert result.evidence == []


def test_vulnerable_post():
    """POST body에서도 감지"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "uid=0(root) gid=0(root)"
    mock_resp.headers = {"Content-Type": "text/plain"}

    with patch("va_mcp.tools.cmd_injection.http_client.request", return_value=mock_resp):
        result = CmdInjectionTool().run(
            make_tool_input(
                method="POST",
                path="/api/execute",
                body={"command": "ping"},
                payload_list=["; whoami"],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert len(result.evidence) > 0