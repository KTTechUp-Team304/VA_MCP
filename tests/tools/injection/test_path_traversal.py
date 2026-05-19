"""Path Traversal Tool 테스트 (1단계: Mock)"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from va_mcp.core.constants import Confidence, Severity, ToolStatus
from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.injection.path_traversal import PathTraversalTool


def make_tool_input(
    method: str = "GET",
    path: str = "/api/file",
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
    """파일 내용 시그니처 없는 정상 응답 → PASSED"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"content": "hello world"}'

    with patch("requests.get", return_value=mock_resp):
        result = PathTraversalTool().run(
            make_tool_input(
                query={"file": "readme.txt"},
                payload_list=["../../../etc/passwd"],
            )
        )

    assert result.status == ToolStatus.PASSED.value
    assert result.severity == Severity.INFO.value


def test_vulnerable():
    """/etc/passwd 내용 감지 → VULNERABLE"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "root:x:0:0:root:/root:/bin/bash"

    with patch("requests.get", return_value=mock_resp):
        result = PathTraversalTool().run(
            make_tool_input(
                query={"file": "readme.txt"},
                payload_list=["../../../etc/passwd"],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert result.severity == Severity.HIGH.value
    assert len(result.evidence) > 0


def test_vulnerable_windows():
    """Windows 시스템 파일 감지 → VULNERABLE"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "[fonts]\n[extensions]"

    with patch("requests.get", return_value=mock_resp):
        result = PathTraversalTool().run(
            make_tool_input(
                query={"file": "readme.txt"},
                payload_list=["..\\..\\..\\windows\\win.ini"],
            )
        )

    assert result.status == ToolStatus.VULNERABLE.value
    assert len(result.evidence) > 0


def test_error():
    """예외 발생 → ERROR"""
    with patch("requests.get", side_effect=Exception("connection refused")):
        result = PathTraversalTool().run(
            make_tool_input(
                query={"file": "readme.txt"},
                payload_list=["../../../etc/passwd"],
            )
        )

    assert result.status == ToolStatus.ERROR.value
    assert result.severity == Severity.INFO.value
    assert result.confidence == Confidence.LOW.value
    assert len(result.errors) > 0


def test_skipped_no_params():
    """파라미터 없으면 SKIPPED"""
    result = PathTraversalTool().run(
        make_tool_input(query={})
    )
    assert result.status == ToolStatus.SKIPPED.value
    assert result.evidence == []