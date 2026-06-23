# tests/tools/injection/test_cmd_injection.py

import requests
from unittest.mock import MagicMock, patch

from va_mcp.core.constants import Confidence, Severity, ToolStatus
from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.injection.cmd_injection import CmdInjectionTool


def make_tool_input(
    method: str = "GET",
    path: str = "/api/run",
    query: dict | None = None,
    body: dict | None = None,
    headers: dict | None = None,
    params: dict | None = None,
    safe_mode: bool = False,          # ← 기본을 False 로 변경
    **extra_opts,
) -> ToolInput:
    return ToolInput(
        target=TargetInfo(base_url="https://test-target.com"),
        request=ApiRequest(
            method=method,
            path=path,
            headers=headers or {},
            query=query or {},
            params=params or {},
            body=body,
        ),
        options=ToolOptions(
            timeout=5000,
            max_requests=1,
            safe_mode=safe_mode,
            extra=extra_opts
        ),
        auth=[],
    )


def mock_resp(text="ok", status=200):
    m = MagicMock()
    m.status_code = status
    m.text = text
    m.headers = {"Content-Type": "text/plain"}
    # safe_mode=True 일 때만 시간 기반 검출되므로
    # elapsed 를 0 으로 지정하여 테스트 통과 보장
    m.elapsed = MagicMock()
    m.elapsed.total_seconds.return_value = 0.0
    return m


# ---------------------------
# TEST 1: PASSED
# ---------------------------
@patch("requests.get", return_value=mock_resp("nothing suspicious"))
def test_passed(mock_get):
    result = CmdInjectionTool().run(
        make_tool_input(query={"cmd": "status"})
    )
    assert result.status == ToolStatus.PASSED.value
    assert result.severity == Severity.INFO.value


# ---------------------------
# TEST 2: VULNERABLE via GET
# ---------------------------
@patch("requests.get", return_value=mock_resp("uid=0(root)", 200))
def test_vulnerable(mock_get):
    result = CmdInjectionTool().run(
        make_tool_input(query={"cmd": "status"})
    )
    assert result.status == ToolStatus.VULNERABLE.value
    assert result.severity == Severity.CRITICAL.value
    assert len(result.evidence) > 0


# ---------------------------
# TEST 3: ERROR
# ---------------------------
@patch("requests.get", side_effect=Exception("connection refused"))
def test_error(mock_get):
    result = CmdInjectionTool().run(
        make_tool_input(query={"cmd": "status"})
    )
    assert result.status == ToolStatus.ERROR.value
    assert result.severity == Severity.INFO.value
    assert result.confidence == Confidence.LOW.value
    assert len(result.errors) > 0


# ---------------------------
# TEST 4: SKIPPED if no params
# ---------------------------
def test_skipped_no_params():
    result = CmdInjectionTool().run(
        make_tool_input(query={})
    )
    assert result.status == ToolStatus.SKIPPED.value
    assert result.evidence == []


# ---------------------------
# TEST 5: VULNERABLE via POST
# ---------------------------
@patch("requests.request", return_value=mock_resp("uid=1000(user)", 200))
def test_vulnerable_post(mock_req):
    result = CmdInjectionTool().run(
        make_tool_input(
            method="POST",
            body={"command": "ping"},
        )
    )
    assert result.status == ToolStatus.VULNERABLE.value
    assert len(result.evidence) > 0


# ---------------------------
# TEST 6: VULNERABLE via path param fallback (T-23, append 방식)
# ---------------------------
@patch("requests.get", return_value=mock_resp("uid=0(root)", 200))
def test_vulnerable_path_param_fallback_append(mock_get):
    """query/body 없는 path-param 전용 엔드포인트에서 cmd_injection은 원본 값에 payload를
    append한 뒤 percent-encode하여 경로 세그먼트로 전달한다 (T-23) — 교체가 아니라 append."""
    result = CmdInjectionTool().run(
        make_tool_input(path="/api/run/36", params={"id": "36"})
    )
    assert result.status == ToolStatus.VULNERABLE.value
    called_url = mock_get.call_args[0][0]
    # cmd_injection은 원본 값(36)을 지우지 않고 payload를 이어붙이므로 "/api/run/36"이
    # 접두사로 남아있는 것은 정상이다 — 핵심은 그 뒤에 payload가 percent-encode되어 붙는 것.
    assert called_url.startswith("https://test-target.com/api/run/36%3B")
    called_kwargs = mock_get.call_args[1]
    assert not called_kwargs.get("params")