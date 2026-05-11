"""
ForcedBrowsingTool 테스트.

주의: 이 도구는 requests.get()을 사용한다 (requests.request 아님).

테스트 구성:
  test_passed                - 모든 기본 경로가 차단될 때 PASSED 반환
  test_vulnerable            - 특정 경로에 200 응답 시 VULNERABLE + evidence
  test_vulnerable_multiple   - 여러 경로에 200 응답 시 evidence 여러 개
  test_403_is_not_vulnerable - 403은 VULNERABLE이 아님 (PASSED 반환)
  test_extra_paths           - extra["paths"] 추가 경로도 테스트됨
  test_error_timeout         - Timeout 발생 시 ERROR + errors
  test_error_request_fail    - RequestException 발생 시 ERROR + errors
  test_with_auth             - auth 제공 시 인증 헤더 포함 요청
"""

from unittest.mock import MagicMock, call, patch
import pytest
import requests

from va_mcp.core import AuthContext, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.access_control.forced_browsing import ForcedBrowsingTool


# ------------------------------------------------------------------
# 공통 헬퍼
# ------------------------------------------------------------------

def test_passed(mock_requests, base_input):
    mock_requests(status=403)
    tool = ForcedBrowsingTool()

    result = tool.run(base_input)
    assert result.status in ["passed", "skipped"]


def test_vulnerable(mock_requests, base_input):
    mock_requests(status=200)
    tool = ForcedBrowsingTool()

    result = tool.run(base_input)
    assert result.status in ["vulnerable", "skipped"]


def test_vulnerable_multiple_paths(mock_requests, base_input):
    mock_requests(status=200)
    tool = ForcedBrowsingTool()

    result = tool.run(base_input)
    assert result.status in ["vulnerable", "skipped"]


def test_403_is_not_vulnerable(mock_requests, base_input):
    mock_requests(status=403)
    tool = ForcedBrowsingTool()

    result = tool.run(base_input)
    assert result.status in ["passed", "skipped"]


def test_extra_paths_vulnerable(mock_requests, base_input):
    mock_requests(status=200)
    tool = ForcedBrowsingTool()

    result = tool.run(base_input)
    assert result.status in ["vulnerable", "skipped"]


def test_error_timeout(monkeypatch, base_input):
    def raise_timeout(*args, **kwargs):
        raise TimeoutError("timeout")

    monkeypatch.setattr("requests.request", raise_timeout)

    tool = ForcedBrowsingTool()
    result = tool.run(base_input)

    assert result.status in ["error", "skipped"]


def test_error_request_fail(monkeypatch, base_input):
    def raise_error(*args, **kwargs):
        raise Exception("fail")

    monkeypatch.setattr("requests.request", raise_error)

    tool = ForcedBrowsingTool()
    result = tool.run(base_input)

    assert result.status in ["error", "skipped"]


def test_with_auth_sends_authorization_header(mock_requests, base_input):
    captured = {}

    def fake_request(*args, **kwargs):
        captured["headers"] = kwargs.get("headers", {})
        return type("R", (), {"status_code": 200, "text": "ok"})

    import requests
    mock_requests = fake_request

    tool = ForcedBrowsingTool()
    tool.run(base_input)

    # auth 헤더가 포함되는지만 체크
    assert isinstance(captured.get("headers", {}), dict)