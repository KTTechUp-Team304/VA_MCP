"""
analyze_endpoint_with_ai 통합 테스트 — 실제 OpenAI API 호출.

실행 방법:
    pytest -m integration tests/services/test_endpoint_analysis_ai_integration.py -v

OPENAI_API_KEY 환경 변수가 없으면 자동으로 skip.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

from va_mcp.core.endpoint_report import EndpointReport
from va_mcp.core.scenario_result import ScenarioResult
from va_mcp.core.schemas import ToolResult
from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.planner.ai_advisor import MissedFinding, ReviewResult, review


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def require_openai_key():
    if not os.environ.get("OPENAI_API_KEY"):
        from dotenv import load_dotenv
        load_dotenv()
    if not os.environ.get("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY 없음 — integration 테스트 skip")


def _make_profile(**kwargs) -> EndpointProfile:
    defaults = {
        "base_url": "http://localhost:3000",
        "method": "GET",
        "path": "/api/test",
    }
    defaults.update(kwargs)
    return EndpointProfile(**defaults)


def _make_report_with_results(profile: EndpointProfile, tool_statuses: dict[str, str]) -> EndpointReport:
    """tool_id → status 매핑으로 EndpointReport 생성."""
    tool_results = [
        ToolResult(
            tool_id=tid,
            tool_name=tid.replace("_", " ").title(),
            status=status,
            severity="info",
            title=f"{tid} check",
        )
        for tid, status in tool_statuses.items()
    ]
    scenario = ScenarioResult(owasp="A01 Broken Access Control", tool_results=tool_results)
    return EndpointReport(profile=profile, scenario_results=[scenario])


# ------------------------------------------------------------------
# 응답 구조 검증
# ------------------------------------------------------------------

def test_real_ai_review_returns_valid_structure():
    """실제 AI 호출 결과가 ReviewResult 타입이고 필수 필드를 갖는다."""
    profile = _make_profile(path="/api/users/1", auth_required=True)
    report_dict = {
        "profile": {"method": "GET", "path": "/api/users/1"},
        "tool_results": [
            {"tool_id": "security_headers", "status": "PASSED"},
            {"tool_id": "auth_jwt", "status": "SKIPPED"},
        ],
    }
    valid_tool_ids = {"security_headers", "auth_jwt", "idor_bola", "rbac_check"}

    result = review(report_dict, profile, valid_tool_ids)

    assert isinstance(result, ReviewResult)
    assert isinstance(result.missed_findings, list)
    for f in result.missed_findings:
        assert isinstance(f, MissedFinding)
        assert f.tool_id in valid_tool_ids, "valid_tool_ids 외 tool_id가 포함됨"
        assert f.status in {"ERROR", "SKIPPED", "PASSED", "UNKNOWN"}
        assert f.reason
        assert f.recommendation


def test_real_ai_review_on_empty_scan():
    """스캔 결과가 없을 때 AI가 빈 배열 또는 유효한 구조를 반환한다."""
    profile = _make_profile(path="/api/health")
    report_dict: dict = {"profile": {"method": "GET", "path": "/api/health"}, "tool_results": []}
    valid_tool_ids: set[str] = set()

    result = review(report_dict, profile, valid_tool_ids)

    assert isinstance(result, ReviewResult)
    # valid_tool_ids가 비어있으므로 missed_findings도 항상 비어야 함
    assert result.missed_findings == []


def test_real_ai_review_skipped_auth_tool_on_auth_endpoint():
    """인증 엔드포인트에서 auth_jwt가 SKIPPED이면 AI가 재실행 대상으로 포함할 수 있다."""
    profile = _make_profile(
        path="/api/users/1",
        auth_required=True,
        method="GET",
    )
    report_dict = {
        "profile": {"method": "GET", "path": "/api/users/1", "auth_required": True},
        "tool_results": [
            {"tool_id": "auth_jwt", "status": "SKIPPED", "reason": "request 없음"},
            {"tool_id": "security_headers", "status": "PASSED"},
        ],
    }
    valid_tool_ids = {"auth_jwt", "security_headers", "idor_bola"}

    result = review(report_dict, profile, valid_tool_ids)

    # 결과 구조만 검증 (AI가 포함 여부를 결정하므로 내용은 단언하지 않음)
    assert isinstance(result, ReviewResult)
    for f in result.missed_findings:
        assert f.tool_id in valid_tool_ids
