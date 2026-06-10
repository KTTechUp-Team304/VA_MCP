"""
analyze_endpoint_with_ai 테스트.

[정상 실행 - mock AI]
test_analyzed_without_ai           - AI mock → 빈 missed_findings, status=analyzed
test_ai_review_included_in_result  - AI review 결과가 ai_review 키에 포함됨
test_comparison_always_present     - comparison/ai_extra_results 키가 항상 응답에 포함됨
test_ai_only_findings              - AI missed tool 재실행 → vulnerable → ai_only_findings에 포함

[폴백]
test_ai_failure_fallback           - _call_openai 예외 → 빈 ReviewResult 반환, 분석 정상 완료

[오류 케이스]
test_invalid_input_returns_error   - 필수 필드 누락 → invalid_input 상태 반환
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from va_mcp.core.endpoint_report import EndpointReport
from va_mcp.core.scenario_result import ScenarioResult
from va_mcp.core.schemas import ToolResult
from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.services.endpoint_analysis_ai import analyze_endpoint_with_ai


# ------------------------------------------------------------------
# 헬퍼
# ------------------------------------------------------------------

def make_raw_input(**overrides) -> dict:
    base = {
        "base_url": "http://localhost:4000",
        "method": "GET",
        "path": "/api/test",
    }
    base.update(overrides)
    return base


def make_endpoint_report(profile: EndpointProfile | None = None) -> EndpointReport:
    if profile is None:
        profile = EndpointProfile(
            base_url="http://localhost:4000",
            method="GET",
            path="/api/test",
        )
    return EndpointReport(profile=profile, scenario_results=[])


def make_vulnerable_report(profile: EndpointProfile, tool_id: str) -> EndpointReport:
    """tool_id가 vulnerable 상태인 ToolResult를 포함한 EndpointReport."""
    result = ToolResult(
        tool_id=tool_id,
        tool_name=tool_id.replace("_", " ").title(),
        status="vulnerable",
        severity="high",
        title=f"{tool_id} vulnerability found",
    )
    scenario = ScenarioResult(owasp="A01 Broken Access Control", tool_results=[result])
    return EndpointReport(profile=profile, scenario_results=[scenario])


def make_mock_recorder() -> MagicMock:
    rec = MagicMock()
    rec.run_id = "test-run-id"
    rec.run_dir = MagicMock()
    return rec


# ------------------------------------------------------------------
# 공통 fixture: 파일시스템·네트워크 의존 제거
# ------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_infra(monkeypatch):
    """RunRecorder, ScenarioRunner, write_vulnerability_report, discover_tools mock."""
    monkeypatch.setattr(
        "va_mcp.services.endpoint_analysis_ai.RunRecorder",
        lambda: make_mock_recorder(),
    )
    monkeypatch.setattr(
        "va_mcp.services.endpoint_analysis_ai._scenario_runner.run",
        lambda planner_output, profile: make_endpoint_report(profile),
    )
    monkeypatch.setattr(
        "va_mcp.services.endpoint_analysis_ai.write_vulnerability_report",
        lambda *a, **kw: {},
    )
    monkeypatch.setattr(
        "va_mcp.services.endpoint_analysis_ai.discover_tools",
        lambda: {"extra_tool": MagicMock()},
    )


# ------------------------------------------------------------------
# 정상 실행 - mock AI
# ------------------------------------------------------------------

def test_analyzed_without_ai():
    """AI(mock)가 빈 missed_findings 반환 → rule-based 결과 그대로 status=analyzed."""
    result = analyze_endpoint_with_ai(make_raw_input())

    assert result["status"] == "analyzed"
    assert result["run_id"] == "test-run-id"
    assert "tool_ids" in result
    assert "endpoint_profile" in result
    assert result["ai_review"]["missed_findings"] == []


def test_ai_review_included_in_result(monkeypatch):
    """AI review 결과가 응답의 ai_review.missed_findings에 포함된다."""
    from va_mcp.planner.ai_advisor import MissedFinding, ReviewResult

    monkeypatch.setattr(
        "va_mcp.services.endpoint_analysis_ai.ai_advisor.review",
        lambda report, profile, valid_tool_ids: ReviewResult(
            missed_findings=[
                MissedFinding(
                    tool_id="sql_injection",
                    status="PASSED",
                    reason="Boolean 기반 탐지 누락",
                    recommendation="AND 1=1 vs AND 1=2 응답 차이 확인 필요",
                )
            ]
        ),
    )

    result = analyze_endpoint_with_ai(make_raw_input())

    assert result["status"] == "analyzed"
    assert len(result["ai_review"]["missed_findings"]) == 1
    assert result["ai_review"]["missed_findings"][0]["tool_id"] == "sql_injection"


def test_comparison_always_present():
    """comparison, ai_extra_results 키가 항상 응답에 포함된다."""
    result = analyze_endpoint_with_ai(make_raw_input())

    assert "comparison" in result
    assert "ai_extra_results" in result
    cmp = result["comparison"]
    assert "rule_based_vulnerable_count" in cmp
    assert "ai_extra_vulnerable_count" in cmp
    assert "ai_only_findings" in cmp
    assert isinstance(cmp["ai_only_findings"], list)


def test_ai_only_findings(monkeypatch):
    """AI가 valid tool을 missed로 반환하고 재실행 결과가 vulnerable이면 ai_only_findings에 포함된다."""
    from va_mcp.planner.ai_advisor import MissedFinding, ReviewResult

    # extra_tool은 discover_tools mock에 등록된 valid tool_id
    monkeypatch.setattr(
        "va_mcp.services.endpoint_analysis_ai.ai_advisor.review",
        lambda report, profile, valid_tool_ids: ReviewResult(
            missed_findings=[
                MissedFinding(
                    tool_id="extra_tool",
                    status="SKIPPED",
                    reason="탐지 누락",
                    recommendation="재실행 필요",
                )
            ]
        ),
    )

    call_count = {"n": 0}

    def mock_run(planner_output, profile):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return make_endpoint_report(profile)       # 1차: 빈 결과
        return make_vulnerable_report(profile, "extra_tool")  # 2차 재실행: vulnerable

    monkeypatch.setattr(
        "va_mcp.services.endpoint_analysis_ai._scenario_runner.run",
        mock_run,
    )

    result = analyze_endpoint_with_ai(make_raw_input())

    assert result["status"] == "analyzed"
    assert call_count["n"] == 2, "rule-based + AI re-run으로 총 2회 실행되어야 한다"
    assert result["comparison"]["ai_extra_vulnerable_count"] == 1
    ai_only = result["comparison"]["ai_only_findings"]
    assert len(ai_only) == 1
    assert ai_only[0]["tool_id"] == "extra_tool"


# ------------------------------------------------------------------
# 폴백
# ------------------------------------------------------------------

def test_ai_failure_fallback(monkeypatch):
    """_call_openai 예외 발생 → review가 빈 ReviewResult 반환하고 분석 정상 완료."""
    def failing_call_openai(*args, **kwargs):
        raise RuntimeError("Claude API 연결 실패")

    monkeypatch.setattr(
        "va_mcp.planner.ai_advisor._call_openai",
        failing_call_openai,
    )

    result = analyze_endpoint_with_ai(make_raw_input())

    assert result["status"] == "analyzed"
    assert result["ai_review"]["missed_findings"] == []


# ------------------------------------------------------------------
# 오류 케이스
# ------------------------------------------------------------------

def test_invalid_input_returns_error():
    """필수 필드(base_url, path) 누락 → invalid_input 상태 반환."""
    result = analyze_endpoint_with_ai({"method": "GET"})

    assert result["status"] == "invalid_input"
    assert result["run_id"] == "test-run-id"
    assert "errors" in result
    assert len(result["errors"]) > 0
