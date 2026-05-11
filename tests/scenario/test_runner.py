"""
ScenarioRunner 테스트.

[need_more_context]
test_runner_returns_need_more_context_when_flagged   - PlannerOutput.need_more_context=True → 즉시 반환
test_runner_skips_orchestrator_on_need_more_context  - need_more_context 시 orchestrator 미호출
test_runner_propagates_missing_list                  - missing 리스트가 EndpointReport에 전달됨

[정상 실행]
test_runner_runs_scenario_for_each_candidate         - OWASP 후보 수 = ScenarioResult 수
test_runner_report_profile_matches_input             - EndpointReport.profile == 입력 profile
test_runner_generated_at_is_set                      - generated_at 필드가 비어 있지 않음
test_runner_collects_all_scenario_results            - 모든 시나리오 결과가 report에 포함

[엣지 케이스]
test_runner_empty_candidates_produces_empty_report   - 후보 없으면 scenario_results=[]
"""

from unittest.mock import MagicMock

import pytest

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.core.planner_output import PlannerOutput
from va_mcp.planner.baseline import A02_BASELINE_TOOL_IDS, A10_BASELINE_TOOL_IDS
from va_mcp.scenario.runner import ScenarioRunner


# ------------------------------------------------------------------
# 헬퍼
# ------------------------------------------------------------------

def make_profile() -> EndpointProfile:
    return EndpointProfile(base_url="https://api.example.com", method="POST", path="/api/login")


def make_orchestrator() -> MagicMock:
    orch = MagicMock()
    orch.run.return_value = []
    return orch


def make_baseline_output(need_more_context: bool = False) -> PlannerOutput:
    return PlannerOutput(
        owasp_candidates=["A02", "A10"],
        tool_ids=list(A02_BASELINE_TOOL_IDS) + list(A10_BASELINE_TOOL_IDS),
        need_more_context=need_more_context,
        missing=["auth_contexts", "resource_context"] if need_more_context else [],
    )


# ------------------------------------------------------------------
# need_more_context
# ------------------------------------------------------------------

def test_runner_returns_need_more_context_when_flagged():
    output = make_baseline_output(need_more_context=True)
    report = ScenarioRunner(make_orchestrator()).run(output, make_profile())
    assert report.need_more_context is True


def test_runner_skips_orchestrator_on_need_more_context():
    orch = make_orchestrator()
    output = make_baseline_output(need_more_context=True)
    ScenarioRunner(orch).run(output, make_profile())
    orch.run.assert_not_called()


def test_runner_propagates_missing_list():
    output = PlannerOutput(
        owasp_candidates=["A02"],
        tool_ids=[],
        need_more_context=True,
        missing=["auth_contexts", "resource_context"],
    )
    report = ScenarioRunner(make_orchestrator()).run(output, make_profile())
    assert "auth_contexts" in report.missing
    assert "resource_context" in report.missing


# ------------------------------------------------------------------
# 정상 실행
# ------------------------------------------------------------------

def test_runner_runs_scenario_for_each_candidate():
    output = make_baseline_output()
    report = ScenarioRunner(make_orchestrator()).run(output, make_profile())
    assert len(report.scenario_results) == 2


def test_runner_report_profile_matches_input():
    profile = make_profile()
    output = make_baseline_output()
    report = ScenarioRunner(make_orchestrator()).run(output, profile)
    assert report.profile is profile


def test_runner_generated_at_is_set():
    output = make_baseline_output()
    report = ScenarioRunner(make_orchestrator()).run(output, make_profile())
    assert report.generated_at != ""


def test_runner_collects_all_scenario_results():
    output = PlannerOutput(
        owasp_candidates=["A02", "A07", "A10"],
        tool_ids=[],
    )
    report = ScenarioRunner(make_orchestrator()).run(output, make_profile())
    owasps = [r.owasp for r in report.scenario_results]
    assert "A02" in owasps
    assert "A07" in owasps
    assert "A10" in owasps


# ------------------------------------------------------------------
# 엣지 케이스
# ------------------------------------------------------------------

def test_runner_empty_candidates_produces_empty_report():
    output = PlannerOutput(owasp_candidates=[], tool_ids=[])
    report = ScenarioRunner(make_orchestrator()).run(output, make_profile())
    assert report.scenario_results == []
    assert report.need_more_context is False
