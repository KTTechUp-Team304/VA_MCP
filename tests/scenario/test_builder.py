"""
ScenarioPlanBuilder 테스트.

[기본 동작]
test_build_creates_one_plan_per_owasp_candidate  - OWASP 후보 수 = 생성된 plan 수
test_build_assigns_endpoint_to_every_plan        - 모든 plan에 endpoint 할당
test_build_sets_correct_owasp_per_plan           - 각 plan의 owasp 필드가 후보와 일치

[tool_ids]
test_build_tool_ids_filtered_by_owasp_tool_map   - OWASP_TOOL_MAP 기준으로 카테고리 도구만 필터링
test_build_baseline_a02_tool_ids                 - A02 plan은 baseline tool_ids 포함
test_build_baseline_a10_tool_ids                 - A10 plan은 baseline tool_ids 포함
test_build_empty_tool_ids_for_a09               - A09 plan은 tool_ids 빈 목록 (미구현 placeholder)
test_build_no_duplicate_tools_across_plans       - 동일 도구가 여러 plan에 중복 실행되지 않음

[엣지 케이스]
test_build_empty_candidates_returns_empty_list   - owasp_candidates 없으면 빈 리스트
test_build_order_preserved                       - 입력 순서 보존 (A01 미포함 케이스)

[실행 순서]
test_build_a01_always_first                      - A01이 owasp_candidates 뒤쪽에 있어도 plan 순서는 항상 맨 앞
test_build_a01_first_preserves_relative_order_of_rest - A01 제외 나머지 카테고리는 상대 순서 유지
"""

import pytest

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.core.planner_output import PlannerOutput
from va_mcp.planner.baseline import A02_BASELINE_TOOL_IDS, A10_BASELINE_TOOL_IDS
from va_mcp.planner.rules import OWASP_TOOL_MAP
from va_mcp.scenario.builder import ScenarioPlanBuilder


@pytest.fixture
def builder() -> ScenarioPlanBuilder:
    return ScenarioPlanBuilder()


@pytest.fixture
def profile() -> EndpointProfile:
    return EndpointProfile(base_url="https://api.example.com", method="GET", path="/api/users/1")


@pytest.fixture
def baseline_output() -> PlannerOutput:
    return PlannerOutput(
        owasp_candidates=["A02", "A10"],
        tool_ids=list(A02_BASELINE_TOOL_IDS) + list(A10_BASELINE_TOOL_IDS),
    )


# ------------------------------------------------------------------
# 기본 동작
# ------------------------------------------------------------------

def test_build_creates_one_plan_per_owasp_candidate(builder, profile, baseline_output):
    plans = builder.build(baseline_output, profile)
    assert len(plans) == 2


def test_build_assigns_endpoint_to_every_plan(builder, profile, baseline_output):
    plans = builder.build(baseline_output, profile)
    for plan in plans:
        assert plan.endpoint is profile


def test_build_sets_correct_owasp_per_plan(builder, profile, baseline_output):
    plans = builder.build(baseline_output, profile)
    owasps = [p.owasp for p in plans]
    assert owasps == ["A02", "A10"]


# ------------------------------------------------------------------
# tool_ids
# ------------------------------------------------------------------

def test_build_tool_ids_filtered_by_owasp_tool_map(builder, profile):
    """A01 plan은 PlannerOutput.tool_ids 중 OWASP_TOOL_MAP["A01"] 소속 도구만 포함한다."""
    output = PlannerOutput(
        owasp_candidates=["A01"],
        tool_ids=["idor_bola", "forced_browsing", "auth_jwt"],  # auth_jwt는 A07 소속
    )
    plans = builder.build(output, profile)
    assert "idor_bola" in plans[0].tool_ids
    assert "forced_browsing" in plans[0].tool_ids
    assert "auth_jwt" not in plans[0].tool_ids  # A01 소속 아님


def test_build_no_duplicate_tools_across_plans(builder, profile):
    """동일 도구가 여러 OWASP plan에 중복 포함되지 않는다."""
    output = PlannerOutput(
        owasp_candidates=["A01", "A07"],
        tool_ids=["idor_bola", "auth_jwt", "auth_session"],
    )
    plans = builder.build(output, profile)
    a01_tools = plans[0].tool_ids
    a07_tools = plans[1].tool_ids
    overlap = set(a01_tools) & set(a07_tools)
    assert len(overlap) == 0


def test_build_baseline_a02_tool_ids(builder, profile, baseline_output):
    plans = builder.build(baseline_output, profile)
    a02_plan = next(p for p in plans if p.owasp == "A02")
    for tid in A02_BASELINE_TOOL_IDS:
        assert tid in a02_plan.tool_ids


def test_build_baseline_a10_tool_ids(builder, profile, baseline_output):
    plans = builder.build(baseline_output, profile)
    a10_plan = next(p for p in plans if p.owasp == "A10")
    for tid in A10_BASELINE_TOOL_IDS:
        assert tid in a10_plan.tool_ids


def test_build_empty_tool_ids_for_a09(builder, profile):
    output = PlannerOutput(owasp_candidates=["A09"], tool_ids=[])
    plans = builder.build(output, profile)
    assert plans[0].owasp == "A09"
    assert plans[0].tool_ids == []


# ------------------------------------------------------------------
# 엣지 케이스
# ------------------------------------------------------------------

def test_build_empty_candidates_returns_empty_list(builder, profile):
    output = PlannerOutput(owasp_candidates=[], tool_ids=[])
    plans = builder.build(output, profile)
    assert plans == []


def test_build_order_preserved(builder, profile):
    output = PlannerOutput(
        owasp_candidates=["A02", "A07", "A10"],
        tool_ids=[],
    )
    plans = builder.build(output, profile)
    assert [p.owasp for p in plans] == ["A02", "A07", "A10"]


# ------------------------------------------------------------------
# 실행 순서 (A01은 항상 최우선 실행)
# ------------------------------------------------------------------

def test_build_a01_always_first(builder, profile):
    """A02가 owasp_candidates에서 A01보다 앞에 있어도, plan 순서는 A01이 먼저여야 한다."""
    output = PlannerOutput(
        owasp_candidates=["A02", "A01", "A10"],
        tool_ids=[],
    )
    plans = builder.build(output, profile)
    assert [p.owasp for p in plans] == ["A01", "A02", "A10"]


def test_build_a01_first_preserves_relative_order_of_rest(builder, profile):
    """A01을 맨 앞으로 옮기는 정렬이 나머지 카테고리의 상대 순서는 바꾸지 않아야 한다."""
    output = PlannerOutput(
        owasp_candidates=["A04", "A02", "A01", "A07", "A10"],
        tool_ids=[],
    )
    plans = builder.build(output, profile)
    assert [p.owasp for p in plans] == ["A01", "A04", "A02", "A07", "A10"]
