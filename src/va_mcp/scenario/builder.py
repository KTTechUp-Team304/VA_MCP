from __future__ import annotations

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.core.planner_output import PlannerOutput
from va_mcp.core.scenario_plan import ScenarioPlan
from va_mcp.planner.rules import OWASP_TOOL_MAP


class ScenarioPlanBuilder:
    """
    PlannerOutput + EndpointProfile → list[ScenarioPlan].

    owasp_candidates의 각 항목에 대해 ScenarioPlan을 하나씩 생성한다.
    tool_ids는 PlannerOutput.tool_ids 중 OWASP_TOOL_MAP 기준으로 해당 카테고리에
    속하는 도구만 필터링해서 사용한다. 중복 실행을 방지하고 카테고리별 도구 분리를 유지한다.
    need_more_context=True일 때도 호출 가능하며, 상위 ScenarioRunner가 처리를 결정한다.
    """

    def build(self, output: PlannerOutput, profile: EndpointProfile) -> list[ScenarioPlan]:
        plans: list[ScenarioPlan] = []
        for owasp in output.owasp_candidates:
            category_pool = set(OWASP_TOOL_MAP.get(owasp, []))
            category_tools = [t for t in output.tool_ids if t in category_pool]
            plans.append(ScenarioPlan(owasp=owasp, tool_ids=category_tools, endpoint=profile))
        return plans
