from __future__ import annotations

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.core.planner_output import PlannerOutput
from va_mcp.core.scenario_plan import ScenarioPlan
from va_mcp.planner.rules import OWASP_TOOL_MAP


class ScenarioPlanBuilder:
    """
    PlannerOutput + EndpointProfile → list[ScenarioPlan].

    owasp_candidates의 각 항목에 대해 ScenarioPlan을 하나씩 생성한다.
    tool_ids는 OWASP_TOOL_MAP에서 해당 카테고리의 목록을 그대로 사용한다.
    need_more_context=True일 때도 호출 가능하며, 상위 ScenarioRunner가 처리를 결정한다.
    """

    def build(self, output: PlannerOutput, profile: EndpointProfile) -> list[ScenarioPlan]:
        plans: list[ScenarioPlan] = []
        for owasp in output.owasp_candidates:
            tool_ids = list(OWASP_TOOL_MAP.get(owasp, []))
            plans.append(ScenarioPlan(owasp=owasp, tool_ids=tool_ids, endpoint=profile))
        return plans
