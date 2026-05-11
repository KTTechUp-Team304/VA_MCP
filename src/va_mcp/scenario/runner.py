from __future__ import annotations

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.core.endpoint_report import EndpointReport
from va_mcp.core.planner_output import PlannerOutput
from va_mcp.scenario._types import OrchestratorProtocol
from va_mcp.scenario.builder import ScenarioPlanBuilder
from va_mcp.scenario.scenario import Scenario


class ScenarioRunner:
    """
    PlannerOutput + EndpointProfile → EndpointReport.

    파이프라인의 Scenario 계층 진입점.
    ScenarioPlanBuilder로 계획을 수립하고, Scenario로 각 계획을 실행한 뒤 결과를 집계한다.

    need_more_context=True이면 Orchestrator를 호출하지 않고 즉시 반환한다.
    """

    def __init__(self, orchestrator: OrchestratorProtocol) -> None:
        self._builder = ScenarioPlanBuilder()
        self._scenario = Scenario(orchestrator)

    def run(self, output: PlannerOutput, profile: EndpointProfile) -> EndpointReport:
        if output.need_more_context:
            return EndpointReport(
                profile=profile,
                need_more_context=True,
                missing=list(output.missing),
            )

        plans = self._builder.build(output, profile)
        scenario_results = [self._scenario.run(plan) for plan in plans]

        return EndpointReport(profile=profile, scenario_results=scenario_results)
