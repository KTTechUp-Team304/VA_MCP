from __future__ import annotations

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.core.endpoint_report import EndpointReport
from va_mcp.core.planner_output import PlannerOutput
from va_mcp.core.scenario_plan import ScenarioPlan
from va_mcp.core.scenario_result import ScenarioResult
from va_mcp.scenario._types import OrchestratorProtocol
from va_mcp.scenario.builder import ScenarioPlanBuilder
from va_mcp.scenario.scenario import Scenario, _build_poc


class ScenarioRunner:
    """
    PlannerOutput + EndpointProfile → EndpointReport.

    파이프라인의 Scenario 계층 진입점.
    ScenarioPlanBuilder로 계획을 수립하고, Scenario로 각 계획을 실행한 뒤 결과를 집계한다.

    need_more_context=True이면 Orchestrator를 호출하지 않고 즉시 반환한다.
    """

    def __init__(self, orchestrator: OrchestratorProtocol) -> None:
        self._orchestrator = orchestrator
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
        scenario_results = self._run_plans(plans)

        return EndpointReport(profile=profile, scenario_results=scenario_results)

    def _run_plans(self, plans: list[ScenarioPlan]) -> list[ScenarioResult]:
        """인증은 1회만 수행하고 OWASP 시나리오별로 tool을 실행한다."""
        from va_mcp.orchestrator.orchestrator import Orchestrator

        if isinstance(self._orchestrator, Orchestrator):
            return self._run_plans_with_shared_auth(plans)

        return [self._scenario.run(plan) for plan in plans]

    def _run_plans_with_shared_auth(self, plans: list[ScenarioPlan]) -> list[ScenarioResult]:
        from va_mcp.orchestrator.orchestrator import Orchestrator

        orch: Orchestrator = self._orchestrator  # type: ignore[assignment]
        profile = plans[0].endpoint if plans else None
        if profile is None:
            return []

        provider = orch._merge_auth_contexts(profile)
        results: list[ScenarioResult] = []
        try:
            for plan in plans:
                if not plan.tool_ids or plan.endpoint is None:
                    results.append(ScenarioResult(owasp=plan.owasp))
                    continue
                tool_results = orch.run(
                    plan.tool_ids,
                    plan.endpoint,
                    provider=provider,
                    logout_when_done=False,
                )
                poc = _build_poc(plan.owasp, tool_results)
                results.append(
                    ScenarioResult(owasp=plan.owasp, tool_results=tool_results, poc=poc)
                )
        finally:
            if provider:
                provider.logout_all()

        return results
