from __future__ import annotations

from va_mcp.core.constants import ToolStatus
from va_mcp.core.scenario_plan import ScenarioPlan
from va_mcp.core.scenario_result import ScenarioResult
from va_mcp.core.schemas import ToolResult
from va_mcp.scenario._types import OrchestratorProtocol


class Scenario:
    """
    ScenarioPlan 한 건을 Orchestrator에 위임하고 ScenarioResult를 반환한다.

    판단 로직 없음 — Orchestrator가 각 Tool을 실행하고, 이 클래스는 결과를 수집·집계만 한다.
    tool_ids가 비어 있거나 endpoint가 None이면 Orchestrator를 호출하지 않고 빈 결과를 반환한다.
    """

    def __init__(self, orchestrator: OrchestratorProtocol) -> None:
        self._orchestrator = orchestrator

    def run(self, plan: ScenarioPlan) -> ScenarioResult:
        if not plan.tool_ids or plan.endpoint is None:
            return ScenarioResult(owasp=plan.owasp)

        tool_results = self._orchestrator.run(plan.tool_ids, plan.endpoint)
        poc = _build_poc(plan.owasp, tool_results)
        return ScenarioResult(owasp=plan.owasp, tool_results=tool_results, poc=poc)


def _build_poc(owasp: str, tool_results: list[ToolResult]) -> str:
    """취약 결과에서 재현 가능한 POC 텍스트를 생성한다."""
    vulns = [r for r in tool_results if r.status == ToolStatus.VULNERABLE.value]
    if not vulns:
        return ""

    lines: list[str] = [f"[{owasp}] 취약점 {len(vulns)}건 발견"]
    for r in vulns:
        lines.append(f"- {r.tool_id}: {r.title}")
        for ev in r.evidence[:1]:
            method = ev.request.get("method", "")
            path = ev.request.get("path", "")
            lines.append(f"  재현: {method} {path} → HTTP {ev.response_status}")
            if ev.note:
                lines.append(f"  근거: {ev.note}")
    return "\n".join(lines)
