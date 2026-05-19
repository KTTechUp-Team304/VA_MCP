from __future__ import annotations

from dataclasses import dataclass, field

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.core.scenario_result import ScenarioResult
from va_mcp.core.utils import utc_now_iso


@dataclass
class EndpointReport:
    """
    단일 엔드포인트에 대한 전체 시나리오 실행 결과 집계.

    ScenarioRunner가 생성하며 MCP 어댑터 / 리포터의 최종 출력 단위다.
    need_more_context=True일 때는 scenario_results가 비어 있고 missing에 부족한 키가 담긴다.
    """

    profile: EndpointProfile
    scenario_results: list[ScenarioResult] = field(default_factory=list)
    need_more_context: bool = False
    missing: list[str] = field(default_factory=list)
    generated_at: str = field(default_factory=utc_now_iso)
