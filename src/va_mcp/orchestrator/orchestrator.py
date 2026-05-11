from __future__ import annotations

import pkgutil
import importlib
import time
from typing import Any, Dict, List

from va_mcp.core.schemas import (
    ToolInput,
    ToolResult,
    PlannerOutput,
    ToolOptions,
)
from va_mcp.endpoint_profile import EndpointProfile, SideEffect, validate_endpoint_profile
from va_mcp.core.constants import ToolStatus, Severity, Confidence, ErrorCode
from va_mcp.core.utils import utc_now_iso, build_tool_error
from va_mcp.feature_extractor.extractor import FeatureExtractor
from va_mcp.planner.scenario_planner import ScenarioPlanner


def discover_tools() -> Dict[str, Any]:
    """
    va_mcp.tools 패키지 하위 전체를 재귀 탐색하여
    BaseTool 서브클래스를 인스턴스화 후 반환합니다.
    tool_id 중복 시 즉시 예외 발생으로 알립니다.
    """
    tools: Dict[str, Any] = {}
    import va_mcp.tools as tools_pkg

    for finder, module_name, is_pkg in pkgutil.walk_packages(
        tools_pkg.__path__, tools_pkg.__name__ + "."
    ):
        module = importlib.import_module(module_name)
        for obj in module.__dict__.values():
            if isinstance(obj, type) and hasattr(obj, "tool_id") and hasattr(obj, "run"):
                inst = obj()
                tid = inst.tool_id
                if tid in tools:
                    raise RuntimeError(f"Duplicate tool_id detected: {tid}")
                tools[tid] = inst

    return tools


class Orchestrator:
    """
    Orchestrator는 두 단계로 나뉩니다.

    1. plan_endpoint: 입력 프로파일 → PlannerOutput (tool_ids, need_more_context 등)
    2. run_tools: tool_ids + 프로파일 → 각 도구 실행 후 ToolResult 리스트 반환
    """

    def __init__(self):
        # 모든 툴을 자동 탐색하여 등록
        self.tools = discover_tools()

    def plan_endpoint(self, profile: Dict[str, Any]) -> PlannerOutput:
        """
        EndpointProfile JSON 딕셔너리를 받아서
        FeatureExtractor → ScenarioPlanner 로 처리 후 PlannerOutput 반환
        """
        start_ts   = time.time()
        started_at = utc_now_iso()

        ep = EndpointProfile(**profile)
        # Feature 추출
        features = FeatureExtractor().extract(ep)
        # 시나리오 플래닝 (tool 후보 선정, need_more_context 판단)
        planner_out = ScenarioPlanner().plan(features, ep)

        # 시간 정보 추가
        planner_out.started_at  = started_at
        planner_out.ended_at    = utc_now_iso()
        planner_out.duration_ms = int((time.time() - start_ts) * 1000)
        return planner_out

    def run_tools(
        self,
        tool_ids: List[str],
        profile: Dict[str, Any],
    ) -> List[ToolResult]:
        """
        plan 단계에서 확정된 tool_ids와 프로파일을 받아
        등록된 BaseTool.run()을 순차 실행하고 결과를 수집합니다.

        need_more_context가 켜진 경우, 빈 리스트를 반환합니다.
        """
        start_ts   = time.time()
        started_at = utc_now_iso()

        ep = EndpointProfile(**profile)
        # need_more_context 인 경우 run 단계 건너뜀
        if getattr(ep, "need_more_context", False):
            return []

        # ToolInput 생성
        ti = ToolInput(
            target=ep.target,
            request=ep.request,
            auth=ep.auth,
            options=ToolOptions(
                timeout      = ep.timeout_ms,
                max_requests = ep.max_requests,
                safe_mode    = ep.safe_mode,
                extra        = ep.extra or {},
            ),
        )

        results: List[ToolResult] = []
        for tid in tool_ids:
            tool = self.tools.get(tid)
            if not tool:
                # 미등록 tool_id는 무시
                continue

            try:
                result = tool.run(ti)
            except Exception as exc:
                # Tool.run 내부 예외는 ToolResult로 감싸서 수집
                ended_at   = utc_now_iso()
                duration_ms = int((time.time() - start_ts) * 1000)
                result = ToolResult(
                    tool_id        = tid,
                    tool_name      = getattr(tool, "tool_name", tid),
                    status         = ToolStatus.ERROR.value,
                    severity       = Severity.INFO.value,
                    confidence     = Confidence.LOW.value,
                    title          = "툴 실행 오류",
                    description    = str(exc),
                    evidence       = [],
                    errors         = [build_tool_error(
                        ErrorCode.INTERNAL_ERROR.value,
                        str(exc),
                        retryable=False,
                    )],
                    started_at     = started_at,
                    ended_at       = ended_at,
                    duration_ms    = duration_ms,
                    tool_version   = getattr(tool, "tool_version", None),
                )
            results.append(result)

        return results