from __future__ import annotations

import importlib
import pkgutil
import time
from typing import Any

from va_mcp.core.constants import (
    Confidence,
    ErrorCode,
    Severity,
    ToolStatus,
)
from va_mcp.core.planner_output import PlannerOutput
from va_mcp.core.schemas import (
    ApiRequest,
    TargetInfo,
    ToolInput,
    ToolOptions,
    ToolResult,
    AuthContext,
)
from va_mcp.core.utils import build_tool_error, utc_now_iso
from va_mcp.endpoint_profile import EndpointProfile


def discover_tools() -> dict[str, Any]:
    """
    va_mcp.tools 하위 전체를 재귀 탐색하여
    BaseTool 서브클래스를 자동 등록한다.
    """
    tools: dict[str, Any] = {}

    import va_mcp.tools as tools_pkg

    for _, module_name, _ in pkgutil.walk_packages(
        tools_pkg.__path__,
        tools_pkg.__name__ + ".",
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


def build_tool_input(ep: EndpointProfile) -> ToolInput:
    """
    EndpointProfile -> ToolInput 변환 어댑터
    """
    auth_contexts = [
        AuthContext(**ctx) if isinstance(ctx, dict) else ctx
        for ctx in (ep.auth_contexts or [])
    ]


    return ToolInput(
        target=TargetInfo(
            base_url=ep.base_url,
        ),
        request=ApiRequest(
            method=ep.method,
            path=ep.path,
            headers=ep.headers,
            query=ep.query,
            params=ep.params,
            body=ep.body,
        ),
        auth=auth_contexts,
        options=ToolOptions(
            timeout=5000,
            safe_mode=False,
            max_requests=20,
        ),
    )


class Orchestrator:
    """
    실행 전용 Orchestrator.

    책임:
      - tool registry 관리
      - ToolInput 생성
      - tool.run() 실행
      - ToolResult 수집
    """

    def __init__(self):
        self.tools = discover_tools()

    def run_tools(
        self,
        planner_output: PlannerOutput,
        profile: EndpointProfile,
    ) -> list[ToolResult]:
        """
        PlannerOutput.tool_ids 를 기반으로
        등록된 tool 을 순차 실행한다.
        """

        if planner_output.need_more_context:
            return []

        tool_input = build_tool_input(profile)

        start_ts = time.time()
        started_at = utc_now_iso()

        results: list[ToolResult] = []

        for tid in planner_output.tool_ids:
            tool = self.tools.get(tid)

            if not tool:
                continue

            try:
                result: ToolResult = tool.run(tool_input)

            except Exception as exc:
                ended_at = utc_now_iso()
                duration_ms = int((time.time() - start_ts) * 1000)

                result = ToolResult(
                    tool_id=tid,
                    tool_name=getattr(tool, "tool_name", tid),
                    status=ToolStatus.ERROR.value,
                    severity=Severity.INFO.value,
                    confidence=Confidence.LOW.value,
                    title="툴 실행 오류",
                    description=str(exc),
                    evidence=[],
                    errors=[
                        build_tool_error(
                            ErrorCode.INTERNAL_ERROR.value,
                            str(exc),
                            retryable=False,
                        )
                    ],
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    tool_version=getattr(tool, "tool_version", "0.1.0"),
                )

            results.append(result)

        return results