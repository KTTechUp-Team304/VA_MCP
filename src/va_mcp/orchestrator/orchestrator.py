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
from va_mcp.core.auth_provider import AuthProvider
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
    ROLE_RANK = {"guest": 0, "student": 1, "user": 1, "instructor": 2, "admin": 3}
    auth_contexts = sorted(
        [
            AuthContext(**ctx) if isinstance(ctx, dict) else ctx
            for ctx in (ep.auth_contexts or [])
        ],
        key=lambda a: ROLE_RANK.get(getattr(a, "role", ""), 0),
    )


    # O-4: path param 치환
    resolved_path = ep.path
    if ep.params:
        for key, value in ep.params.items():
            resolved_path = resolved_path.replace(f"{{{key}}}", str(value))

    # credential_fields: ep.credential_fields 우선, 없으면 auth.login.credential_fields fallback
    cred_fields = ep.credential_fields
    if not cred_fields and ep.auth and ep.auth.login and ep.auth.login.credential_fields:
        cred_fields = ep.auth.login.credential_fields

    return ToolInput(
        target=TargetInfo(
            base_url=ep.base_url,
        ),
        request=ApiRequest(
            method=ep.method,
            path=resolved_path,
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
            extra={
                "field_mapping": {
                    "credential_fields": cred_fields
                } if cred_fields else {}
            },
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

        # auth_provider로 토큰 발급 및 auth_contexts 주입
        provider: AuthProvider | None = None
        if profile.auth and profile.auth.login and profile.auth.accounts:
            provider = AuthProvider(profile.base_url, profile.auth)
            resolved = provider.provide_auth()
            if resolved:
                existing_roles = {
                    getattr(ctx, "role", None)
                    for ctx in (profile.auth_contexts or [])
                }
                merged = list(profile.auth_contexts or [])
                for ctx in resolved:
                    if ctx.role not in existing_roles:
                        merged.append(ctx)
                profile.auth_contexts = merged

        tool_input = build_tool_input(profile)

        # 브루트포스 계열 툴 전용 basic 컨텍스트 (원본 자격증명 보존)
        _CREDENTIAL_TOOLS = {"auth_bruteforce", "auth_lockout", "auth_rate_limit", "auth_enum"}
        basic_contexts = provider.provide_basic_auth() if provider else []
        cred_tool_input = ToolInput(
            target=tool_input.target,
            request=tool_input.request,
            auth=basic_contexts,
            options=tool_input.options,
        ) if basic_contexts else None

        start_ts = time.time()
        started_at = utc_now_iso()

        results: list[ToolResult] = []

        try:
            for tid in planner_output.tool_ids:
                tool = self.tools.get(tid)

                if not tool:
                    continue

                try:
                    # 브루트포스 계열은 basic 컨텍스트가 담긴 별도 ToolInput 사용
                    active_input = (
                        cred_tool_input
                        if tid in _CREDENTIAL_TOOLS and cred_tool_input
                        else tool_input
                    )
                    result: ToolResult = tool.run(active_input)

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

        finally:
            # 스캔 완료 후 토큰 폐기
            if provider:
                provider.logout_all()

        return results