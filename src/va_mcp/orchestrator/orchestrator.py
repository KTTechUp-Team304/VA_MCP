from __future__ import annotations

import importlib
import pkgutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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

    extra: dict = {}
    if cred_fields:
        extra["field_mapping"] = {"credential_fields": cred_fields}
    if ep.resource_context:
        extra["resource_context"] = ep.resource_context

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
            extra=extra,
        ),
    )


_CREDENTIAL_TOOLS = frozenset(
    {"auth_bruteforce", "auth_lockout", "auth_rate_limit", "auth_enum"}
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

    def _merge_auth_contexts(self, profile: EndpointProfile) -> AuthProvider | None:
        """auth_provider로 토큰 발급 후 profile.auth_contexts에 병합한다."""
        if not (profile.auth and profile.auth.login and profile.auth.accounts):
            return None

        provider = AuthProvider(profile.base_url, profile.auth)
        resolved = provider.provide_auth()
        if resolved:
            existing_roles = {
                getattr(ctx, "role", None) for ctx in (profile.auth_contexts or [])
            }
            merged = list(profile.auth_contexts or [])
            for ctx in resolved:
                if ctx.role not in existing_roles:
                    merged.append(ctx)
            profile.auth_contexts = merged
        return provider

    def _run_single_tool(
        self,
        tid: str,
        tool_input: ToolInput,
        cred_tool_input: ToolInput | None,
        start_ts: float,
        started_at: str,
    ) -> ToolResult | None:
        """단일 툴을 실행하고 결과를 반환한다. ThreadPoolExecutor에서 호출된다."""
        tool = self.tools.get(tid)
        if not tool:
            return None

        try:
            active_input = (
                cred_tool_input
                if tid in _CREDENTIAL_TOOLS and cred_tool_input
                else tool_input
            )
            return tool.run(active_input)
        except Exception as exc:
            ended_at = utc_now_iso()
            duration_ms = int((time.time() - start_ts) * 1000)
            return ToolResult(
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

    def run(
        self,
        tool_ids: list[str],
        profile: EndpointProfile,
        *,
        provider: AuthProvider | None = None,
        logout_when_done: bool = True,
    ) -> list[ToolResult]:
        """
        tool_ids에 해당하는 등록 tool을 실행한다.

        - 일반 툴: ThreadPoolExecutor로 병렬 실행 (성능 최적화)
        - _CREDENTIAL_TOOLS: 순차 실행 (서로 간섭 방지)

        ScenarioRunner가 OWASP 카테고리별로 호출한다.
        provider를 넘기면 인증 컨텍스트 병합·로그아웃을 호출자가 제어할 수 있다.
        """
        own_provider = provider
        if own_provider is None:
            own_provider = self._merge_auth_contexts(profile)

        tool_input = build_tool_input(profile)
        basic_contexts = own_provider.provide_basic_auth() if own_provider else []
        cred_tool_input = (
            ToolInput(
                target=tool_input.target,
                request=tool_input.request,
                auth=basic_contexts,
                options=tool_input.options,
            )
            if basic_contexts
            else None
        )

        start_ts = time.time()
        started_at = utc_now_iso()
        results: list[ToolResult] = []

        # 툴을 병렬 실행 대상과 순차 실행 대상으로 분리
        parallel_ids = [tid for tid in tool_ids if tid not in _CREDENTIAL_TOOLS]
        sequential_ids = [tid for tid in tool_ids if tid in _CREDENTIAL_TOOLS]

        try:
            # 일반 툴: 병렬 실행 (max_workers=8로 백서버 부하 조절)
            if parallel_ids:
                with ThreadPoolExecutor(max_workers=8) as executor:
                    futures = {
                        executor.submit(
                            self._run_single_tool,
                            tid,
                            tool_input,
                            cred_tool_input,
                            start_ts,
                            started_at,
                        ): tid
                        for tid in parallel_ids
                    }
                    for future in as_completed(futures):
                        result = future.result()
                        if result is not None:
                            results.append(result)

            # 크리덴셜 툴: 순차 실행 (간섭 방지)
            for tid in sequential_ids:
                result = self._run_single_tool(
                    tid, tool_input, cred_tool_input, start_ts, started_at
                )
                if result is not None:
                    results.append(result)

        finally:
            if logout_when_done and own_provider is not None and provider is None:
                own_provider.logout_all()

        return results

    def run_tools(
        self,
        planner_output: PlannerOutput,
        profile: EndpointProfile,
    ) -> list[ToolResult]:
        """PlannerOutput.tool_ids 기준으로 tool을 한 번에 실행한다 (하위 호환)."""
        if planner_output.need_more_context:
            return []

        provider = self._merge_auth_contexts(profile)
        try:
            return self.run(
                planner_output.tool_ids,
                profile,
                provider=provider,
                logout_when_done=False,
            )
        finally:
            if provider:
                provider.logout_all()