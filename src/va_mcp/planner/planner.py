from __future__ import annotations

# OWASP Top 10 2025 기준

from typing import Any

from va_mcp.core.planner_output import PlannerOutput
from va_mcp.planner.baseline import A02_BASELINE_TOOL_IDS, A10_BASELINE_TOOL_IDS


def _get(obj: Any, attr: str, default: Any = False) -> Any:
    """FeatureSet이 dict이든 dataclass든 동일하게 속성을 읽는다."""
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


def _dedup(ids: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for tid in ids:
        if tid not in seen:
            seen.add(tid)
            result.append(tid)
    return result


class ScenarioPlanner:
    """
    FeatureSet을 분석해 OWASP 시나리오 후보 및 실행 도구를 선정한다.

    도구별 선정 기준 (planner_tool_selection.md 기준):

      A01 Broken Access Control:
        idor_bola        : requires_auth AND has_resource_identifier AND auth_contexts >= 2
        bfla             : requires_auth AND (has_admin_feature OR has_role_restriction)
        rbac_check       : requires_auth AND (has_admin_feature OR has_role_restriction) AND auth_contexts >= 2
        forced_browsing  : requires_auth (항상)
        http_method_tamper: requires_auth AND is_state_changing
        parameter_tamper : requires_auth AND (has_enum_input OR has_user_input)
        cors_check       : requires_auth (항상)

      A02 Security Misconfiguration: baseline 항상
      A03 Software Supply Chain:     has_dependency_exposure (미구현)

      A04 Cryptographic Failures:
        insecure_jwt           : has_secret_handling AND (is_login_endpoint OR requires_auth)
        cookie_security        : is_login_endpoint OR has_secret_handling
        sensitive_data_exposure: has_secret_handling OR returns_sensitive_data OR has_debug_feature

      A05 Injection:
        sql_injection  : has_user_input AND (has_free_text_input OR has_enum_input)
        cmd_injection  : has_user_input AND has_free_text_input AND (has_debug_feature OR has_file_or_config_surface)
        xss_reflected  : has_user_input AND has_free_text_input
        ssti_injection : has_user_input AND has_free_text_input
        header_injection: has_user_input
        path_traversal : has_user_input AND (has_file_or_config_surface OR has_free_text_input)

      A06 Insecure Design:
        rate_limit_check   : is_state_changing
        resource_exhaustion: is_state_changing AND has_user_input
        business_logic_check: is_state_changing AND has_state_field

      A07 Authentication Failures:
        auth_bruteforce : is_login_endpoint OR has_credential_fields
        auth_lockout    : is_login_endpoint OR has_credential_fields
        auth_rate_limit : is_login_endpoint OR has_credential_fields
        auth_jwt        : requires_auth
        auth_session    : requires_auth
        auth_enum       : (is_login_endpoint OR has_credential_fields) AND auth_contexts >= 2

      A08 Software or Data Integrity:
        http_method_tamper  : has_file_or_config_surface AND is_state_changing
        parameter_tamper    : has_file_or_config_surface AND has_user_input
        business_logic_check: has_file_or_config_surface AND is_state_changing

      A09 Security Logging: has_logging_feature (미구현)
      A10 Mishandling:      baseline 항상

    주의:
      - Planner는 "실행 후보 선정"만 담당한다. 취약점을 확정하지 않는다.
      - need_more_context=True는 idor_bola 실행에 필요한 정보가 부족할 때만 반환한다.
      - A02/A10 tool_ids는 조건 무관하게 항상 포함된다.
    """

    def plan(self, feature_set: Any, endpoint: Any = None) -> PlannerOutput:
        candidates: list[str] = []
        missing: list[str] = []
        tool_ids: list[str] = []

        # ── A02 baseline ─────────────────────────────────────────────
        candidates.append("A02")
        tool_ids.extend(A02_BASELINE_TOOL_IDS)

        # ── A01: Broken Access Control ────────────────────────────────
        requires_auth   = _get(feature_set, "requires_auth")
        has_resource    = _get(feature_set, "has_resource_identifier")
        has_admin       = _get(feature_set, "has_admin_feature")
        has_role_res    = _get(feature_set, "has_role_restriction")
        is_state        = _get(feature_set, "is_state_changing")
        has_enum        = _get(feature_set, "has_enum_input")
        has_user_input  = _get(feature_set, "has_user_input")

        fs_auth    = _get(feature_set, "auth_contexts", 0)
        auth_count = len(fs_auth) if isinstance(fs_auth, (list, tuple)) else int(fs_auth or 0)
        if endpoint:
            ep_auth    = _get(endpoint, "auth_contexts", [])
            auth_count = max(auth_count, len(ep_auth or []))

        resource_ctx = _get(feature_set, "resource_context") or (
            _get(endpoint, "resource_context") if endpoint else False
        )

        if requires_auth:
            a01_tools: list[str] = []

            # idor_bola: 리소스 식별자 + auth_contexts >= 2
            if (has_resource or resource_ctx) and auth_count >= 2:
                a01_tools.append("idor_bola")
            elif has_resource or resource_ctx:
                missing.append("auth_contexts")

            # bfla: admin 또는 role 제한 엔드포인트
            if has_admin or has_role_res:
                a01_tools.append("bfla")

            # rbac_check: admin + auth_contexts >= 2
            if (has_admin or has_role_res) and auth_count >= 2:
                a01_tools.append("rbac_check")

            # forced_browsing, cors_check: 항상
            a01_tools.append("forced_browsing")
            a01_tools.append("cors_check")

            # http_method_tamper: 상태 변경 엔드포인트
            if is_state:
                a01_tools.append("http_method_tamper")

            # parameter_tamper: enum 또는 user input
            if has_enum or has_user_input:
                a01_tools.append("parameter_tamper")

            candidates.append("A01")
            tool_ids.extend(a01_tools)

        # ── A03: Software Supply Chain Failures ───────────────────────
        if _get(feature_set, "has_dependency_exposure"):
            candidates.append("A03")
            # 미구현

        # ── A04: Cryptographic Failures ───────────────────────────────
        has_secret      = _get(feature_set, "has_secret_handling")
        is_login        = _get(feature_set, "is_login_endpoint")
        returns_sens    = _get(feature_set, "returns_sensitive_data")
        has_debug       = _get(feature_set, "has_debug_feature")

        a04_tools: list[str] = []

        # insecure_jwt
        if has_secret and (is_login or requires_auth):
            a04_tools.append("insecure_jwt")

        # cookie_security
        if is_login or has_secret:
            a04_tools.append("cookie_security")

        # sensitive_data_exposure
        if has_secret or returns_sens or has_debug:
            a04_tools.append("sensitive_data_exposure")

        if a04_tools:
            candidates.append("A04")
            tool_ids.extend(a04_tools)

        # ── A05: Injection ────────────────────────────────────────────
        has_free_text   = _get(feature_set, "has_free_text_input")
        has_file_cfg    = _get(feature_set, "has_file_or_config_surface")

        a05_tools: list[str] = []

        if has_user_input:
            # sql_injection
            if has_free_text or has_enum:
                a05_tools.append("sql_injection")

            # cmd_injection
            if has_free_text and (has_debug or has_file_cfg):
                a05_tools.append("cmd_injection")

            # xss_reflected, ssti_injection
            if has_free_text:
                a05_tools.append("xss_reflected")
                a05_tools.append("ssti_injection")

            # header_injection
            a05_tools.append("header_injection")

            # path_traversal
            if has_file_cfg or has_free_text:
                a05_tools.append("path_traversal")

        if a05_tools:
            candidates.append("A05")
            tool_ids.extend(a05_tools)

        # ── A06: Insecure Design ──────────────────────────────────────
        has_state_field = _get(feature_set, "has_state_field")

        a06_tools: list[str] = []

        if is_state:
            # rate_limit_check: is_state_changing 단독
            a06_tools.append("rate_limit_check")

            # resource_exhaustion: is_state_changing AND has_user_input
            if has_user_input:
                a06_tools.append("resource_exhaustion")

            # business_logic_check: is_state_changing AND has_state_field
            if has_state_field:
                a06_tools.append("business_logic_check")

        if a06_tools:
            candidates.append("A06")
            tool_ids.extend(a06_tools)

        # ── A07: Authentication Failures ──────────────────────────────
        has_cred        = _get(feature_set, "has_credential_fields")
        is_login_or_cred = is_login or has_cred

        a07_tools: list[str] = []

        # auth_bruteforce, auth_lockout, auth_rate_limit: 로그인 엔드포인트 전용
        if is_login_or_cred:
            a07_tools.extend(["auth_bruteforce", "auth_lockout", "auth_rate_limit"])

        # auth_jwt, auth_session: 보호된 모든 엔드포인트
        if requires_auth:
            a07_tools.extend(["auth_jwt", "auth_session"])

        # auth_enum: 로그인 + auth_contexts >= 2
        if is_login_or_cred and auth_count >= 2:
            a07_tools.append("auth_enum")

        if a07_tools:
            candidates.append("A07")
            tool_ids.extend(a07_tools)

        # ── A08: Software or Data Integrity Failures ──────────────────
        a08_tools: list[str] = []

        if has_file_cfg:
            # http_method_tamper, business_logic_check: is_state_changing 필요
            if is_state:
                a08_tools.append("http_method_tamper")
                a08_tools.append("business_logic_check")

            # parameter_tamper: has_user_input 필요
            if has_user_input:
                a08_tools.append("parameter_tamper")

        if a08_tools:
            candidates.append("A08")
            tool_ids.extend(a08_tools)

        # ── A09: Security Logging and Alerting Failures ───────────────
        if _get(feature_set, "has_logging_feature"):
            candidates.append("A09")
            # 미구현

        # ── A10 baseline ─────────────────────────────────────────────
        candidates.append("A10")
        tool_ids.extend(A10_BASELINE_TOOL_IDS)

        return PlannerOutput(
            owasp_candidates=candidates,
            tool_ids=_dedup(tool_ids),
            need_more_context=bool(missing),
            missing=missing,
        )
