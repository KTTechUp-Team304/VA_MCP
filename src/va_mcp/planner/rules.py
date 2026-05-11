from __future__ import annotations

from va_mcp.planner.baseline import A02_BASELINE_TOOL_IDS, A10_BASELINE_TOOL_IDS

OWASP_TOOL_MAP: dict[str, list[str]] = {
    "A01": [
        "idor_bola",
        "bfla",
        "rbac_check",
        "forced_browsing",
        "http_method_tamper",
        "parameter_tamper",
        "cors_check",
    ],
    "A02": list(A02_BASELINE_TOOL_IDS),
    "A03": [
        "sql_injection",
        "cmd_injection",
        "xss_reflected",
        "ssti_injection",
        "header_injection",
        "path_traversal",
    ],
    "A04": [
        "rate_limit_check",
        "resource_exhaustion",
        "business_logic_check",
    ],
    "A05": [
        "security_headers",
        "cors_misconfiguration",
        "error_info_exposure",
    ],
    "A06": [
        "http_method_tamper",
        "parameter_tamper",
        "business_logic_check",
    ],
    "A07": [
        "auth_bruteforce",
        "auth_lockout",
        "auth_rate_limit",
        "auth_jwt",
        "auth_session",
        "auth_enum",
    ],
    "A08": [
        "sensitive_path",
        "directory_listing",
        "debug_endpoint",
        "default_config",
    ],
    "A09": [],
    "A10": list(A10_BASELINE_TOOL_IDS),
}
