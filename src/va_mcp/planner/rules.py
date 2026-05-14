from __future__ import annotations

# OWASP Top 10 2025 기준
# 카테고리별 도구 목록 상수 테이블 (참조용)
# 실제 도구 선정은 planner.py의 개별 조건 로직에서 수행한다.

from va_mcp.planner.baseline import A02_BASELINE_TOOL_IDS, A10_BASELINE_TOOL_IDS

OWASP_TOOL_MAP: dict[str, list[str]] = {
    "A01": [  # Broken Access Control
        "idor_bola",
        "bfla",
        "rbac_check",
        "forced_browsing",
        "http_method_tamper",
        "parameter_tamper",
        "cors_check",
    ],
    "A02": list(A02_BASELINE_TOOL_IDS),   # Security Misconfiguration
    "A03": [],                             # Software Supply Chain Failures (미구현)
    "A04": [  # Cryptographic Failures
        "insecure_jwt",
        "cookie_security",
        "sensitive_data_exposure",
    ],
    "A05": [  # Injection
        "sql_injection",
        "cmd_injection",
        "xss_reflected",
        "ssti_injection",
        "header_injection",
        "path_traversal",
    ],
    "A06": [  # Insecure Design
        "rate_limit_check",
        "resource_exhaustion",
        "business_logic_check",
    ],
    "A07": [  # Authentication Failures
        "auth_bruteforce",
        "auth_lockout",
        "auth_rate_limit",
        "auth_jwt",
        "auth_session",
        "auth_enum",
    ],
    "A08": [  # Software or Data Integrity Failures
        "http_method_tamper",
        "parameter_tamper",
        "business_logic_check",
    ],
    "A09": [],                             # Security Logging and Alerting Failures (미구현)
    "A10": list(A10_BASELINE_TOOL_IDS),   # Mishandling of Exceptional Conditions
}
