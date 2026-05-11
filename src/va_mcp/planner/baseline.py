from __future__ import annotations

# OWASP Top 10 2025 기준

A02_BASELINE_TOOL_IDS: list[str] = [  # Security Misconfiguration — baseline 항상
    "security_headers",
    "cors_misconfiguration",
    "error_info_exposure",
    "sensitive_path",
    "directory_listing",
    "debug_endpoint",
    "default_config",
]

A04_BASELINE_TOOL_IDS: list[str] = [  # Cryptographic Failures — baseline 항상
    "insecure_jwt",
    "cookie_security",
    "sensitive_data_exposure",
]

A10_BASELINE_TOOL_IDS: list[str] = [  # Mishandling of Exceptional Conditions — baseline 항상
    "stack_trace_exposure",
    "timeout_handling",
    "error_code_consistency",
    "retry_handling",
    "malformed_input",
]
