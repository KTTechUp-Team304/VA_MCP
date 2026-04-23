from va_mcp.resources.supported_checks import SUPPORTED_CHECKS


def list_supported_checks() -> dict:
    """현재 지원 예정인 점검 항목 목록을 반환한다."""
    return {
        "checks": SUPPORTED_CHECKS["checks"],
        "status": "stub"
    }