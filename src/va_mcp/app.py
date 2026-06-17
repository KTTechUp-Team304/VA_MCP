from mcp.server.fastmcp import FastMCP

from va_mcp.adapters.mcp_adapter import analyze_endpoint_tool
from va_mcp.services.endpoint_analysis_ai import analyze_endpoint_with_ai as _analyze_endpoint_with_ai
from va_mcp.services.endpoint_analysis_deep import (
    analyze_endpoint_deep as _analyze_endpoint_deep,
    get_deep_scan_status as _get_deep_scan_status,
)
from va_mcp.config import APP_NAME, ensure_output_dirs, init_logging
from va_mcp.registry.resource_registry import register_resources
from va_mcp.registry.tool_registry import register_tools


def create_app() -> FastMCP:
    ensure_output_dirs()
    init_logging()

    mcp = FastMCP(APP_NAME)

    def analyze_endpoint(input: dict) -> dict:
        """규칙 기반 OWASP 취약점 스캔. 엔드포인트 프로파일을 입력받아 Feature 추출 → 시나리오 플래닝 → 도구 자동 실행 → 결과 반환. 빠르고 안정적이며 별도 AI API 키 불필요. 일반 분석, 기본 스캔, 빠른 스캔 요청 시 사용."""
        return analyze_endpoint_tool(input)

    mcp.tool()(analyze_endpoint)

    def analyze_endpoint_with_ai(input: dict) -> dict:
        """규칙 기반 스캔 + AI 2차 검토. 1단계로 규칙 기반 스캔을 수행한 뒤 AI가 누락된 취약점을 검토하고 해당 도구를 재실행해 보완. AI 보조 분석, AI 검토 요청 시 사용."""
        return _analyze_endpoint_with_ai(input)

    mcp.tool()(analyze_endpoint_with_ai)

    def analyze_endpoint_deep(input: dict) -> dict:
        """딥 모드 AI 에이전트 취약점 분석. OpenAI가 에이전트로서 직접 HTTP 프로브를 동적으로 수행하며 OWASP 취약점을 처음부터 끝까지 자율 분석. 딥 모드, 딥 스캔, 정밀 분석, deep mode, deep scan 요청 시 사용. OPENAI_API_KEY 필요."""
        return _analyze_endpoint_deep(input)

    mcp.tool()(analyze_endpoint_deep)

    def get_deep_scan_status(run_id: str) -> dict:
        """딥 스캔 결과 조회. analyze_endpoint_deep이 반환한 run_id로 완료 여부와 결과를 확인한다. status가 completed면 findings에 결과가 있고, running이면 아직 진행 중이다."""
        return _get_deep_scan_status(run_id)

    mcp.tool()(get_deep_scan_status)

    register_tools(mcp)
    register_resources(mcp)

    return mcp