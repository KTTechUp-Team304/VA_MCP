from mcp.server.fastmcp import FastMCP

from va_mcp.adapters.mcp_adapter import analyze_endpoint_tool
from va_mcp.config import APP_NAME, ensure_output_dirs, init_logging
from va_mcp.registry.resource_registry import register_resources
from va_mcp.registry.tool_registry import register_tools


def create_app() -> FastMCP:
    ensure_output_dirs()
    init_logging()

    mcp = FastMCP(APP_NAME)

    def analyze_endpoint(input: dict) -> dict:
        return analyze_endpoint_tool(input)

    mcp.tool()(analyze_endpoint)

    register_tools(mcp)
    register_resources(mcp)

    return mcp