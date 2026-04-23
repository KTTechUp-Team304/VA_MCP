from mcp.server.fastmcp import FastMCP

from va_mcp.config import APP_NAME, ensure_output_dirs
from va_mcp.registry.tool_registry import register_tools
from va_mcp.registry.resource_registry import register_resources


def create_app() -> FastMCP:
    ensure_output_dirs()

    mcp = FastMCP(APP_NAME)

    register_tools(mcp)
    register_resources(mcp)

    return mcp