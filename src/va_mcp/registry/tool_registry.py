from mcp.server.fastmcp import FastMCP

from va_mcp.tools.health import ping
from va_mcp.tools.scan_registry import list_supported_checks


def register_tools(mcp: FastMCP) -> None:
    mcp.tool()(ping)
    mcp.tool()(list_supported_checks)