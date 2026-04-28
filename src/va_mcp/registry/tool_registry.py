"""
Tool 자동 탐지 및 등록 모듈.

tools/ 폴더에 BaseTool 서브클래스를 추가하기만 하면 자동으로 MCP에 등록된다.
이 파일을 직접 수정할 필요가 없다.

수동 등록 대상 (BaseTool 미사용):
  - ping           (health.py)
  - list_supported_checks (scan_registry.py)
"""

import importlib
import inspect
import pkgutil

import va_mcp.tools as _tools_pkg
from mcp.server.fastmcp import FastMCP

from va_mcp.core import BaseTool
from va_mcp.tools.health import ping
from va_mcp.tools.scan_registry import list_supported_checks

# 자동 탐지에서 제외할 모듈 접두사 (언더스코어 시작 파일)
_SKIP_PREFIX = "_"


def _discover_tools() -> list[BaseTool]:
    """tools/ 패키지에서 BaseTool 서브클래스를 자동으로 찾아 인스턴스 목록을 반환한다."""
    discovered: list[BaseTool] = []

    for _, modname, _ in pkgutil.iter_modules(_tools_pkg.__path__):
        if modname.startswith(_SKIP_PREFIX):
            continue

        module = importlib.import_module(f"va_mcp.tools.{modname}")

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseTool)
                and obj is not BaseTool
                and hasattr(obj, "tool_id")
            ):
                discovered.append(obj())

    return discovered


def register_tools(mcp: FastMCP) -> None:
    mcp.tool()(ping)
    mcp.tool()(list_supported_checks)

    for tool in _discover_tools():
        mcp.tool(name=tool.tool_id)(tool.run)