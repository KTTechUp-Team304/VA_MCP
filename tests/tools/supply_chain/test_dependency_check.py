from __future__ import annotations

import pytest

from va_mcp.core.constants import Confidence, Severity, ToolStatus
from va_mcp.core.schemas import ApiRequest, TargetInfo, ToolInput, ToolOptions
from va_mcp.tools.supply_chain.dependency_check import DependencyCheck


@pytest.fixture
def tool() -> DependencyCheck:
    return DependencyCheck()


def _make_input(resource_context: dict | None = None) -> ToolInput:
    """resource_context를 options.extra에 담아 ToolInput을 생성한다."""
    extra: dict = {}
    if resource_context is not None:
        extra["resource_context"] = resource_context
    return ToolInput(
        target=TargetInfo(base_url="http://localhost:4000"),
        request=ApiRequest(method="GET", path="/"),
        options=ToolOptions(extra=extra),
    )


# ------------------------------------------------------------------ #
# PASSED — 알려진 취약 버전 아님
# ------------------------------------------------------------------ #

def test_passed(tool: DependencyCheck) -> None:
    """lodash 4.17.21 (취약 버전 경계값) → PASSED."""
    inp = _make_input({
        "runtime": "node",
        "dependencies": {"lodash": "4.17.21"},  # < 4.17.21 조건 불충족
    })
    result = tool.run(inp)

    assert result.status == ToolStatus.PASSED
    assert result.evidence == []


# ------------------------------------------------------------------ #
# VULNERABLE — 알려진 CVE 버전 탐지
# ------------------------------------------------------------------ #

def test_vulnerable(tool: DependencyCheck) -> None:
    """lodash 4.17.11 (< 4.17.21) → VULNERABLE HIGH + evidence 검증."""
    inp = _make_input({
        "runtime": "node",
        "dependencies": {"lodash": "4.17.11"},  # CVE-2019-10744 범위
    })
    result = tool.run(inp)

    assert result.status == ToolStatus.VULNERABLE
    assert result.severity == Severity.HIGH
    assert result.confidence == Confidence.HIGH
    assert len(result.evidence) == 1

    ev = result.evidence[0]
    assert ev.request["package"] == "lodash"
    assert ev.request["version"] == "4.17.11"
    assert ev.request["cve"] == "CVE-2019-10744"
    assert ev.response_status == 0  # HTTP 요청 없음


# ------------------------------------------------------------------ #
# ERROR — 잘못된 버전 형식
# ------------------------------------------------------------------ #

def test_error(tool: DependencyCheck) -> None:
    """lodash에 유효하지 않은 버전 형식 → ERROR, severity=INFO, confidence=LOW."""
    inp = _make_input({
        "runtime": "node",
        "dependencies": {"lodash": "not-a-version"},
    })
    result = tool.run(inp)

    assert result.status == ToolStatus.ERROR
    assert result.severity == Severity.INFO
    assert result.confidence == Confidence.LOW
    assert len(result.errors) > 0


# ------------------------------------------------------------------ #
# SKIPPED — dependencies 키 없음
# ------------------------------------------------------------------ #

def test_skipped(tool: DependencyCheck) -> None:
    """resource_context에 dependencies 키 없음 → SKIPPED, evidence=[]."""
    inp = _make_input({"runtime": "node"})  # dependencies 키 의도적으로 누락
    result = tool.run(inp)

    assert result.status == ToolStatus.SKIPPED
    assert result.evidence == []
