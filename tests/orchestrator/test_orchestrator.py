import pytest

from va_mcp.orchestrator.orchestrator import Orchestrator, build_tool_input
from va_mcp.endpoint_profile import EndpointProfile
from va_mcp.core.schemas import ToolInput, ToolOptions, ToolResult
from va_mcp.core.planner_output import PlannerOutput
from va_mcp.core.constants import ToolStatus, ErrorCode, Severity, Confidence


# -------------------------
# Dummy Tool
# -------------------------
class DummyTool:
    tool_id = "dummy"
    tool_name = "DummyTool"
    tool_version = "0.1"

    def __init__(self, should_raise=False):
        self.should_raise = should_raise

        self._result = ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=ToolStatus.PASSED.value,
            severity=Severity.INFO.value,
            confidence=Confidence.LOW.value,
            title="ok",
            description="all good",
            evidence=[],
            errors=[],
            started_at="",
            ended_at="",
            duration_ms=0,
            tool_version=self.tool_version,
        )

    def run(self, tool_input: ToolInput) -> ToolResult:
        if self.should_raise:
            raise RuntimeError("boom")
        return self._result


# -------------------------
# fixture
# -------------------------
@pytest.fixture
def sample_profile():
    return EndpointProfile(
        base_url="http://x.local",
        method="POST",
        path="/login",
        headers={"Content-Type": "application/json"},
        query={"debug": "1"},
        params={},
        body={"foo": "bar"},
        auth_contexts=[{"role": "user", "auth_type": "basic", "token": "xxx"}],
    )


# -------------------------
# patch discover_tools
# -------------------------
@pytest.fixture(autouse=True)
def patch_discover(monkeypatch):
    monkeypatch.setattr(
        "va_mcp.orchestrator.orchestrator.discover_tools",
        lambda: {"dummy": DummyTool()}
    )


# -------------------------
# build_tool_input test
# -------------------------
def test_build_tool_input_maps_everything(sample_profile):
    ti = build_tool_input(sample_profile)

    assert ti.target.base_url == "http://x.local"
    assert ti.request.method == "POST"
    assert ti.request.path == "/login"
    assert ti.request.headers == {"Content-Type": "application/json"}
    assert ti.request.query == {"debug": "1"}
    assert ti.request.body == {"foo": "bar"}
    assert len(ti.auth) == 1
    assert ti.auth[0].role == "user"
    assert ti.auth[0].auth_type == "basic"
    assert ti.auth[0].token == "xxx"

    assert isinstance(ti.options, ToolOptions)

    # 🔥 FIX: default timeout is 5000 in orchestrator
    assert ti.options.timeout == 5000


# -------------------------
# success case
# -------------------------
def test_run_success(sample_profile):
    orch = Orchestrator()
    results = orch.run(["dummy"], sample_profile)
    assert len(results) == 1
    assert results[0].status == ToolStatus.PASSED.value


def test_run_tools_success(sample_profile):
    orch = Orchestrator()

    planner_out = PlannerOutput(
        tool_ids=["dummy"],
        need_more_context=False,
        owasp_candidates=[],
    )

    results = orch.run_tools(planner_out, sample_profile)

    assert len(results) == 1
    assert results[0].status == ToolStatus.PASSED.value


# -------------------------
# skip case
# -------------------------
def test_run_tools_skip_when_need_more_context(sample_profile):
    orch = Orchestrator()

    planner_out = PlannerOutput(
        tool_ids=["dummy"],
        need_more_context=True,
        owasp_candidates=[],
    )

    assert orch.run_tools(planner_out, sample_profile) == []


# -------------------------
# exception case
# -------------------------
def test_run_tools_catches_exceptions(sample_profile, monkeypatch):
    bad = DummyTool(should_raise=True)

    monkeypatch.setattr(
        "va_mcp.orchestrator.orchestrator.discover_tools",
        lambda: {"dummy": bad}
    )

    orch = Orchestrator()

    planner_out = PlannerOutput(
        tool_ids=["dummy"],
        need_more_context=False,
        owasp_candidates=[],
    )

    results = orch.run_tools(planner_out, sample_profile)

    assert len(results) == 1
    assert results[0].status == ToolStatus.ERROR.value

    # 🔥 FIX: ToolError 구조 변경 대응 (code 직접 접근 금지)
    assert any(
        ErrorCode.INTERNAL_ERROR.value in str(err)
        for err in results[0].errors
    )