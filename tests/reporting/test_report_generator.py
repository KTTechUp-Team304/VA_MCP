"""취약점 분석 리포트 생성기 테스트."""

from pathlib import Path

import pytest

from va_mcp.core.constants import Confidence, Severity, ToolStatus
from va_mcp.core.endpoint_report import EndpointReport
from va_mcp.core.scenario_result import ScenarioResult
from va_mcp.core.schemas import ToolResult
from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.reporting.report_generator import (
    build_report_basename,
    endpoint_report_to_dict,
    flatten_tool_results,
    generate_markdown,
    write_vulnerability_report,
)


def _profile() -> EndpointProfile:
    return EndpointProfile(
        base_url="https://api.example.com",
        method="GET",
        path="/api/users/1",
    )


def _result(
    tool_id: str,
    *,
    status: str = ToolStatus.PASSED.value,
    severity: str = Severity.INFO.value,
    title: str = "ok",
) -> ToolResult:
    return ToolResult(
        tool_id=tool_id,
        tool_name=tool_id,
        status=status,
        severity=severity,
        confidence=Confidence.LOW.value,
        title=title,
    )


def test_flatten_dedupes_by_tool_id_prefers_vulnerable():
    report = EndpointReport(
        profile=_profile(),
        scenario_results=[
            ScenarioResult(
                owasp="A01",
                tool_results=[_result("idor_bola", status=ToolStatus.PASSED.value)],
            ),
            ScenarioResult(
                owasp="A08",
                tool_results=[
                    _result(
                        "idor_bola",
                        status=ToolStatus.VULNERABLE.value,
                        severity=Severity.HIGH.value,
                        title="IDOR",
                    )
                ],
            ),
        ],
    )
    flat = flatten_tool_results(report)
    assert len(flat) == 1
    assert flat[0].status == ToolStatus.VULNERABLE.value


def test_generate_markdown_groups_by_owasp():
    report = EndpointReport(
        profile=_profile(),
        scenario_results=[
            ScenarioResult(
                owasp="A05",
                tool_results=[
                    _result(
                        "sql_injection",
                        status=ToolStatus.VULNERABLE.value,
                        severity=Severity.HIGH.value,
                        title="SQLi suspected",
                    )
                ],
                poc="[A05] 취약점 1건 발견",
            ),
        ],
    )
    md = generate_markdown(report, run_id="test-run")
    assert "A05 Injection" in md
    assert "sql_injection" in md
    assert "## 발견 사항" in md
    assert "<details>" not in md
    assert "🔴" not in md


def test_build_report_basename_from_endpoint_and_time():
    profile = EndpointProfile(
        base_url="http://localhost:4000",
        method="GET",
        path="/api/admin",
    )
    stem = build_report_basename(
        profile,
        generated_at="2026-05-20T03:45:46.705663Z",
        run_id="2026-05-20T03-45-46_05f3f6",
    )
    assert stem.startswith("GET_api_admin_2026-05-20T03-45-46")
    assert stem.endswith("05f3f6")


def test_write_report_creates_files(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "va_mcp.reporting.report_generator.REPORTS_OUTPUT_DIR",
        tmp_path,
    )
    report = EndpointReport(
        profile=_profile(),
        scenario_results=[],
        generated_at="2026-05-20T12:00:00Z",
    )
    paths = write_vulnerability_report(report, run_id="2026-05-20T12-00-00_abc123", run_dir=tmp_path / "run")
    assert Path(paths["report_md"]).exists()
    assert Path(paths["report_json"]).exists()
    assert paths["report_basename"].startswith("GET_api_users_1_")
    assert paths["report_md"].endswith(".md")
    assert Path(paths["run_report_md"]).exists()

    data = endpoint_report_to_dict(report)
    assert data["endpoint"]["method"] == "GET"
    assert data["summary"]["tools_run"] == 0
