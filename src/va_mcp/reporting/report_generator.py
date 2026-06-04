from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any
from va_mcp.config import REPORTS_OUTPUT_DIR
from va_mcp.core.constants import Severity, ToolStatus
from va_mcp.core.endpoint_report import EndpointReport
from va_mcp.core.schemas import ToolResult
from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile

OWASP_LABELS: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

_SEVERITY_RANK: dict[str, int] = {
    Severity.CRITICAL.value: 5,
    Severity.HIGH.value: 4,
    Severity.MEDIUM.value: 3,
    Severity.LOW.value: 2,
    Severity.INFO.value: 1,
}

_STATUS_RANK: dict[str, int] = {
    ToolStatus.VULNERABLE.value: 4,
    ToolStatus.ERROR.value: 3,
    ToolStatus.PASSED.value: 2,
    ToolStatus.SKIPPED.value: 1,
}


def _result_priority(result: ToolResult) -> tuple[int, int]:
    return (
        _STATUS_RANK.get(result.status, 0),
        _SEVERITY_RANK.get(result.severity, 0),
    )


def flatten_tool_results(report: EndpointReport) -> list[ToolResult]:
    """시나리오별 중복 실행 결과를 tool_id 기준으로 병합한다 (더 심각한 결과 우선)."""
    by_id: dict[str, ToolResult] = {}
    for scenario in report.scenario_results:
        for result in scenario.tool_results:
            existing = by_id.get(result.tool_id)
            if existing is None or _result_priority(result) > _result_priority(existing):
                by_id[result.tool_id] = result
    merged = list(by_id.values())
    merged.sort(
        key=lambda r: (-_result_priority(r)[0], -_result_priority(r)[1], r.tool_id),
    )
    return merged


def _owasp_heading(code: str) -> str:
    label = OWASP_LABELS.get(code, code)
    return f"{code} {label}"


def _label(value: str) -> str:
    """enum 문자열(ToolStatus.VULNERABLE)을 표시용 라벨(vulnerable)로 정규화한다."""
    if not value:
        return "-"
    if "." in value:
        return value.rsplit(".", 1)[-1].lower()
    return value.lower()


def _status_counts(tool_results: list[ToolResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for tr in tool_results:
        key = _label(tr.status)
        counts[key] = counts.get(key, 0) + 1
    return counts


def build_report_basename(
    profile: EndpointProfile,
    *,
    generated_at: str,
    run_id: str = "",
) -> str:
    """
    리포트 파일명 stem: {METHOD}_{path}_{작동시각}.

    동일 시각·엔드포인트 재실행 시 run_id 접미사로 충돌을 피한다.
    """
    method = (profile.method or "GET").upper()
    path_part = profile.path.strip("/").replace("/", "_") or "root"

    endpoint_slug = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        f"{method}_{path_part}",
    )
    endpoint_slug = re.sub(r"_+", "_", endpoint_slug).strip("_")

    time_slug = generated_at.replace(":", "-").split(".")[0].rstrip("Z")
    stem = f"{endpoint_slug}_{time_slug}"

    if run_id:
        suffix = run_id.rsplit("_", 1)[-1]
        if suffix and not stem.endswith(suffix):
            stem = f"{stem}_{suffix}"

    max_len = 180
    if len(stem) > max_len:
        stem = stem[:max_len].rstrip("_")
    return stem


def _resolve_report_path(directory: Path, stem: str, suffix: str) -> Path:
    path = directory / f"{stem}{suffix}"
    if not path.exists():
        return path
    n = 2
    while True:
        candidate = directory / f"{stem}_{n}{suffix}"
        if not candidate.exists():
            return candidate
        n += 1


def _profile_summary(profile: EndpointProfile) -> dict[str, Any]:
    return {
        "base_url": profile.base_url,
        "method": profile.method,
        "path": profile.path,
        "side_effect": profile.side_effect,
    }


def endpoint_report_to_dict(report: EndpointReport) -> dict[str, Any]:
    """EndpointReport를 JSON 직렬화 가능한 dict로 변환한다."""
    tool_results = flatten_tool_results(report)
    status_counts: dict[str, int] = {}
    for tr in tool_results:
        status_counts[tr.status] = status_counts.get(tr.status, 0) + 1

    vulnerable = [
        asdict(tr) for tr in tool_results if tr.status == ToolStatus.VULNERABLE.value
    ]

    scenarios = []
    for sr in report.scenario_results:
        scenarios.append(
            {
                "owasp": sr.owasp,
                "owasp_label": _owasp_heading(sr.owasp),
                "tool_ids": [tr.tool_id for tr in sr.tool_results],
                "poc": sr.poc,
                "tool_results": [asdict(tr) for tr in sr.tool_results],
            }
        )

    return {
        "generated_at": report.generated_at,
        "need_more_context": report.need_more_context,
        "missing": report.missing,
        "endpoint": _profile_summary(report.profile),
        "scenarios": scenarios,
        "tool_results": [asdict(tr) for tr in tool_results],
        "summary": {
            "tools_run": len(tool_results),
            "status_counts": status_counts,
            "vulnerable_count": len(vulnerable),
            "vulnerable_findings": [
                {
                    "tool_id": v["tool_id"],
                    "tool_name": v["tool_name"],
                    "severity": v["severity"],
                    "title": v["title"],
                }
                for v in vulnerable
            ],
        },
    }


def _append_findings_table(lines: list[str], findings: list[ToolResult]) -> None:
    lines.extend(["| 위험도 | 도구 | 제목 |", "| --- | --- | --- |"])
    for tr in findings:
        lines.append(
            f"| {_label(tr.severity).upper()} | `{tr.tool_id}` | {tr.title or '-'} |"
        )


def _append_status_table(lines: list[str], counts: dict[str, int]) -> None:
    lines.extend(["| 상태 | 건수 |", "| --- | ---: |"])
    for status in ("vulnerable", "error", "passed", "skipped"):
        if status in counts:
            lines.append(f"| {status} | {counts[status]} |")
    for status, n in sorted(counts.items()):
        if status not in ("vulnerable", "error", "passed", "skipped"):
            lines.append(f"| {status} | {n} |")


def _append_tool_detail(lines: list[str], tr: ToolResult) -> None:
    lines.append(f"#### `{tr.tool_id}` — {tr.title or tr.tool_name}")
    lines.append("")
    lines.append(
        f"- 결과: {_label(tr.status)} · 위험도: {_label(tr.severity)} · "
        f"신뢰도: {_label(tr.confidence)}"
    )
    if tr.description:
        lines.append(f"- 설명: {tr.description}")
    if tr.recommendation:
        lines.append(f"- 권고: {tr.recommendation}")
    lines.append("")


def generate_markdown(report: EndpointReport, *, run_id: str = "") -> str:
    """OWASP 항목별로 그룹화한 Markdown 취약점 분석 리포트를 생성한다."""
    profile = report.profile
    endpoint = f"{profile.method} {profile.base_url.rstrip('/')}{profile.path}"

    lines: list[str] = [
        "# 취약점 분석 리포트",
        "",
        f"**대상** {endpoint}  ",
        f"**생성 시각** {report.generated_at}  ",
    ]
    if run_id:
        lines.append(f"**Run ID** `{run_id}`  ")
    lines.append("")

    if report.need_more_context:
        lines.extend(
            [
                "## 추가 컨텍스트 필요",
                "",
                "점검을 실행하지 않았습니다. 아래 항목을 보완한 뒤 다시 분석하세요.",
                "",
            ]
        )
        for key in report.missing:
            lines.append(f"- `{key}`")
        lines.append("")
        return "\n".join(lines)

    tool_results = flatten_tool_results(report)
    counts = _status_counts(tool_results)
    vulnerable = [
        tr for tr in tool_results if _label(tr.status) == ToolStatus.VULNERABLE.value
    ]

    lines.extend(["## 요약", ""])
    _append_status_table(lines, counts)
    lines.extend(["", f"실행 도구: {len(tool_results)}개", ""])

    if vulnerable:
        lines.extend(["## 발견 사항", ""])
        _append_findings_table(
            lines,
            sorted(
                vulnerable,
                key=lambda r: (-_SEVERITY_RANK.get(_label(r.severity), 0), r.tool_id),
            ),
        )
        lines.append("")

    lines.extend(["## OWASP별 점검 결과", ""])

    for sr in report.scenario_results:
        lines.append(f"### {_owasp_heading(sr.owasp)}")
        lines.append("")

        if not sr.tool_results:
            lines.append("실행된 도구 없음.")
            lines.append("")
            continue

        issues = [
            tr
            for tr in sr.tool_results
            if _label(tr.status) in (ToolStatus.VULNERABLE.value, ToolStatus.ERROR.value)
        ]
        ok = [
            tr
            for tr in sr.tool_results
            if _label(tr.status) in (ToolStatus.PASSED.value, ToolStatus.SKIPPED.value)
        ]

        if issues:
            lines.append("**조치 필요**")
            lines.append("")
            for tr in sorted(
                issues,
                key=lambda r: (-_result_priority(r)[0], -_result_priority(r)[1], r.tool_id),
            ):
                _append_tool_detail(lines, tr)

        if ok:
            names = ", ".join(f"`{tr.tool_id}`" for tr in ok)
            lines.append(f"**통과** ({len(ok)}): {names}")
            lines.append("")

        if sr.poc and issues:
            lines.append("**재현 요약**")
            lines.append("")
            lines.append("```")
            lines.append(sr.poc.strip())
            lines.append("```")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_vulnerability_report(
    report: EndpointReport,
    *,
    run_id: str,
    run_dir: Path | None = None,
) -> dict[str, str]:
    """
    Markdown·JSON 리포트를 저장소 루트 reports/ 및 (선택) run 폴더에 저장한다.

    Returns:
        저장된 파일 경로 dict (report_md, report_json, …)
    """
    REPORTS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    report_dict = endpoint_report_to_dict(report)
    markdown = generate_markdown(report, run_id=run_id)

    stem = build_report_basename(
        report.profile,
        generated_at=report.generated_at,
        run_id=run_id,
    )
    json_path = _resolve_report_path(REPORTS_OUTPUT_DIR, stem, ".json")
    md_path = _resolve_report_path(REPORTS_OUTPUT_DIR, stem, ".md")

    json_path.write_text(
        json.dumps(report_dict, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    md_path.write_text(markdown, encoding="utf-8")

    paths: dict[str, str] = {
        "report_basename": stem,
        "report_json": str(json_path),
        "report_md": str(md_path),
    }

    if run_dir is not None:
        run_dir.mkdir(parents=True, exist_ok=True)
        run_json = run_dir / "05_vulnerability_report.json"
        run_md = run_dir / "05_vulnerability_report.md"
        run_json.write_text(json_path.read_text(encoding="utf-8"), encoding="utf-8")
        run_md.write_text(markdown, encoding="utf-8")
        paths["run_report_json"] = str(run_json)
        paths["run_report_md"] = str(run_md)

    return paths
