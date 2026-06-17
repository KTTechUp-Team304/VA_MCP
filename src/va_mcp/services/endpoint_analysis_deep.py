from __future__ import annotations

import json
import logging
import threading
from typing import Any

from va_mcp.config import REPORTS_OUTPUT_DIR
from va_mcp.core.constants import Severity
from va_mcp.endpoint_profile import EndpointProfileValidationError, parse_endpoint_profile
from va_mcp.observability import RunRecorder
from va_mcp.planner.ai_deep_advisor import run_deep_scan
from va_mcp.reporting.report_generator import build_report_basename
from va_mcp.core.utils import utc_now_iso

logger = logging.getLogger(__name__)

# 딥 스캔 결과 저장소 (프로세스 생명주기 동안 유지)
_SCAN_STORE: dict[str, dict[str, Any]] = {}
_SCAN_LOCK = threading.Lock()

_SEVERITY_RANK: dict[str, int] = {
    Severity.CRITICAL.value: 5,
    Severity.HIGH.value: 4,
    Severity.MEDIUM.value: 3,
    Severity.LOW.value: 2,
    Severity.INFO.value: 1,
}


def _write_deep_report(
    profile: Any,
    dynamic_context: dict,
    findings: list[dict],
    *,
    run_id: str,
    generated_at: str,
    run_dir: Any = None,
) -> dict[str, str]:
    """딥 스캔 결과를 Markdown + JSON으로 저장한다. 기존 report 파일명 규칙을 따른다."""
    REPORTS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    stem = build_report_basename(profile, generated_at=generated_at, run_id=run_id)
    # "DEEP_" 접두사로 일반 스캔 결과와 구분
    stem = f"DEEP_{stem}"

    md_path = REPORTS_OUTPUT_DIR / f"{stem}.md"
    json_path = REPORTS_OUTPUT_DIR / f"{stem}.json"

    # ── Markdown ───────────────────────────────────────────────────────────────
    endpoint = f"{profile.method} {profile.base_url.rstrip('/')}{profile.path}"
    vulnerable = [f for f in findings if f.get("status") == "VULNERABLE"]
    lines: list[str] = [
        "# 딥 스캔 취약점 분석 리포트",
        "",
        f"**대상** {endpoint}  ",
        f"**생성 시각** {generated_at}  ",
        f"**Run ID** `{run_id}`  ",
        f"**모드** Deep (AI 에이전트 직접 프로브)  ",
        "",
        "## 요약",
        "",
        f"| 항목 | 값 |",
        f"| --- | --- |",
        f"| 전체 발견 | {len(findings)} |",
        f"| VULNERABLE | {len(vulnerable)} |",
        f"| 기준 요청 | {dynamic_context.get('baseline_status', '-')} |",
        f"| JWT 알고리즘 | {dynamic_context.get('jwt_algorithm', '-')} |",
        "",
    ]

    if vulnerable:
        lines += [
            "## 발견 사항",
            "",
            "| 위험도 | 카테고리 | 제목 |",
            "| --- | --- | --- |",
        ]
        for f in sorted(
            vulnerable,
            key=lambda x: -_SEVERITY_RANK.get(x.get("severity", ""), 0),
        ):
            lines.append(
                f"| {f.get('severity', '-')} "
                f"| {f.get('category', '-')} "
                f"| {f.get('title', '-')} |"
            )
        lines.append("")

    lines += ["## 상세 결과", ""]
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "UNKNOWN")
        status = f.get("status", "UNKNOWN")
        lines += [
            f"### {i}. [{sev}] {f.get('title', '')}",
            "",
            f"- **Tool**: `{f.get('tool_id', '')}`",
            f"- **Category**: {f.get('category', '')} | **Status**: {status} | **Confidence**: {f.get('confidence', '')}",
            "",
            "**Evidence**",
            "",
            f"> {f.get('evidence', '')}",
            "",
            "**Attack Scenario**",
            "",
            f"{f.get('attack_scenario', '')}",
            "",
            "**Recommendation**",
            "",
            f"{f.get('recommendation', '')}",
            "",
            "---",
            "",
        ]

    if dynamic_context:
        lines += [
            "## 동적 컨텍스트",
            "",
            "```json",
            json.dumps(dynamic_context, ensure_ascii=False, indent=2),
            "```",
            "",
        ]

    md_path.write_text("\n".join(lines), encoding="utf-8")

    # ── JSON ───────────────────────────────────────────────────────────────────
    report_dict = {
        "generated_at": generated_at,
        "run_id": run_id,
        "mode": "deep",
        "endpoint": {
            "base_url": profile.base_url,
            "method": profile.method,
            "path": profile.path,
        },
        "dynamic_context": dynamic_context,
        "findings": findings,
        "summary": {
            "total": len(findings),
            "vulnerable_count": len(vulnerable),
            "vulnerable_findings": [
                {
                    "tool_id": f.get("tool_id"),
                    "category": f.get("category"),
                    "severity": f.get("severity"),
                    "title": f.get("title"),
                }
                for f in vulnerable
            ],
        },
    }
    json_path.write_text(
        json.dumps(report_dict, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    paths: dict[str, str] = {
        "report_basename": stem,
        "report_md": str(md_path),
        "report_json": str(json_path),
    }

    if run_dir is not None:
        run_dir.mkdir(parents=True, exist_ok=True)
        run_md = run_dir / "deep_vulnerability_report.md"
        run_json = run_dir / "deep_vulnerability_report.json"
        run_md.write_text(md_path.read_text(encoding="utf-8"), encoding="utf-8")
        run_json.write_text(json_path.read_text(encoding="utf-8"), encoding="utf-8")
        paths["run_report_md"] = str(run_md)
        paths["run_report_json"] = str(run_json)

    return paths


def get_deep_scan_status(run_id: str) -> dict[str, Any]:
    """딥 스캔 결과 조회. analyze_endpoint_deep이 반환한 run_id로 완료 여부와 결과를 확인한다."""
    with _SCAN_LOCK:
        result = _SCAN_STORE.get(run_id)
    if result is None:
        return {"status": "not_found", "run_id": run_id}
    return result


def _run_deep_scan_background(
    run_id: str,
    raw_input: dict[str, Any],
    recorder: RunRecorder,
) -> None:
    """백그라운드 스레드에서 딥 스캔을 실행하고 결과를 _SCAN_STORE에 저장한다."""
    logger.info("deep_scan background start run_id=%s", run_id)
    try:
        profile = parse_endpoint_profile(raw_input)
        profile_dict = profile.to_serializable_dict()
        recorder.dump("01_endpoint_profile.json", profile_dict)

        deep_result = run_deep_scan(profile)
        logger.info(
            "deep_scan done: findings=%d turns=%d",
            len(deep_result.findings),
            deep_result.turns_used,
        )

        generated_at = utc_now_iso()
        report_paths = _write_deep_report(
            profile,
            deep_result.dynamic_context,
            deep_result.findings,
            run_id=run_id,
            generated_at=generated_at,
            run_dir=recorder.run_dir,
        )

        vulnerable = [
            {
                "tool_id": f.get("tool_id"),
                "category": f.get("category"),
                "severity": f.get("severity"),
                "title": f.get("title"),
            }
            for f in deep_result.findings
            if f.get("status") == "VULNERABLE"
        ]

        recorder.finalize(
            status="analyzed",
            summary_extra={
                "method": profile.method,
                "path": profile.path,
                "mode": "deep",
                "findings_count": len(deep_result.findings),
                "vulnerable_count": len(vulnerable),
                "turns_used": deep_result.turns_used,
                "report_paths": report_paths,
            },
        )

        result = {
            "status": "completed",
            "mode": "deep",
            "run_id": run_id,
            "endpoint_profile": profile_dict,
            "dynamic_context": deep_result.dynamic_context,
            "findings": deep_result.findings,
            "report_paths": report_paths,
        }

    except EndpointProfileValidationError as e:
        error_list = [
            {"code": issue.code, "field": issue.field, "message": issue.message}
            for issue in e.issues
        ]
        recorder.finalize(status="invalid_input", summary_extra={"errors": error_list})
        result = {"status": "invalid_input", "run_id": run_id, "errors": error_list}

    except Exception:
        logger.exception("deep_scan background failed run_id=%s", run_id)
        recorder.finalize(status="error")
        result = {"status": "error", "run_id": run_id, "message": "딥 스캔 중 오류가 발생했습니다. 로그를 확인하세요."}

    with _SCAN_LOCK:
        _SCAN_STORE[run_id] = result
    logger.info("deep_scan background complete run_id=%s status=%s", run_id, result["status"])


def analyze_endpoint_deep(raw_input: dict[str, Any]) -> dict[str, Any]:
    """
    딥 모드: OpenAI 에이전트가 직접 HTTP 프로브를 수행하며 OWASP 취약점을 분석한다.
    백그라운드에서 실행되며 즉시 run_id를 반환한다.
    결과는 get_deep_scan_status(run_id)로 확인하세요.
    딥 모드, 딥 스캔, 정밀 분석, deep mode, deep scan 요청 시 사용. OPENAI_API_KEY 필요.
    """
    recorder = RunRecorder()
    run_id = recorder.run_id
    logger.info("analyze_endpoint_deep start (async) run_id=%s", run_id)
    recorder.dump("00_input.json", raw_input)

    with _SCAN_LOCK:
        _SCAN_STORE[run_id] = {"status": "running", "run_id": run_id}

    thread = threading.Thread(
        target=_run_deep_scan_background,
        args=(run_id, raw_input, recorder),
        daemon=True,
    )
    thread.start()

    return {
        "status": "running",
        "run_id": run_id,
        "message": "딥 스캔이 백그라운드에서 시작됐습니다. get_deep_scan_status 툴에 run_id를 전달해 결과를 확인하세요.",
    }
