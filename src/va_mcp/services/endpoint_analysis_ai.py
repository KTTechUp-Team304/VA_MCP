from __future__ import annotations

import logging
from collections import Counter
from dataclasses import asdict
from typing import Any

from va_mcp.core.planner_output import PlannerOutput
from va_mcp.endpoint_profile import EndpointProfileValidationError, parse_endpoint_profile
from va_mcp.feature_extractor import FeatureExtractor, FeatureSet
from va_mcp.observability import RunRecorder
from va_mcp.orchestrator.orchestrator import Orchestrator, discover_tools
from va_mcp.planner import ai_advisor
from va_mcp.planner.planner import ScenarioPlanner
from va_mcp.reporting.report_generator import (
    endpoint_report_to_dict,
    flatten_tool_results,
    write_vulnerability_report,
)
from va_mcp.scenario.runner import ScenarioRunner

logger = logging.getLogger(__name__)

_extractor = FeatureExtractor()
_planner = ScenarioPlanner()
_orchestrator = Orchestrator()
_scenario_runner = ScenarioRunner(_orchestrator)


def analyze_endpoint_with_ai(raw_input: dict[str, Any]) -> dict[str, Any]:
    """
    analyze_endpoint 흐름에 AI 2차 검증 + 재실행 단계를 추가한 버전.

    1. rule-based 스캔 실행 (결과 A)
    2. AI가 missed_findings 검토
    3. missed 툴 재실행 (결과 B)
    4. A vs B 비교 → ai_only_findings
    """
    recorder = RunRecorder()
    logger.info("analyze_endpoint_with_ai start run_id=%s", recorder.run_id)
    recorder.dump("00_input.json", raw_input)

    try:
        profile = parse_endpoint_profile(raw_input)
        profile_dict = profile.to_serializable_dict()
        recorder.dump("01_endpoint_profile.json", profile_dict)

        feature_set: FeatureSet = _extractor.extract(profile)
        feature_dict = asdict(feature_set)
        recorder.dump("02_feature_set.json", feature_dict)

        planner_output = _planner.plan(feature_set, profile)
        recorder.dump("03_planner_output.json", asdict(planner_output))

        # ── 1단계: rule-based 스캔 (결과 A) ──
        endpoint_report = _scenario_runner.run(planner_output, profile)
        report_dict = endpoint_report_to_dict(endpoint_report)
        recorder.dump("04_endpoint_report.json", report_dict)

        tool_results = flatten_tool_results(endpoint_report)
        result_dicts = [asdict(r) for r in tool_results]
        for rd in result_dicts:
            recorder.dump_tool_result(rd.get("tool_id", "unknown"), rd)

        # ── 2단계: AI 2차 검증 ──
        valid_tool_ids: set[str] = set(discover_tools().keys())
        review_result = ai_advisor.review(report_dict, profile, valid_tool_ids)
        ai_review_dict = {
            "missed_findings": [
                {
                    "tool_id": f.tool_id,
                    "reason": f.reason,
                    "recommendation": f.recommendation,
                }
                for f in review_result.missed_findings
            ]
        }
        recorder.dump("05_ai_review.json", ai_review_dict)
        logger.info("ai_reviewer done: missed_findings=%d", len(review_result.missed_findings))

        # ── 3단계: missed 툴 재실행 (결과 B) ──
        ai_extra_results: list[dict] = []
        if review_result.missed_findings:
            missed_tool_ids = [
                f.tool_id for f in review_result.missed_findings
                if f.tool_id in valid_tool_ids
            ]
            if missed_tool_ids:
                missed_planner_output = PlannerOutput(
                    tool_ids=missed_tool_ids,
                    owasp_candidates=planner_output.owasp_candidates,
                    need_more_context=False,
                    missing=[],
                )
                missed_report = _scenario_runner.run(missed_planner_output, profile)
                missed_tool_results = flatten_tool_results(missed_report)
                ai_extra_results = [asdict(r) for r in missed_tool_results]
                recorder.dump("06_ai_extra_results.json", ai_extra_results)
                logger.info(
                    "ai re-run: %d tools, %d results",
                    len(missed_tool_ids),
                    len(ai_extra_results),
                )

        # ── 4단계: A vs B 비교 ──
        rule_based_vulnerable_ids = {
            rd["tool_id"] for rd in result_dicts
            if rd.get("status") == "vulnerable"
        }
        ai_only_findings = [
            rd for rd in ai_extra_results
            if rd.get("status") == "vulnerable"
            and rd.get("tool_id") not in rule_based_vulnerable_ids
        ]
        comparison = {
            "rule_based_vulnerable_count": len(rule_based_vulnerable_ids),
            "ai_extra_vulnerable_count": len(ai_only_findings),
            "ai_only_findings": [
                {
                    "tool_id": rd.get("tool_id"),
                    "tool_name": rd.get("tool_name"),
                    "severity": rd.get("severity"),
                    "title": rd.get("title"),
                }
                for rd in ai_only_findings
            ],
        }
        recorder.dump("07_comparison.json", comparison)
        logger.info(
            "comparison: rule_based=%d ai_only=%d",
            comparison["rule_based_vulnerable_count"],
            comparison["ai_extra_vulnerable_count"],
        )

        report_paths = write_vulnerability_report(
            endpoint_report,
            run_id=recorder.run_id,
            run_dir=recorder.run_dir,
        )

        status_counts = Counter(rd.get("status", "unknown") for rd in result_dicts)
        vulnerable = [
            {
                "tool_id": rd.get("tool_id"),
                "tool_name": rd.get("tool_name"),
                "severity": rd.get("severity"),
                "title": rd.get("title"),
            }
            for rd in result_dicts
            if rd.get("status") == "vulnerable"
        ]

        if planner_output.need_more_context:
            recorder.finalize(
                status="need_more_context",
                summary_extra={
                    "method": profile.method,
                    "path": profile.path,
                    "owasp_candidates": planner_output.owasp_candidates,
                    "tool_ids": planner_output.tool_ids,
                    "missing": planner_output.missing,
                    "report_paths": report_paths,
                    "ai_review": ai_review_dict,
                    "comparison": comparison,
                },
            )
            return {
                "status": "need_more_context",
                "run_id": recorder.run_id,
                "missing": planner_output.missing,
                "endpoint_profile": profile_dict,
                "feature_set": feature_dict,
                "endpoint_report": report_dict,
                "ai_review": ai_review_dict,
                "comparison": comparison,
                "report_paths": report_paths,
            }

        recorder.finalize(
            status="analyzed",
            summary_extra={
                "method": profile.method,
                "path": profile.path,
                "owasp_candidates": planner_output.owasp_candidates,
                "tool_ids": planner_output.tool_ids,
                "status_counts": dict(status_counts),
                "vulnerable_findings": vulnerable,
                "report_paths": report_paths,
                "ai_review": ai_review_dict,
                "comparison": comparison,
            },
        )

        return {
            "status": "analyzed",
            "run_id": recorder.run_id,
            "endpoint_profile": profile_dict,
            "feature_set": feature_dict,
            "owasp_candidates": planner_output.owasp_candidates,
            "tool_ids": planner_output.tool_ids,
            "tool_results": result_dicts,
            "endpoint_report": report_dict,
            "ai_review": ai_review_dict,
            "ai_extra_results": ai_extra_results,
            "comparison": comparison,
            "report_paths": report_paths,
        }

    except EndpointProfileValidationError as e:
        error_list = [
            {"code": issue.code, "field": issue.field, "message": issue.message}
            for issue in e.issues
        ]
        recorder.finalize(
            status="invalid_input",
            summary_extra={"errors": error_list},
        )
        return {
            "status": "invalid_input",
            "run_id": recorder.run_id,
            "errors": error_list,
        }

    except Exception:
        logger.exception("analyze_endpoint_with_ai failed run_id=%s", recorder.run_id)
        recorder.finalize(status="error")
        raise
