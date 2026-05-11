from __future__ import annotations

import logging
from collections import Counter
from dataclasses import asdict
from typing import Any

from va_mcp.endpoint_profile import EndpointProfileValidationError, parse_endpoint_profile
from va_mcp.feature_extractor import FeatureExtractor, FeatureSet
from va_mcp.observability import RunRecorder
from va_mcp.orchestrator.orchestrator import Orchestrator
from va_mcp.planner.planner import ScenarioPlanner

logger = logging.getLogger(__name__)

_extractor = FeatureExtractor()
_planner = ScenarioPlanner()
_orchestrator = Orchestrator()


def analyze_endpoint(raw_input: dict[str, Any]) -> dict[str, Any]:
    """
    EndpointProfile 파싱 → FeatureExtractor → ScenarioPlanner → Orchestrator 순으로 실행한다.

    각 단계의 입출력은 outputs/runs/<run_id>/ 폴더에 JSON으로 dump되며,
    동일한 흐름이 outputs/logs/va-mcp.log 와 outputs/runs/<run_id>/run.log에 로그로도 남는다.
    DUMP_ARTIFACTS=false 환경에서는 dump를 건너뛰고 run_id만 부여한다.
    """
    recorder = RunRecorder()
    logger.info("analyze_endpoint start run_id=%s", recorder.run_id)
    recorder.dump("00_input.json", raw_input)

    try:
        profile = parse_endpoint_profile(raw_input)
        profile_dict = profile.to_serializable_dict()
        recorder.dump("01_endpoint_profile.json", profile_dict)
        logger.debug(
            "parsed endpoint: method=%s path=%s side_effect=%s",
            profile.method,
            profile.path,
            profile.side_effect,
        )

        feature_set: FeatureSet = _extractor.extract(profile)
        feature_dict = asdict(feature_set)
        recorder.dump("02_feature_set.json", feature_dict)
        logger.debug("feature_set: %s", feature_dict)

        planner_output = _planner.plan(feature_set, profile)
        planner_dict = asdict(planner_output)
        recorder.dump("03_planner_output.json", planner_dict)
        logger.info(
            "planner: owasp=%s tools=%d need_more_context=%s",
            planner_output.owasp_candidates,
            len(planner_output.tool_ids),
            planner_output.need_more_context,
        )

        if planner_output.need_more_context:
            logger.warning(
                "need_more_context: missing=%s",
                planner_output.missing,
            )
            recorder.finalize(
                status="need_more_context",
                summary_extra={
                    "method": profile.method,
                    "path": profile.path,
                    "owasp_candidates": planner_output.owasp_candidates,
                    "tool_ids": planner_output.tool_ids,
                    "missing": planner_output.missing,
                },
            )
            return {
                "status": "need_more_context",
                "run_id": recorder.run_id,
                "missing": planner_output.missing,
                "endpoint_profile": profile_dict,
                "feature_set": feature_dict,
            }

        tool_results = _orchestrator.run_tools(planner_output, profile)
        result_dicts = [asdict(r) for r in tool_results]

        for rd in result_dicts:
            recorder.dump_tool_result(rd.get("tool_id", "unknown"), rd)

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
        logger.info(
            "orchestrator done: tools=%d counts=%s vulnerable=%d",
            len(result_dicts),
            dict(status_counts),
            len(vulnerable),
        )

        recorder.finalize(
            status="analyzed",
            summary_extra={
                "method": profile.method,
                "path": profile.path,
                "owasp_candidates": planner_output.owasp_candidates,
                "tool_ids": planner_output.tool_ids,
                "status_counts": dict(status_counts),
                "vulnerable_findings": vulnerable,
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
        }

    except EndpointProfileValidationError as e:
        error_list = [
            {"code": issue.code, "field": issue.field, "message": issue.message}
            for issue in e.issues
        ]
        logger.warning("invalid_input: %d issue(s)", len(error_list))
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
        logger.exception("analyze_endpoint failed run_id=%s", recorder.run_id)
        recorder.finalize(status="error")
        raise
