#!/usr/bin/env python3
"""Orchestrator 직전(parse → FeatureSet → Planner) 검증 스크립트."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

# repo root
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from va_mcp.endpoint_profile import parse_endpoint_profile
from va_mcp.feature_extractor import FeatureExtractor
from va_mcp.orchestrator.orchestrator import build_tool_input
from va_mcp.planner.planner import ScenarioPlanner


ENROLLMENTS_ME_V4 = {
    "base_url": "http://localhost:4000",
    "method": "GET",
    "path": "/api/enrollments/me",
    "headers": {"Accept": "application/json"},
    "query": {"userId": "1"},
    "auth_required": False,
    "required_roles": [],
    "resource_context": {
        "resource_type": "enrollment",
        "resource_id_key": "userId",
        "owner_id_key": "userId",
    },
    "side_effect": "read",
    "returns_sensitive_data": True,
    "description": "내 수강 목록. userId SQL 결합. JwtAuthGuard 없음.",
    "auth": {
        "login": {
            "path": "/api/auth/login",
            "method": "POST",
            "credential_fields": {
                "username": "username",
                "password": "passwordHash",
            },
            "token_json_path": "accessToken",
        },
        "accounts": [
            {"username": "김민수", "password": "student1", "role": "student"},
            {"username": "이서연", "password": "student1", "role": "student"},
        ],
    },
}

ENROLLMENTS_ME_AUTH_REQUIRED = {
    **ENROLLMENTS_ME_V4,
    "auth_required": True,
    "required_roles": ["student"],
}


def run_case(name: str, raw: dict) -> dict:
    profile = parse_endpoint_profile(raw)
    fs = FeatureExtractor().extract(profile)
    plan = ScenarioPlanner().plan(fs, profile)
    tool_input_preview = {
        "base_url": tool_input.target.base_url if (tool_input := build_tool_input(profile)) else None,
        "method": tool_input.request.method if tool_input.request else None,
        "path": tool_input.request.path if tool_input.request else None,
        "query": tool_input.request.query if tool_input.request else None,
        "auth_count": len(tool_input.auth),
        "auth_roles": [getattr(a, "role", None) for a in tool_input.auth],
    }
    return {
        "case": name,
        "profile_ok": True,
        "auth_accounts": len(profile.auth.accounts) if profile.auth else 0,
        "credential_fields": profile.credential_fields,
        "required_roles": profile.required_roles,
        "feature_set": asdict(fs),
        "planner": asdict(plan),
        "tool_input_preview": tool_input_preview,
    }


def main() -> int:
    cases = [
        run_case("enrollments_me_v4_no_guard", ENROLLMENTS_ME_V4),
        run_case("enrollments_me_v4_auth_required", ENROLLMENTS_ME_AUTH_REQUIRED),
    ]
    print(json.dumps(cases, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
