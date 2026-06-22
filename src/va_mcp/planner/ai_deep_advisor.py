from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import requests
import urllib3

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile
from va_mcp.skills import load_skill

logger = logging.getLogger(__name__)

# SSL 검증 경고 억제 (취약점 스캐너 특성상)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_TURNS = 30  # MCP 타임아웃 고려해 줄임


# ── 결과 타입 ────────────────────────────────────────────────────────────────

@dataclass
class AuthState:
    tokens: dict[str, str] = field(default_factory=dict)
    role_hierarchy: list[str] = field(default_factory=list)
    resource_ids: dict[str, list] = field(default_factory=dict)
    baseline_responses: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeepScanResult:
    dynamic_context: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    turns_used: int = 0


# ── OpenAI 툴 스키마 ─────────────────────────────────────────────────────────

_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_mcp_context",
            "description": (
                "엔드포인트 프로필 정보를 반환합니다. "
                "base_url, method, path, auth, accounts[] 등 컨텍스트를 확인하려면 이 툴을 먼저 호출하세요."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_probe",
            "description": (
                "HTTP 프로브를 실행하고 응답(status_code, headers, body, elapsed_seconds)을 반환합니다. "
                "path는 base_url 기준 상대 경로입니다 (예: /api/login). "
                "다른 호스트를 테스트하려면 override_url 파라미터를 사용하세요."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "description": "HTTP 메서드 (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)",
                    },
                    "path": {
                        "type": "string",
                        "description": "base_url 기준 상대 경로 (예: /api/users/1)",
                    },
                    "headers": {
                        "type": "object",
                        "description": "요청 헤더 (예: {\"Authorization\": \"Bearer <token>\"})",
                        "additionalProperties": {"type": "string"},
                    },
                    "body": {
                        "type": "object",
                        "description": "JSON 요청 바디",
                    },
                    "query_params": {
                        "type": "object",
                        "description": "URL 쿼리 파라미터",
                        "additionalProperties": {"type": "string"},
                    },
                    "timeout": {
                        "type": "number",
                        "description": "타임아웃(초). 기본값 10",
                    },
                    "override_url": {
                        "type": "string",
                        "description": "base_url 대신 사용할 전체 URL (다른 호스트 테스트 시)",
                    },
                },
                "required": ["method", "path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_findings",
            "description": (
                "모든 스캔이 완료된 후 최종 결과를 보고합니다. "
                "이 툴을 호출하면 분석이 종료됩니다."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "dynamic_context": {
                        "type": "object",
                        "description": "동적으로 탐지된 컨텍스트 (detected_fields, baseline_status, jwt_algorithm 등)",
                    },
                    "findings": {
                        "type": "array",
                        "description": "발견된 취약점 목록",
                        "items": {
                            "type": "object",
                            "properties": {
                                "tool_id": {"type": "string"},
                                "category": {"type": "string", "description": "OWASP 카테고리 (예: A01, A05)"},
                                "status": {
                                    "type": "string",
                                    "enum": ["VULNERABLE", "LOW", "INFO", "PASSED"],
                                },
                                "severity": {
                                    "type": "string",
                                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                                },
                                "confidence": {
                                    "type": "string",
                                    "enum": ["HIGH", "MEDIUM", "LOW"],
                                },
                                "title": {"type": "string"},
                                "evidence": {"type": "string"},
                                "attack_scenario": {"type": "string"},
                                "recommendation": {"type": "string"},
                            },
                            "required": [
                                "tool_id", "category", "status",
                                "severity", "title", "evidence",
                                "attack_scenario", "recommendation",
                            ],
                        },
                    },
                },
                "required": ["dynamic_context", "findings"],
            },
        },
    },
]


# ── Reconnaissance 툴 스키마 ──────────────────────────────────────────────────

_RECON_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_mcp_context",
            "description": (
                "엔드포인트 프로필 정보를 반환합니다. "
                "base_url, auth, accounts[] 등 컨텍스트를 확인하려면 이 툴을 먼저 호출하세요."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_probe",
            "description": (
                "HTTP 프로브를 실행하고 응답(status_code, headers, body, elapsed_seconds)을 반환합니다. "
                "로그인 및 베이스라인 수집에만 사용하세요. 공격성 페이로드는 사용하지 마세요."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string"},
                    "path": {"type": "string"},
                    "headers": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                    },
                    "body": {"type": "object"},
                    "query_params": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                    },
                    "timeout": {"type": "number"},
                    "override_url": {"type": "string"},
                },
                "required": ["method", "path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_recon",
            "description": (
                "Reconnaissance 완료 후 수집된 토큰, 권한 계층, 리소스 ID, 베이스라인 응답을 반환합니다. "
                "이 툴을 호출하면 Phase 0이 종료됩니다."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tokens": {
                        "type": "object",
                        "description": "role명 → JWT 토큰 매핑. 예) {\"admin\": \"eyJ...\"}",
                        "additionalProperties": {"type": "string"},
                    },
                    "role_hierarchy": {
                        "type": "array",
                        "description": "높은 권한 순으로 정렬된 role 목록. 예) [\"admin\", \"student\"]",
                        "items": {"type": "string"},
                    },
                    "resource_ids": {
                        "type": "object",
                        "description": "계정별 소유 리소스 ID 목록. 예) {\"A_owns\": [1, 2, 3]}",
                    },
                    "baseline_responses": {
                        "type": "object",
                        "description": "role명 → 베이스라인 응답 매핑. anonymous 포함.",
                    },
                },
                "required": ["tokens", "role_hierarchy", "resource_ids", "baseline_responses"],
            },
        },
    },
]


# ── 프로브 실행기 ─────────────────────────────────────────────────────────────

def _execute_probe(
    base_url: str,
    method: str,
    path: str,
    headers: dict | None = None,
    body: dict | None = None,
    query_params: dict | None = None,
    timeout: float = 10.0,
    override_url: str | None = None,
) -> dict[str, Any]:
    """실제 HTTP 요청을 수행하고 구조화된 응답을 반환합니다."""
    url = override_url if override_url else f"{base_url.rstrip('/')}{path}"
    try:
        resp = requests.request(
            method=method.upper(),
            url=url,
            headers=headers or {},
            json=body,
            params=query_params,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
        # 응답 본문 4KB로 제한 (컨텍스트 절약)
        body_text = resp.text[:4096] if resp.text else ""
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": body_text,
            "elapsed_seconds": round(resp.elapsed.total_seconds(), 3),
        }
    except requests.exceptions.Timeout:
        return {"error": "timeout", "elapsed_seconds": timeout}
    except requests.exceptions.ConnectionError as e:
        return {"error": f"connection_error: {e}"}
    except Exception as e:
        return {"error": str(e)}


# ── Phase 0: Reconnaissance ───────────────────────────────────────────────────

MAX_RECON_TURNS = 10


def run_reconnaissance(
    profile: EndpointProfile,
    model: str = "gpt-4o",
) -> AuthState:
    """
    Phase 0: 공격 없이 토큰 수집, 베이스라인 저장, 리소스 ID 매핑만 수행합니다.
    실패 시 빈 AuthState를 반환해 Phase 1이 graceful fallback으로 동작합니다.
    """
    from openai import OpenAI

    client = OpenAI()
    system_prompt = load_skill("reconnaissance")
    profile_dict = profile.to_serializable_dict()
    base_url = profile.base_url

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                "Reconnaissance를 시작하세요. "
                "먼저 get_mcp_context()를 호출한 뒤 STEP 1~5를 순서대로 수행하고 "
                "report_recon()으로 결과를 반환하세요."
            ),
        },
    ]

    for turn in range(1, MAX_RECON_TURNS + 1):
        logger.info("[recon] turn=%d", turn)

        try:
            response = client.chat.completions.create(
                model=model,
                tools=_RECON_TOOLS,
                tool_choice="auto",
                messages=messages,
            )
        except Exception as e:
            logger.error("[recon] LLM 호출 실패: %s", e)
            return AuthState()

        msg = response.choices[0].message

        assistant_entry: dict[str, Any] = {"role": "assistant"}
        if msg.content:
            assistant_entry["content"] = msg.content
        if msg.tool_calls:
            assistant_entry["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in msg.tool_calls
            ]
        messages.append(assistant_entry)

        if not msg.tool_calls:
            logger.warning("[recon] 툴 호출 없이 종료 — turn=%d", turn)
            break

        tool_results: list[dict[str, Any]] = []

        for tc in msg.tool_calls:
            fn = tc.function.name
            try:
                args = json.loads(tc.function.arguments) if tc.function.arguments else {}
            except json.JSONDecodeError:
                args = {}

            logger.info("[recon] tool=%s", fn)

            if fn == "get_mcp_context":
                result = profile_dict

            elif fn == "execute_probe":
                result = _execute_probe(
                    base_url=base_url,
                    method=args.get("method", "GET"),
                    path=args.get("path", "/"),
                    headers=args.get("headers"),
                    body=args.get("body"),
                    query_params=args.get("query_params"),
                    timeout=float(args.get("timeout", 10)),
                    override_url=args.get("override_url"),
                )

            elif fn == "report_recon":
                logger.info("[recon] report_recon 호출 — Phase 0 완료 (turn=%d)", turn)
                return AuthState(
                    tokens=args.get("tokens", {}),
                    role_hierarchy=args.get("role_hierarchy", []),
                    resource_ids=args.get("resource_ids", {}),
                    baseline_responses=args.get("baseline_responses", {}),
                )

            else:
                result = {"error": f"unknown tool: {fn}"}

            tool_results.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(result, ensure_ascii=False),
            })

        messages.extend(tool_results)

    logger.warning("[recon] MAX_RECON_TURNS(%d) 초과 — 빈 AuthState 반환", MAX_RECON_TURNS)
    return AuthState()


# ── 메인 에이전틱 루프 ────────────────────────────────────────────────────────

def run_deep_scan(
    profile: EndpointProfile,
    model: str = "gpt-4o",
) -> DeepScanResult:
    """
    딥 스캔 에이전틱 루프.

    AI가 get_mcp_context / execute_probe / report_findings 툴을 자율적으로
    호출하며 취약점을 분석합니다. report_findings 호출 시 루프가 종료됩니다.
    """
    from openai import OpenAI

    client = OpenAI()
    system_prompt = load_skill("deep_mode_prompt")
    profile_dict = profile.to_serializable_dict()
    base_url = profile.base_url

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt + "\n\n【언어 규칙】 report_findings()의 모든 필드(title, evidence, attack_scenario, recommendation)는 반드시 한국어로 작성하세요."},
        {
            "role": "user",
            "content": (
                "딥 스캔을 시작하세요. 먼저 get_mcp_context()를 호출하세요.\n\n"
                "【필수 규칙 1 — 기본 스캔 항목】\n"
                "아래 항목은 서버가 500을 반환하더라도 반드시 직접 프로브하고 결과를 findings에 포함하세요:\n"
                "1. security_headers: 응답 헤더에 CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy 존재 여부 확인. 없으면 VULNERABLE.\n"
                "2. error_info_exposure: 응답 헤더의 X-Powered-By, Server 값 확인. 존재하면 VULNERABLE.\n"
                "3. debug_endpoint: /api-docs, /swagger, /health, /metrics 경로에 GET 요청. 200 반환 시 VULNERABLE.\n"
                "4. cors_misconfiguration: Origin: https://evil.example.com 헤더로 요청. ACAO가 반영되면 VULNERABLE.\n"
                "5. retry_handling: 동일 요청 20회 연속 전송. 429가 없으면 VULNERABLE.\n"
                "6. sensitive_path: /.env, /.git/config 접근. 200이면 VULNERABLE.\n\n"
                "【필수 규칙 2 — 500 응답 처리】\n"
                "500 응답도 분석 대상입니다. 응답 헤더에서 X-Powered-By, Server 등을 확인하고, "
                "보안 헤더 누락 여부를 체크하세요. 500이라고 findings를 비워두지 마세요.\n\n"
                "STEP 1 ~ STEP 5를 진행한 뒤 report_findings()로 결과를 보고하세요."
            ),
        },
    ]

    turn = 0
    probe_count = 0  # execute_probe 호출 횟수 추적
    MIN_PROBES = 8   # report_findings 허용 최소 프로브 수
    final: DeepScanResult | None = None

    while turn < MAX_TURNS:
        turn += 1
        logger.info("[deep_scan] turn=%d", turn)

        response = client.chat.completions.create(
            model=model,
            tools=_TOOLS,
            tool_choice="auto",
            messages=messages,
        )

        msg = response.choices[0].message

        # assistant 메시지 저장 (tool_calls 포함 직렬화)
        assistant_entry: dict[str, Any] = {"role": "assistant"}
        if msg.content:
            assistant_entry["content"] = msg.content
        if msg.tool_calls:
            assistant_entry["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in msg.tool_calls
            ]
        messages.append(assistant_entry)

        # 툴 호출 없으면 — probe 최소치 미달 시 강제 계속
        if not msg.tool_calls:
            if probe_count < MIN_PROBES:
                remaining = MIN_PROBES - probe_count
                logger.warning(
                    "[deep_scan] no tool calls but probe_count=%d < MIN_PROBES=%d — forcing continue",
                    probe_count, MIN_PROBES,
                )
                messages.append({
                    "role": "user",
                    "content": (
                        f"분석이 너무 일찍 종료됩니다. "
                        f"execute_probe를 최소 {remaining}번 더 실행한 뒤 report_findings()를 호출하세요. "
                        f"500 응답도 분석 대상입니다. 응답 헤더에서 보안 헤더 누락 여부를 확인하고 "
                        f"security_headers, cors_misconfiguration, error_info_exposure, "
                        f"debug_endpoint, retry_handling 항목을 계속 수행하세요."
                    ),
                })
                continue
            logger.info("[deep_scan] no tool calls — ending at turn=%d", turn)
            break

        # 툴 실행
        tool_results: list[dict[str, Any]] = []
        should_stop = False

        for tc in msg.tool_calls:
            fn = tc.function.name
            try:
                args = json.loads(tc.function.arguments) if tc.function.arguments else {}
            except json.JSONDecodeError:
                args = {}

            logger.info("[deep_scan] tool=%s", fn)

            if fn == "get_mcp_context":
                result = profile_dict

            elif fn == "execute_probe":
                probe_count += 1
                result = _execute_probe(
                    base_url=base_url,
                    method=args.get("method", "GET"),
                    path=args.get("path", "/"),
                    headers=args.get("headers"),
                    body=args.get("body"),
                    query_params=args.get("query_params"),
                    timeout=float(args.get("timeout", 10)),
                    override_url=args.get("override_url"),
                )

            elif fn == "report_findings":
                if probe_count < MIN_PROBES:
                    # 프로브가 충분하지 않으면 계속 강제
                    remaining = MIN_PROBES - probe_count
                    logger.warning(
                        "[deep_scan] report_findings blocked: probe_count=%d < MIN_PROBES=%d",
                        probe_count, MIN_PROBES,
                    )
                    result = {
                        "error": (
                            f"분석이 너무 일찍 종료됩니다. "
                            f"execute_probe를 최소 {remaining}번 더 실행한 뒤 보고하세요. "
                            f"security_headers, cors_misconfiguration, error_info_exposure, "
                            f"debug_endpoint, retry_handling 등 기본 툴을 실행하세요."
                        )
                    }
                else:
                    final = DeepScanResult(
                        dynamic_context=args.get("dynamic_context", {}),
                        findings=args.get("findings", []),
                        turns_used=turn,
                    )
                    result = {"status": "recorded"}
                    should_stop = True

            else:
                result = {"error": f"unknown tool: {fn}"}

            tool_results.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(result, ensure_ascii=False),
            })

        messages.extend(tool_results)

        if should_stop:
            logger.info("[deep_scan] report_findings called — stopping at turn=%d", turn)
            break

    if final is None:
        logger.warning("[deep_scan] MAX_TURNS(%d) reached without report_findings", MAX_TURNS)
        final = DeepScanResult(turns_used=turn)

    return final
