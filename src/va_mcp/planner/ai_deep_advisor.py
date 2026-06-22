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


# ── AuthState ────────────────────────────────────────────────────────────────

@dataclass
class AuthState:
    tokens: dict[str, str] = field(default_factory=dict)
    # {"admin": "eyJ...", "student": "eyJ..."}
    role_hierarchy: list[str] = field(default_factory=list)
    # ["admin", "professor", "student"]
    resource_ids: dict[str, list] = field(default_factory=dict)
    # {"userA_owns": [1, 2, 3], "userB_owns": [4, 5]}
    baseline_responses: dict[str, Any] = field(default_factory=dict)
    # {"admin": {"status_code": 200, "body_summary": "...", "elapsed_seconds": 0.123}}


# ── SKILL 선택 ────────────────────────────────────────────────────────────────

def select_skills(profile: EndpointProfile, auth_state: AuthState) -> list[str]:
    """
    EndpointProfile과 AuthState를 기반으로 실행할 SKILL 파일 경로 목록을 반환한다.
    항상 실행할 always/ 카테고리를 기본으로 포함하고,
    엔드포인트 특성에 따라 조건부 카테고리를 추가한다.
    """
    skills: list[str] = []

    # always: 항상 실행
    skills += [
        "always/security_headers",
        "always/cors",
        "always/error_info_exposure",
        "always/sensitive_path",
        "always/debug_endpoint",
        "always/stack_trace",
    ]

    # injection: body 또는 query 파라미터 존재 시 (빈 dict도 파라미터 있음으로 판단)
    has_params = (
        getattr(profile, "body", None) is not None
        or getattr(profile, "query_params", None) is not None
    )
    if has_params:
        skills += [
            "injection/sql_injection",
            "injection/xss_reflected",
            "injection/ssti",
            "injection/path_traversal",
            "injection/cmd_injection",
        ]

    # access_control: auth_required=true 시
    if getattr(profile, "auth_required", False):
        skills += [
            "access_control/forced_browsing",
            "access_control/http_method_tamper",
        ]
        # role_hierarchy 2단계 이상 시 권한 비교 툴 추가
        if len(auth_state.role_hierarchy) >= 2:
            skills += [
                "access_control/bfla",
                "access_control/rbac_check",
            ]
        # resource_ids 존재 시 IDOR 추가
        if auth_state.resource_ids:
            skills.append("access_control/idor_bola")

    # auth: 토큰 존재 시
    if auth_state.tokens:
        skills += [
            "auth/jwt_attacks",
            "auth/auth_bruteforce",
            "auth/auth_lockout",
            "auth/auth_enum",
            "auth/auth_rate_limit",
        ]
        # 로그아웃 경로 명시 시 세션 무효화 테스트 추가
        logout_path = None
        try:
            logout_path = profile.auth.logout.path  # type: ignore[union-attr]
        except AttributeError:
            pass
        if logout_path:
            skills.append("auth/auth_session")

    # crypto: 토큰 존재 또는 Set-Cookie 가능성 있는 엔드포인트
    if auth_state.tokens or getattr(profile, "auth_required", False):
        skills += [
            "crypto/insecure_jwt",
            "crypto/cookie_security",
        ]
    if getattr(profile, "returns_sensitive_data", False):
        skills.append("crypto/sensitive_data_exposure")

    # business: side_effect가 create/update/delete 시
    side_effect = getattr(profile, "side_effect", "") or ""
    if side_effect in ("create", "update", "delete"):
        skills += [
            "business/rate_limit",
            "business/retry_handling",
            "business/business_logic",
            "business/resource_exhaustion",
        ]

    logger.info("[select_skills] selected %d skills: %s", len(skills), skills)
    return skills


# ── 결과 타입 ────────────────────────────────────────────────────────────────

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


# ── Attack Phase 루프 ─────────────────────────────────────────────────────────

def run_attack_phase(
    profile: EndpointProfile,
    auth_state: AuthState,
    applicable_skills: list[str],
    model: str = "gpt-4o",
) -> DeepScanResult:
    """
    Phase 1: Attack.
    auth_state와 선택된 SKILL 목록을 주입받아 취약점 분석을 수행한다.
    """
    from openai import OpenAI

    client = OpenAI()
    profile_dict = profile.to_serializable_dict()
    base_url = profile.base_url

    # SKILL 파일 로드 및 결합
    skill_contents: list[str] = []
    for skill_name in applicable_skills:
        try:
            skill_contents.append(f"=== {skill_name} ===\n{load_skill(skill_name)}")
        except FileNotFoundError:
            logger.warning("[attack_phase] skill not found: %s", skill_name)

    system_prompt = load_skill("orchestrator")
    skill_block = "\n\n".join(skill_contents)

    # auth_state를 구조화된 컨텍스트로 직렬화
    auth_context = json.dumps({
        "tokens": auth_state.tokens,
        "role_hierarchy": auth_state.role_hierarchy,
        "resource_ids": auth_state.resource_ids,
        "baseline_responses": auth_state.baseline_responses,
    }, ensure_ascii=False)

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                "딥 스캔을 시작하세요. 먼저 get_mcp_context()를 호출하세요.\n\n"
                f"【주입된 auth_state】\n{auth_context}\n\n"
                f"【실행할 SKILL 목록】\n아래 SKILL을 순서대로 실행하세요:\n"
                + "\n".join(f"- {s}" for s in applicable_skills)
                + f"\n\n【SKILL 상세 내용】\n{skill_block}\n\n"
                "【필수 규칙】\n"
                "- 각 SKILL의 PROBE-N을 순서대로 실행하세요.\n"
                "- 판단은 SKILL의 수치 기준을 따르고, auth_state.baseline_responses 대비 변화량을 우선 참조하세요.\n"
                "- evidence 필드에는 실제 요청 URL + 페이로드 + 응답 코드 + 응답 본문 발췌를 반드시 포함하세요. 추론 금지.\n"
                "- 4xx/5xx 응답은 정지 기준이 아닙니다. 계속 진행하세요.\n\n"
                "모든 SKILL 실행 후 report_findings()로 결과를 보고하세요."
            ),
        },
    ]

    turn = 0
    probe_count = 0
    MIN_PROBES = max(len(applicable_skills), 8)
    final: DeepScanResult | None = None

    while turn < MAX_TURNS:
        turn += 1
        logger.info("[attack_phase] turn=%d", turn)

        response = client.chat.completions.create(
            model=model,
            tools=_TOOLS,
            tool_choice="auto",
            messages=messages,
        )

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
            logger.info("[attack_phase] no tool calls — ending at turn=%d", turn)
            break

        tool_results: list[dict[str, Any]] = []
        should_stop = False

        for tc in msg.tool_calls:
            fn = tc.function.name
            try:
                args = json.loads(tc.function.arguments) if tc.function.arguments else {}
            except json.JSONDecodeError:
                args = {}

            logger.info("[attack_phase] tool=%s", fn)

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
                    remaining = MIN_PROBES - probe_count
                    logger.warning(
                        "[attack_phase] report_findings blocked: probe_count=%d < MIN_PROBES=%d",
                        probe_count, MIN_PROBES,
                    )
                    result = {
                        "error": (
                            f"분석이 너무 일찍 종료됩니다. "
                            f"execute_probe를 최소 {remaining}번 더 실행한 뒤 보고하세요. "
                            f"주입된 SKILL 목록의 PROBE-N을 순서대로 실행하세요."
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
            logger.info("[attack_phase] report_findings called — stopping at turn=%d", turn)
            break

    if final is None:
        logger.warning("[attack_phase] MAX_TURNS(%d) reached without report_findings", MAX_TURNS)
        final = DeepScanResult(turns_used=turn)

    return final


# ── 메인 오케스트레이터 ───────────────────────────────────────────────────────

def run_deep_scan(
    profile: EndpointProfile,
    model: str = "gpt-4o",
    auth_state: AuthState | None = None,
) -> DeepScanResult:
    """
    딥 스캔 오케스트레이터.
    Phase 0(reconnaissance) → Phase 1(attack) 순서로 실행.
    """
    # Phase 0: Reconnaissance
    if auth_state is None:
        logger.info("[run_deep_scan] Phase 0 start — reconnaissance")
        auth_state = run_reconnaissance(profile, model)
        logger.info(
            "[run_deep_scan] Phase 0 complete — tokens=%d, roles=%d, resources=%d",
            len(auth_state.tokens),
            len(auth_state.role_hierarchy),
            len(auth_state.resource_ids),
        )

    # SKILL 선택
    applicable_skills = select_skills(profile, auth_state)
    logger.info("[run_deep_scan] Phase 1 start — skills=%d", len(applicable_skills))

    # Phase 1: Attack
    return run_attack_phase(profile, auth_state, applicable_skills, model)
