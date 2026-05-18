from __future__ import annotations

import json
import logging
from typing import Any, Mapping

from va_mcp.endpoint_profile.endpoint_profile import EndpointProfile, SideEffect
from va_mcp.endpoint_profile.endpoint_profile_auth_normalizer import normalize_auth_config
from va_mcp.endpoint_profile.endpoint_profile_normalizer import (
    normalize_base_url,
    normalize_method,
    normalize_optional_maps,
    normalize_path,
    normalize_resource_context,
    normalize_side_effect_string,
)
from va_mcp.endpoint_profile.endpoint_profile_validator import (
    EndpointProfileValidationError,
    ValidationIssue,
    validate_endpoint_profile,
)
from va_mcp.endpoint_profile.logging_utils import log_stage_io

logger = logging.getLogger(__name__)

_CANONICAL_KEYS = frozenset(
    {
        "base_url",
        "method",
        "path",
        "headers",
        "query",
        "params",
        "body",
        "auth_required",
        "auth_contexts",
        "description",
        "normal_request_example",
        "normal_response_example",
        "resource_context",
        "side_effect",
        "returns_sensitive_data",
        "credential_fields",
        "auth",
        "required_roles",
    }
)


def _describe_parse_input(raw: Any) -> dict[str, Any]:
    """로그용으로 원본 입력 형태만 요약 (큰 JSON 문자열은 미리보기)."""
    if isinstance(raw, str):
        return {
            "kind": "json_string",
            "length": len(raw),
            "preview": raw[:800] + ("..." if len(raw) > 800 else ""),
        }
    if isinstance(raw, Mapping):
        return {
            "kind": "mapping",
            "top_level_keys": sorted(str(k) for k in raw.keys()),
        }
    return {"kind": type(raw).__name__, "repr_preview": repr(raw)[:800]}


_ALIASES: dict[str, str] = {
    "baseUrl": "base_url",
    "authRequired": "auth_required",
    "authContexts": "auth_contexts",
    "normalRequestExample": "normal_request_example",
    "normalResponseExample": "normal_response_example",
    "resourceContext": "resource_context",
    "sideEffect": "side_effect",
    "returnsSensitiveData": "returns_sensitive_data",
    "credentialFields": "credential_fields",
    "requiredRoles": "required_roles",
}


def _coerce_raw_mapping(raw: Any) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as e:
            raise EndpointProfileValidationError(
                [
                    ValidationIssue(
                        "INVALID_JSON",
                        "root",
                        f"JSON 파싱 실패: {e}",
                    )
                ]
            ) from e
    if not isinstance(raw, Mapping):
        raise EndpointProfileValidationError(
            [
                ValidationIssue(
                    "INVALID_INPUT",
                    "root",
                    "입력은 dict 또는 JSON 문자열이어야 합니다",
                )
            ]
        )
    return dict(raw)


def _canonicalize_keys(flat: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in flat.items():
        key = _ALIASES.get(k, k)
        if key in _CANONICAL_KEYS:
            out[key] = v
        else:
            logger.debug("endpoint profile 입력에서 계약 필드가 아닌 키 무시: %s", k)
    return out


def _parse_bool(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and v in (0, 1):
        return bool(int(v))
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1", "yes", "y"):
            return True
        if s in ("false", "0", "no", "n", ""):
            return False
    return bool(v)


def _parse_required_roles(raw: Any) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise EndpointProfileValidationError(
            [
                ValidationIssue(
                    "TYPE",
                    "required_roles",
                    "required_roles는 문자열 리스트이거나 생략되어야 합니다",
                )
            ]
        )
    roles: list[str] = []
    for i, item in enumerate(raw):
        if not isinstance(item, str) or not item.strip():
            raise EndpointProfileValidationError(
                [
                    ValidationIssue(
                        "TYPE",
                        "required_roles",
                        f"required_roles[{i}]는 비어 있지 않은 문자열이어야 합니다",
                    )
                ]
            )
        roles.append(item.strip())
    return roles


def parse_endpoint_profile(
    raw: Mapping[str, Any] | str,
    *,
    strict_resource_context: bool = True,
) -> EndpointProfile:
    """
    외부 dict/JSON 문자열을 정규화·검증된 EndpointProfile로 변환한다.

    Args:
        raw: 엔드포인트 설명 매핑 또는 JSON 문자열.
        strict_resource_context: True면 resource_context를 최소 스키마로 맞출 수 없을 때 검증 오류.
            False면 맞출 수 없을 때 None으로 두고 경고 로그를 남긴다.
    """
    log_stage_io(
        logger,
        "parse.00_options",
        input_data={
            "strict_resource_context": strict_resource_context,
            "raw_preview": _describe_parse_input(raw),
        },
        output_data=None,
    )

    flat = _coerce_raw_mapping(raw)
    log_stage_io(
        logger,
        "parse.01_coerce_raw",
        input_data=_describe_parse_input(raw),
        output_data=flat,
    )

    c = _canonicalize_keys(flat)
    log_stage_io(
        logger,
        "parse.02_canonical_keys",
        input_data=flat,
        output_data=c,
    )

    base_url = str(c["base_url"]).strip() if c.get("base_url") is not None else ""
    method_raw = str(c["method"]).strip() if c.get("method") is not None else ""
    path_raw = str(c["path"]).strip() if c.get("path") is not None else ""

    method = normalize_method(method_raw) if method_raw else ""
    path = normalize_path(path_raw) if path_raw else ""
    base_url = normalize_base_url(base_url) if base_url else ""

    log_stage_io(
        logger,
        "parse.03_normalize_core_fields",
        input_data={
            "base_url_in": str(c.get("base_url") or "").strip(),
            "method_raw": method_raw,
            "path_raw": path_raw,
        },
        output_data={"base_url": base_url, "method": method, "path": path},
    )

    for _fname, _val in (
        ("headers", c.get("headers")),
        ("query", c.get("query")),
        ("params", c.get("params")),
    ):
        if _val is not None and not isinstance(_val, Mapping):
            raise EndpointProfileValidationError(
                [
                    ValidationIssue(
                        "TYPE",
                        _fname,
                        f"{_fname}는 dict이거나 생략되어야 합니다",
                    )
                ]
            )

    body_in = c.get("body")
    if body_in is not None and not isinstance(body_in, Mapping):
        raise EndpointProfileValidationError(
            [
                ValidationIssue(
                    "TYPE",
                    "body",
                    "body는 dict | None이어야 합니다",
                )
            ]
        )

    headers, query, params, body = normalize_optional_maps(
        c.get("headers"),
        c.get("query"),
        c.get("params"),
        body_in,
    )

    auth_required = _parse_bool(c.get("auth_required"), False)
    description = str(c.get("description") or "").strip()

    auth_raw = c.get("auth_contexts")
    if auth_raw is None:
        auth_contexts: list[Any] = []
    elif isinstance(auth_raw, list):
        auth_contexts = list(auth_raw)
    else:
        raise EndpointProfileValidationError(
            [
                ValidationIssue(
                    "TYPE",
                    "auth_contexts",
                    "auth_contexts는 리스트이거나 생략되어야 합니다",
                )
            ]
        )

    nreq = c.get("normal_request_example")
    if nreq is not None and not isinstance(nreq, Mapping):
        raise EndpointProfileValidationError(
            [
                ValidationIssue(
                    "TYPE",
                    "normal_request_example",
                    "normal_request_example는 dict | None이어야 합니다",
                )
            ]
        )
    nreq_dict = dict(nreq) if isinstance(nreq, Mapping) else None

    nres = c.get("normal_response_example")
    if nres is not None and not isinstance(nres, Mapping):
        raise EndpointProfileValidationError(
            [
                ValidationIssue(
                    "TYPE",
                    "normal_response_example",
                    "normal_response_example는 dict | None이어야 합니다",
                )
            ]
        )
    nres_dict = dict(nres) if isinstance(nres, Mapping) else None

    rc_raw = c.get("resource_context")
    resource_context: dict[str, Any] | None
    try:
        resource_context, rc_warnings = normalize_resource_context(
            rc_raw, strict=strict_resource_context
        )
    except ValueError as e:
        raise EndpointProfileValidationError(
            [
                ValidationIssue(
                    "RESOURCE_CONTEXT",
                    "resource_context",
                    str(e),
                )
            ]
        ) from e
    for w in rc_warnings:
        logger.warning("resource_context: %s", w)

    log_stage_io(
        logger,
        "parse.04_resource_context",
        input_data={"raw": rc_raw, "strict_resource_context": strict_resource_context},
        output_data={"normalized": resource_context, "warnings": rc_warnings},
    )

    side_effect_raw = c.get("side_effect", SideEffect.READ.value)
    side_effect = normalize_side_effect_string(side_effect_raw)

    returns_sensitive = _parse_bool(c.get("returns_sensitive_data"), False)

    cred_raw = c.get("credential_fields")
    if cred_raw is None:
        credential_fields: dict[str, str] = {}
    elif not isinstance(cred_raw, Mapping):
        raise EndpointProfileValidationError(
            [
                ValidationIssue(
                    "TYPE",
                    "credential_fields",
                    "credential_fields는 dict이거나 생략되어야 합니다",
                )
            ]
        )
    else:
        credential_fields = {}
        for ck, cv in cred_raw.items():
            if not isinstance(ck, str):
                raise EndpointProfileValidationError(
                    [
                        ValidationIssue(
                            "TYPE",
                            "credential_fields",
                            "credential_fields의 키는 문자열이어야 합니다",
                        )
                    ]
                )
            credential_fields[ck] = "" if cv is None else str(cv)

    required_roles = _parse_required_roles(c.get("required_roles"))

    auth_raw = c.get("auth")
    auth_config = None
    if auth_raw is not None:
        try:
            auth_config = normalize_auth_config(auth_raw)
        except ValueError as e:
            raise EndpointProfileValidationError(
                [ValidationIssue("AUTH", "auth", str(e))]
            ) from e
        if auth_config and auth_config.login and auth_config.login.credential_fields:
            if not credential_fields:
                credential_fields = dict(auth_config.login.credential_fields)
            else:
                merged = dict(auth_config.login.credential_fields)
                merged.update(credential_fields)
                credential_fields = merged

    log_stage_io(
        logger,
        "parse.04b_auth",
        input_data={"auth_raw": auth_raw, "required_roles": required_roles},
        output_data={
            "auth": auth_config.to_serializable_dict() if auth_config else None,
            "credential_fields": credential_fields,
        },
    )

    profile = EndpointProfile(
        base_url=base_url,
        method=method,
        path=path,
        headers=headers,
        query=query,
        params=params,
        body=body,
        auth_required=auth_required,
        auth_contexts=auth_contexts,
        auth=auth_config,
        required_roles=required_roles,
        description=description,
        normal_request_example=nreq_dict,
        normal_response_example=nres_dict,
        resource_context=resource_context,
        side_effect=side_effect,
        returns_sensitive_data=returns_sensitive,
        credential_fields=credential_fields,
    )
    log_stage_io(
        logger,
        "parse.05_built_profile_pre_validate",
        input_data=None,
        output_data=profile.to_serializable_dict(),
    )
    validate_endpoint_profile(profile)
    log_stage_io(
        logger,
        "parse.06_success",
        input_data=None,
        output_data=profile.to_serializable_dict(),
    )
    return profile
