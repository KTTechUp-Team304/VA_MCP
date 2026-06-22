from __future__ import annotations

import logging
from typing import Any, Mapping

from va_mcp.endpoint_profile.endpoint_profile import SideEffect
from va_mcp.endpoint_profile.logging_utils import log_stage_io

logger = logging.getLogger(__name__)


def normalize_method(method: str) -> str:
    out = method.strip().upper()
    log_stage_io(
        logger,
        "normalize_method",
        input_data={"method": method},
        output_data={"method": out},
    )
    return out


def normalize_path(path: str) -> str:
    p = path.strip()
    if not p.startswith("/"):
        p = "/" + p
    log_stage_io(
        logger,
        "normalize_path",
        input_data={"path": path},
        output_data={"path": p},
    )
    return p


def normalize_base_url(base_url: str) -> str:
    u = base_url.strip()
    while u.endswith("/"):
        u = u[:-1]
    log_stage_io(
        logger,
        "normalize_base_url",
        input_data={"base_url": base_url},
        output_data={"base_url": u},
    )
    return u


def normalize_optional_maps(
    headers: Mapping[str, Any] | None,
    query: Mapping[str, Any] | None,
    params: Mapping[str, Any] | None,
    body: Any,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    h = dict(headers) if headers is not None else {}
    q = dict(query) if query is not None else {}
    p = dict(params) if params is not None else {}
    b: dict[str, Any] | None
    if body is None:
        b = None
    elif isinstance(body, Mapping):
        b = dict(body)
    else:
        b = None
    log_stage_io(
        logger,
        "normalize_optional_maps",
        input_data={
            "headers": None if headers is None else dict(headers),
            "query": None if query is None else dict(query),
            "params": None if params is None else dict(params),
            "body": None if body is None else (dict(body) if isinstance(body, Mapping) else body),
        },
        output_data={"headers": h, "query": q, "params": p, "body": b},
    )
    return h, q, p, b


def normalize_side_effect_string(value: str | SideEffect) -> str:
    if isinstance(value, SideEffect):
        out = value.value
    else:
        out = str(value).strip().lower()
    log_stage_io(
        logger,
        "normalize_side_effect_string",
        input_data={"side_effect": value},
        output_data={"side_effect": out},
    )
    return out


def normalize_resource_context(
    raw: Any,
    *,
    strict: bool,
) -> tuple[dict[str, Any] | None, list[str]]:
    """
    자유 형태 입력을 최소 스키마 dict로 맞춘다.

    Returns:
        (normalized_dict | None, warnings)
    """
    warnings: list[str] = []
    log_stage_io(
        logger,
        "normalize_resource_context.entry",
        input_data={"raw": raw, "strict": strict},
        output_data=None,
    )
    if raw is None:
        log_stage_io(
            logger,
            "normalize_resource_context.exit",
            input_data=None,
            output_data={"normalized": None, "warnings": warnings},
        )
        return None, warnings
    if not isinstance(raw, Mapping):
        msg = "resource_context는 객체(dict)여야 합니다"
        if strict:
            log_stage_io(
                logger,
                "normalize_resource_context.exit",
                input_data=None,
                output_data={"normalized": None, "warnings": warnings, "error": msg},
            )
            raise ValueError(msg)
        warnings.append(msg)
        log_stage_io(
            logger,
            "normalize_resource_context.exit",
            input_data=None,
            output_data={"normalized": None, "warnings": warnings},
        )
        return None, warnings

    def _get_str(*keys: str) -> str | None:
        for k in keys:
            if k in raw and raw[k] is not None and raw[k] != "":
                return str(raw[k]).strip()
        return None

    rt = _get_str("resource_type", "resourceType")
    rid = _get_str("resource_id_key", "resourceIdKey")

    # A03 : Software Supply Chain 모드 — resource_type/resource_id_key 없이
    # runtime/dependencies만 오는 입력은 IDOR 분기와 별도로 처리
    if rt is None and rid is None and "dependencies" in raw:
        runtime = _get_str("runtime") or "unknown"
        deps_raw = raw.get("dependencies")
        if isinstance(deps_raw, Mapping):
            deps = dict(deps_raw)
        else:
            msg = "dependencies는 객체(dict)여야 합니다"
            if strict:
                log_stage_io(
                    logger,
                    "normalize_resource_context.exit",
                    input_data=None,
                    output_data={"normalized": None, "warnings": warnings, "error": msg},
                )
                raise ValueError(msg)
            warnings.append(msg)
            deps = {}
        normalized = {"runtime": runtime, "dependencies": deps}
        log_stage_io(
            logger,
            "normalize_resource_context.exit",
            input_data=None,
            output_data={"normalized": normalized, "warnings": warnings},
        )
        return normalized, warnings

    if rt is None or rid is None:
        msg = "resource_context에 resource_type, resource_id_key가 필요합니다"
        if strict:
            log_stage_io(
                logger,
                "normalize_resource_context.exit",
                input_data=None,
                output_data={"normalized": None, "warnings": warnings, "error": msg},
            )
            raise ValueError(msg)
        warnings.append(msg)
        log_stage_io(
            logger,
            "normalize_resource_context.exit",
            input_data=None,
            output_data={"normalized": None, "warnings": warnings},
        )
        return None, warnings

    owner = _get_str("owner_id_key", "ownerIdKey")
    tenant = _get_str("tenant_id_key", "tenantIdKey")
    access_type = _get_str("access_type", "accessType")  # idor_bola의 교차 접근 테스트에서 사용
    hier_raw = raw.get("hierarchy_keys", raw.get("hierarchyKeys", []))
    if hier_raw is None:
        hierarchy: list[str] = []
    elif isinstance(hier_raw, (list, tuple)):
        hierarchy = [str(x).strip() for x in hier_raw if str(x).strip()]
    else:
        msg = "hierarchy_keys는 문자열 리스트여야 합니다"
        if strict:
            log_stage_io(
                logger,
                "normalize_resource_context.exit",
                input_data=None,
                output_data={"normalized": None, "warnings": warnings, "error": msg},
            )
            raise ValueError(msg)
        warnings.append(msg)
        hierarchy = []

    normalized: dict[str, Any] = {
        "resource_type": rt,
        "resource_id_key": rid,
        "owner_id_key": owner,
        "tenant_id_key": tenant,
        "hierarchy_keys": hierarchy,
        "access_type": access_type,  # None 포함하여 항상 키 존재
    }
    extra_keys = set(raw.keys()) - {
        "resource_type",
        "resourceType",
        "resource_id_key",
        "resourceIdKey",
        "owner_id_key",
        "ownerIdKey",
        "tenant_id_key",
        "tenantIdKey",
        "hierarchy_keys",
        "hierarchyKeys",
        "access_type",
        "accessType",
    }
    for k in sorted(extra_keys):
        logger.debug("resource_context에서 인식하지 않는 키 무시: %s", k)

    log_stage_io(
        logger,
        "normalize_resource_context.exit",
        input_data=None,
        output_data={"normalized": normalized, "warnings": warnings},
    )
    return normalized, warnings
