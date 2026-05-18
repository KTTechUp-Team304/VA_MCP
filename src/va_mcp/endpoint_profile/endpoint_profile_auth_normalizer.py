from __future__ import annotations

import logging
from typing import Any, Mapping

from va_mcp.endpoint_profile.auth_config import AccountCredential, AuthConfig, LoginConfig
from va_mcp.endpoint_profile.endpoint_profile_normalizer import normalize_method, normalize_path
from va_mcp.endpoint_profile.logging_utils import log_stage_io

logger = logging.getLogger(__name__)

_LOGICAL_CREDENTIAL_KEYS = frozenset({"username", "password"})


def _normalize_credential_fields(raw: Any, *, field_path: str) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ValueError(f"{field_path}는 객체(dict)여야 합니다")
    out: dict[str, str] = {}
    for key, val in raw.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError(f"{field_path}의 키는 비어 있지 않은 문자열이어야 합니다")
        logical = key.strip()
        if logical not in _LOGICAL_CREDENTIAL_KEYS:
            logger.debug("%s에서 인식하지 않는 논리 키 무시: %s", field_path, logical)
            continue
        out[logical] = "" if val is None else str(val).strip()
    return out


def _normalize_login(raw: Any) -> LoginConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ValueError("auth.login은 객체(dict)여야 합니다")

    path_raw = raw.get("path", raw.get("loginPath"))
    if path_raw is None or not str(path_raw).strip():
        raise ValueError("auth.login.path는 비어 있지 않아야 합니다")
    path = normalize_path(str(path_raw).strip())

    method_raw = raw.get("method", "POST")
    method = normalize_method(str(method_raw).strip()) if str(method_raw).strip() else "POST"

    cred = _normalize_credential_fields(
        raw.get("credential_fields", raw.get("credentialFields")),
        field_path="auth.login.credential_fields",
    )
    token_path = raw.get("token_json_path", raw.get("tokenJsonPath", "accessToken"))
    token_json_path = str(token_path).strip() if token_path is not None else "accessToken"
    if not token_json_path:
        raise ValueError("auth.login.token_json_path는 비어 있지 않아야 합니다")

    return LoginConfig(
        path=path,
        method=method,
        credential_fields=cred,
        token_json_path=token_json_path,
    )


def _normalize_accounts(raw: Any) -> list[AccountCredential]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("auth.accounts는 리스트이어야 합니다")

    accounts: list[AccountCredential] = []
    for i, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ValueError(f"auth.accounts[{i}]는 객체(dict)여야 합니다")
        username = item.get("username", item.get("user"))
        password = item.get("password", item.get("passwd", item.get("pwd")))
        role = item.get("role", item.get("roleName", ""))
        if username is None or not str(username).strip():
            raise ValueError(f"auth.accounts[{i}].username은 비어 있지 않아야 합니다")
        if password is None or not str(password):
            raise ValueError(f"auth.accounts[{i}].password는 비어 있지 않아야 합니다")
        if role is None or not str(role).strip():
            raise ValueError(f"auth.accounts[{i}].role은 비어 있지 않아야 합니다")
        accounts.append(
            AccountCredential(
                username=str(username).strip(),
                password=str(password),
                role=str(role).strip(),
            )
        )
    return accounts


def normalize_auth_config(raw: Any) -> AuthConfig | None:
    """
    V4 auth 블록을 AuthConfig로 정규화한다.
    raw가 None이면 None. accounts만 있고 login이 없으면 ValueError.
    """
    log_stage_io(
        logger,
        "normalize_auth_config.entry",
        input_data={"raw": raw},
        output_data=None,
    )
    if raw is None:
        log_stage_io(
            logger,
            "normalize_auth_config.exit",
            input_data=None,
            output_data={"normalized": None},
        )
        return None
    if not isinstance(raw, Mapping):
        raise ValueError("auth는 객체(dict)여야 합니다")

    login = _normalize_login(raw.get("login"))
    accounts = _normalize_accounts(raw.get("accounts"))

    if accounts and login is None:
        raise ValueError("auth.accounts가 있으면 auth.login이 필요합니다")

    normalized = AuthConfig(login=login, accounts=accounts)
    log_stage_io(
        logger,
        "normalize_auth_config.exit",
        input_data=None,
        output_data=normalized.to_serializable_dict(),
    )
    return normalized


def count_effective_auth_contexts(auth_contexts: list[Any]) -> int:
    """Bearer 토큰이 채워진 auth_contexts 개수."""
    n = 0
    for ctx in auth_contexts or []:
        if isinstance(ctx, Mapping):
            auth_type = str(ctx.get("auth_type", ctx.get("authType", ""))).lower()
            token = ctx.get("token")
        else:
            auth_type = str(getattr(ctx, "auth_type", "")).lower()
            token = getattr(ctx, "token", None)
        if auth_type == "bearer" and token:
            n += 1
        elif auth_type in ("", "none") and token:
            n += 1
    return n


def effective_auth_account_count(profile: Any) -> int:
    """
    Planner/FeatureExtractor용: bearer auth_contexts 수 vs auth.accounts 수 중 큰 값.
    """
    contexts = getattr(profile, "auth_contexts", None) or []
    bearer_count = count_effective_auth_contexts(list(contexts))
    auth = getattr(profile, "auth", None)
    account_count = len(auth.accounts) if auth and auth.accounts else 0
    return max(bearer_count, account_count)
