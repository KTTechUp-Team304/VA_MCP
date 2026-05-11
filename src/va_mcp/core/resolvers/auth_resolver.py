from __future__ import annotations

from typing import Any, Optional, Dict


class CredentialResolverError(Exception):
    """
    credential parsing·mapping 중 발생하는 예외
    """
    pass


def parse_credentials(auth_ctx: Any) -> Dict[str, Optional[str]]:
    """
    AuthContext 안의 token을 내부 표준 키(username, password, token)로 파싱.

    Args:
        auth_ctx: ToolInput.auth 리스트의 단일 AuthContext

    Returns:
        {
            "username": str | None,
            "password": str | None,
            "token": str | None,
        }

    Raises:
        CredentialResolverError: auth_ctx나 token이 비어있거나 포맷이 잘못된 경우
    """
    if not auth_ctx or not getattr(auth_ctx, "token", None):
        raise CredentialResolverError("auth_ctx.token이 비어 있거나 없습니다.")

    t = auth_ctx.token
    fmt = getattr(auth_ctx, "auth_type", "").lower()

    # Basic 형식 (username:password)
    if fmt == "basic":
        if ":" not in t:
            raise CredentialResolverError("Basic auth token 포맷 오류")
        user, pwd = t.split(":", 1)
        return {"username": user, "password": pwd, "token": None}

    # Bearer 형식 (JWT 등)
    if fmt == "bearer":
        return {"username": None, "password": None, "token": t}

    # 미지원 타입
    raise CredentialResolverError(f"지원하지 않는 auth_type: {fmt}")


def apply_field_mapping(
    creds: Dict[str, Optional[str]],
    field_mapping: dict[str, Any],
) -> Dict[str, str]:
    """
    parse_credentials 결과에 planner/orchestrator가 내려준
    field_mapping을 적용하여 실제 요청 payload 키로 변환.

    field_mapping 예시:
        {
            "credential_fields": {
                "username": "email",
                "password": "passwd"
            }
        }

    Args:
        creds: parse_credentials 반환값
        field_mapping: options.extra.get("field_mapping", {})

    Returns:
        실제 request.json/body 에 사용될 { key: value } dict
    """
    result: Dict[str, str] = {}
    fm = field_mapping.get("credential_fields", {})

    if creds.get("username") is not None:
        key_u = fm.get("username", "username")
        result[key_u] = creds["username"]  # type: ignore

    if creds.get("password") is not None:
        key_p = fm.get("password", "password")
        result[key_p] = creds["password"]  # type: ignore

    return result


def resolve_auth_headers(
    auth_ctx: Any,
) -> Dict[str, str]:
    """
    Bearer 타입일 경우 Authorization 헤더 생성.
    Basic 은 body payload로만 전달하므로 빈 dict 반환.

    Args:
        auth_ctx: ToolInput.auth 리스트의 단일 AuthContext

    Returns:
        {"Authorization": "Bearer <token>"} 또는 {}
    """
    fmt = getattr(auth_ctx, "auth_type", "").lower()
    if fmt == "bearer":
        token = getattr(auth_ctx, "token", "")
        return {"Authorization": f"Bearer {token}"}
    return {}