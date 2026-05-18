from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class LoginConfig:
    """V4 auth.login — AuthProvider가 login HTTP 요청을 조립할 때 사용."""

    path: str
    method: str = "POST"
    credential_fields: dict[str, str] = field(default_factory=dict)
    token_json_path: str = "accessToken"


@dataclass
class LogoutConfig:
    """V4 auth.logout — AuthProvider가 분석 종료 후 세션 정리 HTTP에 사용."""

    path: str
    method: str = "POST"
    refresh_cookie_name: str | None = None


@dataclass
class AccountCredential:
    """V4 auth.accounts[] — 테스트 계정 (provide_auth 전, JWT 없음)."""

    username: str
    password: str
    role: str


@dataclass
class AuthConfig:
    """V4 auth 블록 정규화 결과."""

    login: LoginConfig | None = None
    logout: LogoutConfig | None = None
    accounts: list[AccountCredential] = field(default_factory=list)

    def to_serializable_dict(self) -> dict[str, Any]:
        return asdict(self)
