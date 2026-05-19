from __future__ import annotations

from typing import Any

import requests

from va_mcp.endpoint_profile.auth_config import AccountCredential, AuthConfig, LoginConfig, LogoutConfig
from va_mcp.core.schemas import AuthContext


class AuthProvider:
    """
    AuthConfig를 기반으로 테스트 계정별 access token을 발급하고 캐싱한다.
    orchestrator가 build_tool_input 전에 provide_auth()를 호출하여 auth_contexts를 구성하고,
    스캔 완료 후 logout_all()을 호출하여 발급된 토큰을 폐기한다.

    사용 예시:
        provider = AuthProvider(base_url, profile.auth)
        auth_contexts = provider.provide_auth()
        # ... 스캔 실행 ...
        provider.logout_all()
    """

    def __init__(self, base_url: str, auth_config: AuthConfig) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_config = auth_config
        # role → {"access_token": str, "refresh_token": str}
        self._token_cache: dict[str, dict[str, str]] = {}

    def provide_auth(self) -> list[AuthContext]:
        """
        accounts를 순회하며 로그인 요청으로 role별 access_token을 발급받고
        AuthContext 목록으로 반환한다.
        로그인 실패한 계정은 결과에서 제외된다.
        """
        if not self._auth_config or not self._auth_config.login:
            return []

        login_cfg = self._auth_config.login
        auth_contexts: list[AuthContext] = []

        for account in (self._auth_config.accounts or []):
            tokens = self._login(account, login_cfg)
            if tokens:
                self._token_cache[account.role] = tokens
                auth_contexts.append(
                    AuthContext(
                        role=account.role,
                        auth_type="bearer",
                        token=tokens["access_token"],
                    )
                )

        return auth_contexts

    def provide_basic_auth(self) -> list[AuthContext]:
        """
        원본 자격증명을 basic AuthContext로 반환한다.
        auth_bruteforce / auth_lockout / auth_rate_limit / auth_enum 전용.
        token 필드에 "username:password" 포맷으로 담아 auth_resolver가 파싱할 수 있게 한다.
        """
        return [
            AuthContext(
                role=account.role,
                auth_type="basic",
                token=f"{account.username}:{account.password}",
            )
            for account in (self._auth_config.accounts or [])
        ]

    def logout_all(self) -> None:
        """
        캐싱된 모든 계정의 토큰을 폐기한다.
        스캔 완료 후 orchestrator가 호출한다.
        AuthConfig.logout이 없으면 건너뜀.
        """
        logout_cfg: LogoutConfig | None = self._auth_config.logout
        if not logout_cfg:
            self._token_cache.clear()
            return

        url = f"{self._base_url}/{logout_cfg.path.lstrip('/')}"
        cookie_name = logout_cfg.refresh_cookie_name or "refreshToken"

        for role, tokens in self._token_cache.items():
            try:
                requests.request(
                    method=logout_cfg.method,
                    url=url,
                    headers={
                        "Authorization": f"Bearer {tokens['access_token']}",
                        "Cookie": f"{cookie_name}={tokens['refresh_token']}",
                    },
                    timeout=10,
                )
            except Exception:
                pass  # 로그아웃 실패는 무시 (스캔 결과에 영향 없음)

        self._token_cache.clear()

    def _login(self, account: AccountCredential, login_cfg: LoginConfig) -> dict[str, str] | None:
        """
        단일 계정으로 로그인 요청을 보내 access_token과 refresh_token을 반환한다.
        실패 시 None 반환.
        """
        url = f"{self._base_url}/{login_cfg.path.lstrip('/')}"

        # credential_fields 매핑으로 실제 body 필드명 구성
        # 예: {"username": "username", "password": "passwordHash"}
        cred_fields = login_cfg.credential_fields or {}
        username_key = cred_fields.get("username", "username")
        password_key = cred_fields.get("password", "password")

        body: dict[str, Any] = {
            username_key: account.username,
            password_key: account.password,
        }

        try:
            resp = requests.request(
                method=login_cfg.method,
                url=url,
                json=body,
                timeout=10,
            )
            if resp.status_code not in (200, 201):
                return None

            data = resp.json()
            access_token = data.get(login_cfg.token_json_path)
            refresh_token = data.get("refreshToken")

            if not isinstance(access_token, str):
                return None

            return {
                "access_token": access_token,
                "refresh_token": refresh_token or "",
            }

        except Exception:
            return None
