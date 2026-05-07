from __future__ import annotations

import re

from va_mcp.core.endpoint_profile import EndpointProfile
from va_mcp.core.feature_set import FeatureSet

# ------------------------------------------------------------------ #
# 키워드 상수 — V3.1 §3 스펙 기준으로 정의
# 각 집합은 해당 Feature 판단에 사용되는 필드 키 또는 경로 키워드다.
# ------------------------------------------------------------------ #

# 자유 입력(free text) 필드로 판단할 키 키워드 (body/query 키 대상)
_FREE_TEXT_KEYS: frozenset[str] = frozenset({
    "keyword", "search", "text", "q", "query", "content", "message", "input", "term",
})

# 열거형(enum) 입력 필드로 판단할 키 키워드 (body/query 키 대상)
_ENUM_KEYS: frozenset[str] = frozenset({
    "status", "type", "role", "category", "state", "mode",
})

# 상태 변경 필드로 판단할 키 키워드 (body 키 대상)
_STATE_FIELD_KEYS: frozenset[str] = frozenset({
    "status", "role", "state", "active", "enabled", "disabled", "approved",
})

# 자격증명 필드로 판단할 키 키워드 (body 키 대상)
_CREDENTIAL_KEYS: frozenset[str] = frozenset({
    "username", "password", "passwd", "pwd",
})

# 로그인 엔드포인트 판단 키워드 (path/description 대상, 보조 신호)
_LOGIN_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "sign-in",
})

# 로깅 기능 판단 키워드 (path/description 대상)
_LOGGING_KEYWORDS: frozenset[str] = frozenset({
    "log", "logs", "audit", "event", "events", "history",
})

# 의존성 노출 단서 키워드 (path 대상) — build-info, version, dependency
_DEPENDENCY_KEYWORDS: frozenset[str] = frozenset({
    "build-info", "build_info", "version", "dependency", "dependencies", "actuator",
})

# 비밀정보 처리 단서 키워드 (path/body 키 대상) — token, secret, api-key, password reset
_SECRET_KEYWORDS: frozenset[str] = frozenset({
    "token", "secret", "api-key", "apikey", "api_key",
    "reset-password", "reset_password", "refresh", "revoke",
})

# 파일/설정 처리 단서 키워드 (path/body 키 대상)
_FILE_CONFIG_KEYWORDS: frozenset[str] = frozenset({
    "upload", "download", "file", "config", "configuration",
    "export", "import", "backup", "restore",
})


class FeatureExtractor:
    """
    EndpointProfile을 입력받아 FeatureSet으로 변환하는 순수 변환 클래스.
    HTTP 요청을 보내지 않으며 부작용이 없다.
    Planner가 OWASP A01~A10 항목별 실행 여부를 판단하는 신호(FeatureSet)를 생성한다.
    """

    def extract(self, profile: EndpointProfile) -> FeatureSet:
        """EndpointProfile을 받아 분석 신호 집합(FeatureSet)으로 변환한다."""
        return FeatureSet(
            # ===== 입력 =====
            has_user_input=self._has_user_input(profile),
            has_free_text_input=self._has_free_text_input(profile),
            has_enum_input=self._has_enum_input(profile),
            # ===== 권한 =====
            requires_auth=profile.auth_required,                        # EndpointProfile 값 직접 반영
            has_resource_identifier=self._has_resource_identifier(profile),
            # ===== 상태 =====
            is_state_changing=self._is_state_changing(profile),
            has_state_field=self._has_state_field(profile),
            # ===== 인증 =====
            is_login_endpoint=self._is_login_endpoint(profile),
            has_credential_fields=self._has_credential_fields(profile),
            # ===== 시스템 (보조 신호 — path 기반) =====
            has_admin_feature=self._has_admin_feature(profile),
            has_debug_feature=self._has_debug_feature(profile),
            has_logging_feature=self._has_logging_feature(profile),
            # ===== A03/A04/A08 보강 =====
            has_dependency_exposure=self._has_dependency_exposure(profile),
            has_secret_handling=self._has_secret_handling(profile),
            has_file_or_config_surface=self._has_file_or_config_surface(profile),
            # ===== 응답 =====
            returns_sensitive_data=profile.returns_sensitive_data,      # EndpointProfile 값 직접 반영
        )

    # ------------------------------------------------------------------ #
    # 입력 관련
    # ------------------------------------------------------------------ #

    def _has_user_input(self, profile: EndpointProfile) -> bool:
        """body/query/params 중 하나라도 값이 있으면 사용자 입력이 존재한다고 판단."""
        return bool(profile.body or profile.query or profile.params)

    def _has_free_text_input(self, profile: EndpointProfile) -> bool:
        """body 또는 query에 자유 입력 키워드(search, keyword, text 등)가 키로 존재하는지 확인."""
        return (
            self._any_key_matches(profile.body, _FREE_TEXT_KEYS)
            or self._any_key_matches(profile.query, _FREE_TEXT_KEYS)
        )

    def _has_enum_input(self, profile: EndpointProfile) -> bool:
        """body 또는 query에 열거형 키워드(status, type, role 등)가 키로 존재하는지 확인."""
        return (
            self._any_key_matches(profile.body, _ENUM_KEYS)
            or self._any_key_matches(profile.query, _ENUM_KEYS)
        )

    # ------------------------------------------------------------------ #
    # 권한 관련
    # ------------------------------------------------------------------ #

    def _has_resource_identifier(self, profile: EndpointProfile) -> bool:
        """
        리소스 식별자 존재 여부를 판단한다.
        path의 {param} 패턴은 보조 신호로 사용하며, body/query/params의 *id 키도 확인한다.
        """
        # path의 경로 파라미터 {userId} 등은 리소스 식별자의 강한 단서 (보조 신호)
        if re.search(r"\{[^}]+\}", profile.path):
            return True

        # camelCase(userId→userid)와 스네이크케이스(user_id) 모두 처리하기 위해
        # endswith("id")와 endswith("_id")를 함께 사용한다
        for data in (profile.body, profile.query, profile.params):
            if not data:
                continue
            for key in data:
                key_lower = key.lower()
                if key_lower.endswith("_id") or key_lower.endswith("id"):
                    return True

        return False

    # ------------------------------------------------------------------ #
    # 상태 관련
    # ------------------------------------------------------------------ #

    def _is_state_changing(self, profile: EndpointProfile) -> bool:
        """side_effect가 create/update/delete이면 상태 변경 엔드포인트로 판단."""
        return profile.side_effect in ("create", "update", "delete")

    def _has_state_field(self, profile: EndpointProfile) -> bool:
        """body에 상태 변경 키워드(status, role, state 등)가 키로 존재하는지 확인."""
        # 상태 변경은 REST 규약상 request body로 전달되므로 query는 검사하지 않는다
        return self._any_key_matches(profile.body, _STATE_FIELD_KEYS)

    # ------------------------------------------------------------------ #
    # 인증 관련
    # ------------------------------------------------------------------ #

    def _is_login_endpoint(self, profile: EndpointProfile) -> bool:
        """
        path 또는 description에 login 관련 키워드가 포함되어 있는지 확인한다.
        path 기반 판단은 보조 신호이며, description 키워드 매칭과 함께 사용한다.
        """
        path_lower = profile.path.lower()
        desc_lower = profile.description.lower()
        return (
            any(kw in path_lower for kw in _LOGIN_KEYWORDS)
            or any(kw in desc_lower for kw in _LOGIN_KEYWORDS)
        )

    def _has_credential_fields(self, profile: EndpointProfile) -> bool:
        """body에 자격증명 키워드(username, password 등)가 키로 존재하는지 확인."""
        return self._any_key_matches(profile.body, _CREDENTIAL_KEYS)

    # ------------------------------------------------------------------ #
    # 시스템 관련 (보조 신호 — path 기반)
    # ------------------------------------------------------------------ #

    def _has_admin_feature(self, profile: EndpointProfile) -> bool:
        """path에 'admin' 키워드가 포함되어 있는지 확인. (보조 신호 — path 기반)"""
        return "admin" in profile.path.lower()

    def _has_debug_feature(self, profile: EndpointProfile) -> bool:
        """path에 'debug' 키워드가 포함되어 있는지 확인. (보조 신호 — path 기반)"""
        return "debug" in profile.path.lower()

    def _has_logging_feature(self, profile: EndpointProfile) -> bool:
        """path 또는 description에 log/audit 관련 키워드가 포함되어 있는지 확인."""
        path_lower = profile.path.lower()
        desc_lower = profile.description.lower()
        return (
            any(kw in path_lower for kw in _LOGGING_KEYWORDS)
            or any(kw in desc_lower for kw in _LOGGING_KEYWORDS)
        )

    # ------------------------------------------------------------------ #
    # A03/A04/A08 보강
    # ------------------------------------------------------------------ #

    def _has_dependency_exposure(self, profile: EndpointProfile) -> bool:
        """path에 build-info/version/dependency 등 의존성 노출 단서 키워드가 포함되어 있는지 확인."""
        path_lower = profile.path.lower()
        return any(kw in path_lower for kw in _DEPENDENCY_KEYWORDS)

    def _has_secret_handling(self, profile: EndpointProfile) -> bool:
        """path 또는 body 키에 token/secret/api-key 등 비밀정보 처리 단서가 있는지 확인."""
        path_lower = profile.path.lower()
        return (
            any(kw in path_lower for kw in _SECRET_KEYWORDS)
            or self._any_key_matches(profile.body, _SECRET_KEYWORDS)
        )

    def _has_file_or_config_surface(self, profile: EndpointProfile) -> bool:
        """path 또는 body 키에 file upload/download, config export/import 단서가 있는지 확인."""
        path_lower = profile.path.lower()
        return (
            any(kw in path_lower for kw in _FILE_CONFIG_KEYWORDS)
            or self._any_key_matches(profile.body, _FILE_CONFIG_KEYWORDS)
        )

    # ------------------------------------------------------------------ #
    # 공통 유틸
    # ------------------------------------------------------------------ #

    @staticmethod
    def _any_key_matches(data: dict | None, keywords: frozenset[str]) -> bool:
        """data dict의 키(소문자 변환)가 keywords 집합과 교집합이 있으면 True를 반환한다."""
        if not data:
            return False
        # 소문자 변환 후 집합 교차 연산으로 O(n) 탐색
        return bool({k.lower() for k in data} & keywords)
