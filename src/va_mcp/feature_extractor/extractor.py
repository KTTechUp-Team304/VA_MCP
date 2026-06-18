from __future__ import annotations

import re

from va_mcp.endpoint_profile import EndpointProfile
from va_mcp.endpoint_profile.endpoint_profile_auth_normalizer import effective_auth_account_count
from va_mcp.feature_extractor.feature_set import FeatureSet

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
    "log", "logs", "logging", "audit", "event", "events", "history",
})

# 의존성 노출 단서 키워드 (path 대상) — build-info, version, dependency
_DEPENDENCY_KEYWORDS: frozenset[str] = frozenset({
    "build-info", "build_info", "version", "dependency", "dependencies",
})

# 비밀정보 처리 단서 키워드 (path/body 키 대상) — token, secret, api-key, password reset
_SECRET_KEYWORDS: frozenset[str] = frozenset({
    "token", "secret", "api-key", "apikey", "api_key",
    "reset-password", "reset_password", "refresh",
})

# 파일/설정 처리 단서 키워드 (path/body 키 대상)
_FILE_CONFIG_KEYWORDS: frozenset[str] = frozenset({
    "upload", "download", "file", "config", "configuration",
    "export", "import", "backup", "restore",
})

# 메서드 기반 상태 변경 보조 판단 대상 — POST 제외 (로그인·조회 용도로도 쓰임)
_STATE_CHANGING_METHODS: frozenset[str] = frozenset({"PUT", "PATCH", "DELETE"})


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
            requires_auth=profile.auth_required,
            has_resource_identifier=self._has_resource_identifier(profile),
            has_role_restriction=self._has_role_restriction(profile),
            has_auth_accounts=self._has_auth_accounts(profile),
            auth_account_count=effective_auth_account_count(profile),
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

        # 리터럴 숫자 경로 세그먼트 탐지 — /api/users/36 등 치환된 경로 입력
        for segment in profile.path.split('/'):
            if segment and segment.isdigit():
                return True

        # 4가지 패턴만 허용 — endswith("id") 단독 사용 시 is_valid 등 오탐 발생
        for data in (profile.body, profile.query, profile.params):
            if not data:
                continue
            for key in data:
                key_lower = key.lower()
                if (
                    key_lower == "id"                       # 단독 "id" 키
                    or key_lower.endswith("_id")            # snake_case: user_id, order_id
                    or bool(re.search(r"[a-z]Id$", key))   # camelCase: userId, orderId
                    or bool(re.search(r"[a-z]ID$", key))   # 대문자ID: userID, orderID
                ):
                    return True

        return False

    def _has_role_restriction(self, profile: EndpointProfile) -> bool:
        """EndpointProfile.required_roles가 비어 있지 않으면 역할 제한 메타데이터로 본다."""
        return bool(profile.required_roles)

    def _has_auth_accounts(self, profile: EndpointProfile) -> bool:
        """V4 auth.accounts가 1개 이상이면 True."""
        return bool(profile.auth and profile.auth.accounts)

    # ------------------------------------------------------------------ #
    # 상태 관련
    # ------------------------------------------------------------------ #

    def _is_state_changing(self, profile: EndpointProfile) -> bool:
        """side_effect가 create/update/delete이면 상태 변경 엔드포인트로 판단."""
        if profile.side_effect in ("create", "update", "delete"):
            return True
        # side_effect 기본값("read")일 때 HTTP 메서드로 보조 판단
        # PUT/PATCH/DELETE는 의미상 상태 변경이 확실하므로 보조 신호로 활용
        if profile.side_effect == "read" and profile.method.upper() in _STATE_CHANGING_METHODS:
            return True
        return False

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
        # 세그먼트 정확 매칭 — sub-word 미적용: last-login → {last, login}이 되면 오탐 재발
        path_parts = {p for p in profile.path.lower().split("/") if p}
        desc_lower = profile.description.lower()
        return (
            bool(path_parts & _LOGIN_KEYWORDS)
            or any(kw in desc_lower for kw in _LOGIN_KEYWORDS)
        )

    def _has_credential_fields(self, profile: EndpointProfile) -> bool:
        """엔드포인트 자체의 body에 자격증명 키워드가 있는지만 확인한다.

        auth.login.credential_fields는 V4 auth 블록의 로그인 메타데이터로,
        테스트 대상 엔드포인트 자체의 입력 구조와 무관하다.
        profile.credential_fields 역시 파서가 auth 블록에서 전파한 값이므로 제외한다.
        """
        # 엔드포인트 body 키만 확인 — auth 블록 전파값은 모든 엔드포인트에 퍼지므로 오탐 원인
        return self._any_key_matches(profile.body, _CREDENTIAL_KEYS)

    # ------------------------------------------------------------------ #
    # 시스템 관련 (보조 신호 — path 기반)
    # ------------------------------------------------------------------ #

    def _has_admin_feature(self, profile: EndpointProfile) -> bool:
        """path에 'admin' sub-word가 존재하는지 확인. (보조 신호 — path 기반)"""
        # sub-word 매칭: super-admin, admin-panel 등 하이픈 결합도 탐지
        # substring 미적용: administrator → {administrator} ≠ "admin" → 오탐 방지
        return "admin" in self._path_sub_words(profile.path)

    def _has_debug_feature(self, profile: EndpointProfile) -> bool:
        """path에 'debug' sub-word가 존재하는지 확인. (보조 신호 — path 기반)"""
        # sub-word 매칭: debug-mode 등 하이픈 결합도 탐지
        # substring 미적용: debugger → {debugger} ≠ "debug" → 오탐 방지
        return "debug" in self._path_sub_words(profile.path)

    def _has_logging_feature(self, profile: EndpointProfile) -> bool:
        """path 또는 description에 log/audit 관련 키워드가 포함되어 있는지 확인."""
        # sub-word 매칭: audit-log → {audit, log} → "log" 탐지
        # substring 미적용: login → path_sub_words에서 "login" ≠ "log" → 오탐 방지
        path_sub_words = self._path_sub_words(profile.path)
        desc_lower = profile.description.lower()
        return (
            bool(path_sub_words & _LOGGING_KEYWORDS)
            or any(kw in desc_lower for kw in _LOGGING_KEYWORDS)
        )

    # ------------------------------------------------------------------ #
    # A03/A04/A08 보강
    # ------------------------------------------------------------------ #

    def _has_dependency_exposure(self, profile: EndpointProfile) -> bool:
        """path 키워드 또는 resource_context에 의존성 목록이 존재하는지 확인."""
        path_lower = profile.path.lower()
        path_hit = any(kw in path_lower for kw in _DEPENDENCY_KEYWORDS)
        # path=/, resource_context.dependencies 형태에서는 path 키워드가 없으므로 rc도 함께 검사
        rc = profile.resource_context or {}
        rc_hit = "dependencies" in rc
        return path_hit or rc_hit

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

    @staticmethod
    def _path_sub_words(path: str) -> frozenset[str]:
        """URL을 /, -, _ 기준으로 분리해 하위 단어(sub-word) 집합을 반환한다.

        예) /api/super-admin → {api, super, admin}
            /api/audit-log  → {api, audit, log}
        로그인 오탐 방지 목적으로 _is_login_endpoint에는 사용하지 않는다.
        """
        words: set[str] = set()
        for seg in path.lower().split("/"):
            for part in re.split(r"[-_]", seg):
                if part:
                    words.add(part)
        return frozenset(words)
