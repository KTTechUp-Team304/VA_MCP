from __future__ import annotations

import pytest

from va_mcp.endpoint_profile import EndpointProfile
from va_mcp.feature_extractor.feature_set import FeatureSet
from va_mcp.feature_extractor.extractor import FeatureExtractor


@pytest.fixture
def extractor() -> FeatureExtractor:
    return FeatureExtractor()


# ------------------------------------------------------------------ #
# 1. 로그인 엔드포인트
# ------------------------------------------------------------------ #

def test_login_endpoint(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="POST",
        path="/api/login",
        body={"username": "user1", "password": "secret"},
        auth_required=False,
        description="사용자 로그인",
    )
    result = extractor.extract(profile)

    assert result.is_login_endpoint is True
    assert result.has_credential_fields is True
    assert result.has_user_input is True
    assert result.is_state_changing is False


# ------------------------------------------------------------------ #
# 2. IDOR 후보 — 경로 파라미터 + 인증
# ------------------------------------------------------------------ #

def test_idor_candidate(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/api/users/{userId}/orders",
        auth_required=True,
        description="특정 사용자의 주문 목록 조회",
    )
    result = extractor.extract(profile)

    assert result.requires_auth is True
    assert result.has_resource_identifier is True
    assert result.has_user_input is False


# ------------------------------------------------------------------ #
# 3. 상태 변경 엔드포인트
# ------------------------------------------------------------------ #

def test_state_changing_endpoint(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="PUT",
        path="/api/orders/42/status",
        body={"status": "approved"},
        side_effect="update",
        auth_required=True,
        description="주문 상태 업데이트",
    )
    result = extractor.extract(profile)

    assert result.is_state_changing is True
    assert result.has_state_field is True
    assert result.requires_auth is True
    assert result.has_user_input is True


# ------------------------------------------------------------------ #
# 4. 검색 엔드포인트 — 자유 입력 + 열거형 입력
# ------------------------------------------------------------------ #

def test_search_endpoint(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/api/products/search",
        query={"keyword": "phone", "type": "electronics"},
        description="상품 검색",
    )
    result = extractor.extract(profile)

    assert result.has_free_text_input is True
    assert result.has_enum_input is True
    assert result.has_user_input is True


# ------------------------------------------------------------------ #
# 5. 관리자 엔드포인트
# ------------------------------------------------------------------ #

def test_admin_endpoint(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/api/admin/users",
        auth_required=True,
        description="관리자 전용 사용자 목록",
    )
    result = extractor.extract(profile)

    assert result.has_admin_feature is True
    assert result.requires_auth is True


# ------------------------------------------------------------------ #
# 6. 파일 업로드 엔드포인트
# ------------------------------------------------------------------ #

def test_file_upload_endpoint(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="POST",
        path="/api/files/upload",
        body={"file": "binary_data"},
        side_effect="create",
        auth_required=True,
        description="파일 업로드",
    )
    result = extractor.extract(profile)

    assert result.has_file_or_config_surface is True
    assert result.is_state_changing is True
    assert result.has_user_input is True


# ------------------------------------------------------------------ #
# 7. 토큰 갱신 엔드포인트
# ------------------------------------------------------------------ #

def test_token_refresh_endpoint(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="POST",
        path="/api/auth/token/refresh",
        body={"refresh": "some_refresh_token"},
        description="액세스 토큰 갱신",
    )
    result = extractor.extract(profile)

    assert result.has_secret_handling is True
    assert result.has_user_input is True


# ------------------------------------------------------------------ #
# 8. 버전/의존성 정보 노출 엔드포인트
# ------------------------------------------------------------------ #

def test_version_info_endpoint(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/api/version",
        description="서버 버전 정보",
    )
    result = extractor.extract(profile)

    assert result.has_dependency_exposure is True
    assert result.has_user_input is False


def test_dependency_exposure_via_resource_context(extractor: FeatureExtractor) -> None:
    """path=/ 이지만 resource_context.dependencies 존재 → has_dependency_exposure=True."""
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/",
        resource_context={"runtime": "node", "dependencies": {"lodash": "4.17.11"}},
    )
    result = extractor.extract(profile)

    assert result.has_dependency_exposure is True


# ------------------------------------------------------------------ #
# 9. 민감 데이터 반환 엔드포인트
# ------------------------------------------------------------------ #

def test_sensitive_data_endpoint(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/api/users/{userId}/profile",
        auth_required=True,
        returns_sensitive_data=True,
        description="사용자 개인정보 조회",
    )
    result = extractor.extract(profile)

    assert result.returns_sensitive_data is True
    assert result.has_resource_identifier is True
    assert result.requires_auth is True


# ------------------------------------------------------------------ #
# 10. 디버그 엔드포인트
# ------------------------------------------------------------------ #

def test_debug_endpoint(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/api/debug/info",
        description="디버그 정보 조회",
    )
    result = extractor.extract(profile)

    assert result.has_debug_feature is True


# ------------------------------------------------------------------ #
# 11. 로깅/감사 엔드포인트
# ------------------------------------------------------------------ #

def test_logging_endpoint(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/api/audit/logs",
        auth_required=True,
        description="감사 로그 조회",
    )
    result = extractor.extract(profile)

    assert result.has_logging_feature is True


# ------------------------------------------------------------------ #
# 13. 고도화 개선 3 — _is_state_changing: side_effect 기본값 + DELETE 메서드
# ------------------------------------------------------------------ #

def test_state_changing_by_delete_method(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="DELETE",
        path="/api/users/{userId}",
        auth_required=True,
        description="사용자 삭제",
        # side_effect 미제공 → 기본값 "read"
    )
    result = extractor.extract(profile)

    # side_effect="read"이지만 DELETE 메서드 → 상태 변경으로 판단
    assert result.is_state_changing is True


# ------------------------------------------------------------------ #
# F-4: last-login 세그먼트 오탐 방지
# ------------------------------------------------------------------ #

def test_last_login_not_login_endpoint(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/api/users/last-login",
        description="마지막 로그인 시각 조회",
    )
    result = extractor.extract(profile)

    assert result.is_login_endpoint is False


# ------------------------------------------------------------------ #
# F-6: administrator 오탐 방지 + super-admin 정탐 확인
# ------------------------------------------------------------------ #

def test_administrator_not_admin_feature(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/api/users/administrator",
        description="관리자 계정 조회",
    )
    result = extractor.extract(profile)

    # "administrator" ≠ sub-word "admin" → 오탐 방지
    assert result.has_admin_feature is False


def test_super_admin_is_admin_feature(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/api/super-admin/settings",
        description="슈퍼 관리자 설정",
    )
    result = extractor.extract(profile)

    # "super-admin" → sub-words {super, admin} → "admin" 탐지
    assert result.has_admin_feature is True


# ------------------------------------------------------------------ #
# F-5: is_valid 키 오탐 방지
# ------------------------------------------------------------------ #

def test_is_valid_not_resource_identifier(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="POST",
        path="/api/orders/validate",
        body={"is_valid": True, "amount": 100},
        description="주문 유효성 검사",
    )
    result = extractor.extract(profile)

    # "is_valid".endswith("id") → True 오탐 방지 — 4패턴 매칭으로 False
    assert result.has_resource_identifier is False


# ------------------------------------------------------------------ #
# F-1: login path에서 "log" substring 오탐 방지
# ------------------------------------------------------------------ #

def test_login_not_logging_feature(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="POST",
        path="/api/auth/login",
        body={"username": "user1", "password": "secret"},
        description="사용자 로그인",
    )
    result = extractor.extract(profile)

    # "login" → sub-words {auth, login} → "log" 없음 → 오탐 방지
    assert result.has_logging_feature is False


# ------------------------------------------------------------------ #
# F-7: 리터럴 숫자 경로 세그먼트 탐지
# ------------------------------------------------------------------ #

def test_literal_numeric_segment_is_resource_identifier(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/api/users/36",
        auth_required=True,
        description="특정 사용자 조회",
    )
    result = extractor.extract(profile)

    # {param} 없이 숫자 세그먼트 "36"만 존재해도 has_resource_identifier=True
    assert result.has_resource_identifier is True


# ------------------------------------------------------------------ #
# 12. 최소 엔드포인트 — 모든 플래그 False
# ------------------------------------------------------------------ #

def test_minimal_endpoint(extractor: FeatureExtractor) -> None:
    profile = EndpointProfile(
        base_url="http://api.example.com",
        method="GET",
        path="/api/health",
        description="헬스체크",
    )
    result = extractor.extract(profile)

    assert result == FeatureSet()
