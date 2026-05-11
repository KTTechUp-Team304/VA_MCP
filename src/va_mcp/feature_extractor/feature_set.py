from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FeatureSet:
    """
    EndpointProfile에서 추출된 분석 신호 집합.
    ScenarioPlanner가 OWASP 항목별 실행 여부를 판단하는 기준이 된다.
    모든 필드는 bool 타입이며, FeatureExtractor가 자동 추출하거나 EndpointProfile 값을 직접 반영한다.
    V3.1 §3 스펙 기준으로 정의된다.
    """

    # ===== 입력 =====
    has_user_input: bool = False
    # body/query/params 중 하나라도 값이 존재하는지 여부

    has_free_text_input: bool = False
    # keyword/search/text 등 자유 입력 필드가 body 또는 query에 존재하는지 여부

    has_enum_input: bool = False
    # status/type/role 등 제한된 열거형 입력 필드가 존재하는지 여부

    # ===== 권한 =====
    requires_auth: bool = False
    # 인증 필요 여부 (EndpointProfile.auth_required 직접 반영)

    has_resource_identifier: bool = False
    # userId, courseId 등 리소스 식별자가 path/body/query/params에 존재하는지 여부

    # ===== 상태 =====
    is_state_changing: bool = False
    # side_effect가 create/update/delete인 경우 True

    has_state_field: bool = False
    # status/role 등 상태를 변경하는 필드가 body에 존재하는지 여부

    # ===== 인증 =====
    is_login_endpoint: bool = False
    # login 관련 엔드포인트 여부 (path 또는 description의 키워드로 판단)

    has_credential_fields: bool = False
    # username/password 등 자격증명 필드가 body에 존재하는지 여부

    # ===== 시스템 =====
    has_admin_feature: bool = False
    # /admin 경로 포함 여부 (보조 신호 — path 기반)

    has_debug_feature: bool = False
    # /debug 경로 포함 여부 (보조 신호 — path 기반)

    has_logging_feature: bool = False
    # log/audit 관련 키워드가 path 또는 description에 존재하는지 여부

    # ===== A03/A04/A08 보강 =====
    has_dependency_exposure: bool = False
    # build-info, version, dependency 등 의존성 정보 노출 단서가 path에 존재하는지 여부

    has_secret_handling: bool = False
    # token/secret/api-key/password reset 등 비밀정보 처리 단서가 path 또는 body에 존재하는지 여부

    has_file_or_config_surface: bool = False
    # file upload/download, config export/import 단서가 path 또는 body에 존재하는지 여부

    # ===== 응답 =====
    returns_sensitive_data: bool = False
    # 민감 데이터 반환 여부 (EndpointProfile.returns_sensitive_data 직접 반영)
