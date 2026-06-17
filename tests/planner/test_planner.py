"""
ScenarioPlanner 테스트 — OWASP Top 10 2025 기준

테스트 구성:
  [baseline]
  test_baseline_always_includes_a02_a10           - 빈 FeatureSet에서도 A02/A10 항상 선정
  test_baseline_tool_ids_always_present           - A02/A10 tool_ids 항상 포함

  [A01] Broken Access Control
  test_a01_selected_by_resource_identifier        - requires_auth + has_resource_identifier → A01 선정
  test_a01_selected_by_auth_contexts              - requires_auth + auth_contexts>=2 → A01 선정
  test_a01_not_selected_without_requires_auth     - requires_auth=False → A01 미선정
  test_a01_need_more_context                      - 조건 미충족 → need_more_context=True, A01은 forced_browsing/cors_check으로 유지
  test_a01_missing_list_content                   - missing 리스트에 auth_contexts/resource_context 포함

  [A03] Software Supply Chain Failures
  test_a03_dependency_exposure                    - has_dependency_exposure → A03 선정

  [A05] Injection
  test_a05_user_input_with_free_text              - has_user_input + has_free_text_input → A05 선정
  test_a05_user_input_with_file_surface           - has_user_input + has_file_or_config_surface → A05 선정
  test_a05_user_input_alone_only_header_injection  - has_user_input 단독 → header_injection만 선정, A05 포함

  [A04] Cryptographic Failures
  test_a04_secret_handling                        - has_secret_handling → A04 선정
  test_a04_not_selected_without_secret_handling   - has_secret_handling=False → A04 미선정

  [A06] Insecure Design
  test_a06_state_changing                         - is_state_changing + has_state_field → A06 선정
  test_a06_state_changing_alone_rate_limit_only   - is_state_changing 단독 → rate_limit_check만 선정, A06 포함

  [A07] Authentication Failures
  test_a07_login_endpoint                         - is_login_endpoint → A07 선정
  test_a07_credential_fields                      - has_credential_fields → A07 선정
  test_a07_requires_auth                          - requires_auth → A07 선정

  [A08] Software or Data Integrity Failures
  test_a08_file_surface_with_state_changing       - has_file_or_config_surface + is_state_changing → A08 선정
  test_a08_file_surface_alone_not_selected        - has_file_or_config_surface 단독 → A08 미선정

  [A09] Security Logging and Alerting Failures
  test_a09_logging_feature                        - has_logging_feature → A09 선정

  [tool_ids]
  test_tool_ids_deduplicated                      - 중복 tool_id 제거
  test_tool_ids_order_preserved                   - baseline tool_ids 순서 보존

  [FeatureSet 타입]
  test_feature_set_as_dataclass                   - dataclass 형태의 FeatureSet 지원
  test_feature_set_as_dict                        - dict 형태의 FeatureSet 지원

  [복합]
  test_full_featured_endpoint                     - 모든 조건 충족 시 전체 후보 선정
"""

from dataclasses import dataclass

import pytest

from va_mcp.planner import ScenarioPlanner
from va_mcp.planner.baseline import A02_BASELINE_TOOL_IDS, A10_BASELINE_TOOL_IDS


# ------------------------------------------------------------------
# 헬퍼
# ------------------------------------------------------------------

@dataclass
class FeatureSet:
    requires_auth: bool = False
    has_resource_identifier: bool = False
    auth_contexts: int = 0
    resource_context: bool = False
    has_dependency_exposure: bool = False
    has_secret_handling: bool = False
    has_user_input: bool = False
    has_free_text_input: bool = False
    has_file_or_config_surface: bool = False
    is_state_changing: bool = False
    has_state_field: bool = False
    is_login_endpoint: bool = False
    has_credential_fields: bool = False
    has_logging_feature: bool = False
    has_admin_feature: bool = False
    has_role_restriction: bool = False


@pytest.fixture
def planner() -> ScenarioPlanner:
    return ScenarioPlanner()


@pytest.fixture
def empty_fs() -> FeatureSet:
    return FeatureSet()


# ------------------------------------------------------------------
# baseline
# ------------------------------------------------------------------

def test_baseline_always_includes_a02_a10(planner, empty_fs):
    """FeatureSet이 비어 있어도 A02, A10은 반드시 candidates에 포함된다."""
    out = planner.plan(empty_fs)
    assert "A02" in out.owasp_candidates
    assert "A10" in out.owasp_candidates


def test_baseline_tool_ids_always_present(planner, empty_fs):
    """A02, A10 baseline tool_ids는 조건 무관하게 항상 tool_ids에 포함된다."""
    out = planner.plan(empty_fs)
    for tid in list(A02_BASELINE_TOOL_IDS) + list(A10_BASELINE_TOOL_IDS):
        assert tid in out.tool_ids, f"baseline tool '{tid}' missing"


# ------------------------------------------------------------------
# A01 — Broken Access Control
# ------------------------------------------------------------------

def test_a01_selected_by_resource_identifier(planner):
    """requires_auth=True + has_resource_identifier=True + auth_contexts>=2 → idor_bola 선정."""
    fs = FeatureSet(requires_auth=True, has_resource_identifier=True, auth_contexts=2)
    out = planner.plan(fs)
    assert "A01" in out.owasp_candidates
    assert "idor_bola" in out.tool_ids
    assert out.need_more_context is False


def test_a01_selected_by_auth_contexts(planner):
    """requires_auth=True + auth_contexts>=2 → A01 선정 (resource_identifier 없어도)."""
    fs = FeatureSet(requires_auth=True, auth_contexts=2, resource_context=True)
    out = planner.plan(fs)
    assert "A01" in out.owasp_candidates
    assert out.need_more_context is False


def test_a01_not_selected_without_requires_auth(planner):
    """requires_auth=False → A01 선정 안 됨, need_more_context도 False."""
    fs = FeatureSet(requires_auth=False, has_resource_identifier=True)
    out = planner.plan(fs)
    assert "A01" not in out.owasp_candidates
    assert out.need_more_context is False


def test_a01_vertical_selected_by_admin_feature(planner):
    """requires_auth + has_admin_feature + auth_contexts>=2 → bfla/rbac_check 선정."""
    fs = FeatureSet(requires_auth=True, has_admin_feature=True, auth_contexts=2)
    out = planner.plan(fs)
    assert "A01" in out.owasp_candidates
    assert "bfla" in out.tool_ids
    assert "rbac_check" in out.tool_ids


def test_a01_vertical_rbac_requires_two_auth_contexts(planner):
    """requires_auth + has_admin_feature + auth_contexts>=2 → rbac_check 선정."""
    fs = FeatureSet(requires_auth=True, has_admin_feature=True, auth_contexts=2)
    out = planner.plan(fs)
    assert "rbac_check" in out.tool_ids


def test_a01_vertical_selected_by_role_restriction(planner):
    """requires_auth + has_role_restriction + auth_contexts>=2 → bfla/rbac_check 선정."""
    fs = FeatureSet(requires_auth=True, has_role_restriction=True, auth_contexts=2)
    out = planner.plan(fs)
    assert "A01" in out.owasp_candidates
    assert "bfla" in out.tool_ids
    assert "rbac_check" in out.tool_ids


def test_a01_bfla_not_selected_without_admin(planner):
    """requires_auth + has_resource_identifier + auth_contexts>=2 → idor_bola 선정, bfla 미선정."""
    fs = FeatureSet(requires_auth=True, has_resource_identifier=True, auth_contexts=2)
    out = planner.plan(fs)
    assert "idor_bola" in out.tool_ids
    assert "bfla" not in out.tool_ids
    assert "rbac_check" not in out.tool_ids


def test_a01_need_more_context(planner):
    """requires_auth + has_resource_identifier이지만 auth_contexts<2.

    forced_browsing/cors_check이 선정되므로 need_more_context=False.
    missing에는 auth_contexts가 담겨 caller가 보강 여부를 판단한다.
    """
    fs = FeatureSet(
        requires_auth=True,
        has_resource_identifier=True,
        auth_contexts=1,
    )
    out = planner.plan(fs)
    assert out.need_more_context is False
    assert "auth_contexts" in out.missing
    assert "A01" in out.owasp_candidates


def test_a01_missing_list_content(planner):
    """has_resource_identifier=True인데 auth_contexts<2 → missing에 auth_contexts 포함."""
    fs = FeatureSet(
        requires_auth=True,
        has_resource_identifier=True,
        auth_contexts=1,
    )
    out = planner.plan(fs)
    assert "auth_contexts" in out.missing


# ------------------------------------------------------------------
# A03 — Software Supply Chain Failures
# ------------------------------------------------------------------

def test_a03_dependency_exposure(planner):
    """has_dependency_exposure=True → A03 선정 + dependency_check 도구 포함."""
    fs = FeatureSet(has_dependency_exposure=True)
    out = planner.plan(fs)
    assert "A03" in out.owasp_candidates
    assert "dependency_check" in out.tool_ids


# ------------------------------------------------------------------
# A05 — Injection
# ------------------------------------------------------------------

def test_a05_user_input_with_free_text(planner):
    """has_user_input=True + has_free_text_input=True → A05 선정."""
    fs = FeatureSet(has_user_input=True, has_free_text_input=True)
    out = planner.plan(fs)
    assert "A05" in out.owasp_candidates


def test_a05_user_input_with_file_surface(planner):
    """has_user_input=True + has_file_or_config_surface=True → A05 선정."""
    fs = FeatureSet(has_user_input=True, has_file_or_config_surface=True)
    out = planner.plan(fs)
    assert "A05" in out.owasp_candidates


def test_a05_user_input_alone_only_header_injection(planner):
    """has_user_input=True 단독 → header_injection만 선정 (sql/cmd/xss 등은 미선정)."""
    fs = FeatureSet(has_user_input=True)
    out = planner.plan(fs)
    assert "header_injection" in out.tool_ids
    assert "sql_injection" not in out.tool_ids
    assert "xss_reflected" not in out.tool_ids
    assert "cmd_injection" not in out.tool_ids


# ------------------------------------------------------------------
# A04 — Cryptographic Failures
# ------------------------------------------------------------------

def test_a04_secret_handling(planner):
    """has_secret_handling=True → A04 선정."""
    fs = FeatureSet(has_secret_handling=True)
    out = planner.plan(fs)
    assert "A04" in out.owasp_candidates


def test_a04_not_selected_without_secret_handling(planner):
    """has_secret_handling=False → A04 미선정."""
    fs = FeatureSet(has_secret_handling=False)
    out = planner.plan(fs)
    assert "A04" not in out.owasp_candidates


# ------------------------------------------------------------------
# A06 — Insecure Design
# ------------------------------------------------------------------

def test_a06_state_changing(planner):
    """is_state_changing=True + has_state_field=True → A06 선정."""
    fs = FeatureSet(is_state_changing=True, has_state_field=True)
    out = planner.plan(fs)
    assert "A06" in out.owasp_candidates


def test_a06_state_changing_alone_rate_limit_only(planner):
    """is_state_changing=True 단독 → A06 선정, rate_limit_check만 포함."""
    fs = FeatureSet(is_state_changing=True, has_state_field=False)
    out = planner.plan(fs)
    assert "A06" in out.owasp_candidates
    assert "rate_limit_check" in out.tool_ids
    assert "business_logic_check" not in out.tool_ids  # has_state_field 없음


# ------------------------------------------------------------------
# A07 — Authentication Failures
# ------------------------------------------------------------------

def test_a07_login_endpoint(planner):
    """is_login_endpoint=True → A07 선정."""
    fs = FeatureSet(is_login_endpoint=True)
    out = planner.plan(fs)
    assert "A07" in out.owasp_candidates


def test_a07_credential_fields(planner):
    """has_credential_fields=True → A07 선정."""
    fs = FeatureSet(has_credential_fields=True)
    out = planner.plan(fs)
    assert "A07" in out.owasp_candidates


def test_a07_requires_auth(planner):
    """requires_auth=True → A07 선정."""
    fs = FeatureSet(requires_auth=True)
    out = planner.plan(fs)
    assert "A07" in out.owasp_candidates


# ------------------------------------------------------------------
# A08 — Software or Data Integrity Failures
# ------------------------------------------------------------------

def test_a08_file_surface_with_state_changing(planner):
    """has_file_or_config_surface=True + is_state_changing=True → A08 선정."""
    fs = FeatureSet(has_file_or_config_surface=True, is_state_changing=True)
    out = planner.plan(fs)
    assert "A08" in out.owasp_candidates
    assert "http_method_tamper" in out.tool_ids
    assert "business_logic_check" in out.tool_ids


def test_a08_file_surface_alone_not_selected(planner):
    """has_file_or_config_surface=True 단독 → is_state_changing, has_user_input 없으면 A08 미선정."""
    fs = FeatureSet(has_file_or_config_surface=True)
    out = planner.plan(fs)
    assert "A08" not in out.owasp_candidates


# ------------------------------------------------------------------
# A09 — Security Logging and Alerting Failures
# ------------------------------------------------------------------

def test_a09_logging_feature(planner):
    """has_logging_feature=True → A09 선정."""
    fs = FeatureSet(has_logging_feature=True)
    out = planner.plan(fs)
    assert "A09" in out.owasp_candidates


# ------------------------------------------------------------------
# tool_ids
# ------------------------------------------------------------------

def test_tool_ids_deduplicated(planner):
    """A01과 A08에 겹치는 tool_id가 있어도 중복 없이 한 번만 포함된다."""
    fs = FeatureSet(
        requires_auth=True,
        has_resource_identifier=True,
        resource_context=True,
        has_file_or_config_surface=True,
    )
    out = planner.plan(fs)
    assert len(out.tool_ids) == len(set(out.tool_ids))


def test_tool_ids_order_preserved(planner, empty_fs):
    """baseline tool_ids는 삽입 순서대로 반환된다."""
    out = planner.plan(empty_fs)
    a02_ids = [t for t in out.tool_ids if t in A02_BASELINE_TOOL_IDS]
    assert a02_ids == [t for t in A02_BASELINE_TOOL_IDS if t in out.tool_ids]


# ------------------------------------------------------------------
# FeatureSet 타입
# ------------------------------------------------------------------

def test_feature_set_as_dataclass(planner):
    """dataclass 형태의 FeatureSet을 지원한다."""
    fs = FeatureSet(has_logging_feature=True)
    out = planner.plan(fs)
    assert "A09" in out.owasp_candidates


def test_feature_set_as_dict(planner):
    """dict 형태의 FeatureSet을 지원한다."""
    fs = {"has_logging_feature": True}
    out = planner.plan(fs)
    assert "A09" in out.owasp_candidates


# ------------------------------------------------------------------
# 복합
# ------------------------------------------------------------------

def test_full_featured_endpoint(planner):
    """모든 조건을 충족하면 A01~A10 전체 후보가 선정된다."""
    fs = FeatureSet(
        requires_auth=True,
        has_resource_identifier=True,
        resource_context=True,
        auth_contexts=2,
        has_dependency_exposure=True,
        has_secret_handling=True,
        has_user_input=True,
        has_free_text_input=True,
        has_file_or_config_surface=True,
        is_state_changing=True,
        has_state_field=True,
        is_login_endpoint=True,
        has_logging_feature=True,
    )
    out = planner.plan(fs)
    for code in ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]:
        assert code in out.owasp_candidates, f"{code} missing"
