"""
ScenarioPlanner 테스트.

테스트 구성:
  [baseline]
  test_baseline_always_includes_a02_a10         - 빈 FeatureSet에서도 A02/A10 항상 선정
  test_baseline_tool_ids_always_present         - A02/A10 tool_ids 항상 포함

  [A01]
  test_a01_selected_by_resource_identifier      - requires_auth + has_resource_identifier → A01 선정
  test_a01_selected_by_auth_contexts            - requires_auth + auth_contexts>=2 → A01 선정
  test_a01_not_selected_without_requires_auth   - requires_auth=False → A01 미선정
  test_a01_need_more_context                    - 조건 미충족 → need_more_context=True, A01 제외
  test_a01_missing_list_content                 - missing 리스트에 auth_contexts/resource_context 포함

  [A03~A09]
  test_a03_dependency_exposure                  - has_dependency_exposure → A03 선정
  test_a04_secret_handling                      - has_secret_handling → A04 선정
  test_a05_user_input_with_free_text            - has_user_input + has_free_text_input → A05 선정
  test_a05_user_input_with_file_surface         - has_user_input + has_file_or_config_surface → A05 선정
  test_a05_not_selected_user_input_alone        - has_user_input 단독 → A05 미선정 (과탐 방지)
  test_a06_state_changing                       - is_state_changing + has_state_field → A06 선정
  test_a06_not_selected_partial                 - is_state_changing 단독 → A06 미선정
  test_a07_login_endpoint                       - is_login_endpoint → A07 선정
  test_a07_credential_fields                    - has_credential_fields → A07 선정
  test_a07_requires_auth                        - requires_auth → A07 선정
  test_a08_file_surface                         - has_file_or_config_surface → A08 선정
  test_a09_logging_feature                      - has_logging_feature → A09 선정

  [tool_ids]
  test_tool_ids_deduplicated                    - 중복 tool_id 제거
  test_tool_ids_order_preserved                 - baseline tool_ids 순서 보존

  [FeatureSet 타입]
  test_feature_set_as_dataclass                 - dataclass 형태의 FeatureSet 지원
  test_feature_set_as_dict                      - dict 형태의 FeatureSet 지원

  [복합]
  test_full_featured_endpoint                   - 모든 조건 충족 시 전체 후보 선정
"""

from dataclasses import dataclass, field

import pytest

from va_mcp.planner import ScenarioPlanner
from va_mcp.planner.baseline import A02_BASELINE_TOOL_IDS, A10_BASELINE_TOOL_IDS
from va_mcp.planner.rules import OWASP_TOOL_MAP


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
    for tid in A02_BASELINE_TOOL_IDS + A10_BASELINE_TOOL_IDS:
        assert tid in out.tool_ids, f"baseline tool '{tid}' missing"


# ------------------------------------------------------------------
# A01
# ------------------------------------------------------------------

def test_a01_selected_by_resource_identifier(planner):
    """requires_auth=True + has_resource_identifier=True → A01 선정."""
    fs = FeatureSet(requires_auth=True, has_resource_identifier=True, resource_context=True)
    out = planner.plan(fs)
    assert "A01" in out.owasp_candidates
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


def test_a01_need_more_context(planner):
    """requires_auth=True인데 조건 미충족 → need_more_context=True, A01 candidates 제외."""
    fs = FeatureSet(
        requires_auth=True,
        has_resource_identifier=False,
        auth_contexts=1,
        resource_context=False,
    )
    out = planner.plan(fs)
    assert out.need_more_context is True
    assert "A01" not in out.owasp_candidates


def test_a01_missing_list_content(planner):
    """need_more_context 시 missing에 auth_contexts, resource_context가 포함된다."""
    fs = FeatureSet(
        requires_auth=True,
        has_resource_identifier=False,
        auth_contexts=1,
        resource_context=False,
    )
    out = planner.plan(fs)
    assert "auth_contexts" in out.missing
    assert "resource_context" in out.missing


# ------------------------------------------------------------------
# A03 ~ A09
# ------------------------------------------------------------------

def test_a03_dependency_exposure(planner):
    """has_dependency_exposure=True → A03 선정."""
    fs = FeatureSet(has_dependency_exposure=True)
    out = planner.plan(fs)
    assert "A03" in out.owasp_candidates
    for tid in OWASP_TOOL_MAP["A03"]:
        assert tid in out.tool_ids


def test_a04_secret_handling(planner):
    """has_secret_handling=True → A04 선정."""
    fs = FeatureSet(has_secret_handling=True)
    out = planner.plan(fs)
    assert "A04" in out.owasp_candidates
    for tid in OWASP_TOOL_MAP["A04"]:
        assert tid in out.tool_ids


def test_a05_user_input_with_free_text(planner):
    """has_user_input + has_free_text_input → A05 선정."""
    fs = FeatureSet(has_user_input=True, has_free_text_input=True)
    out = planner.plan(fs)
    assert "A05" in out.owasp_candidates


def test_a05_user_input_with_file_surface(planner):
    """has_user_input + has_file_or_config_surface → A05 선정."""
    fs = FeatureSet(has_user_input=True, has_file_or_config_surface=True)
    out = planner.plan(fs)
    assert "A05" in out.owasp_candidates


def test_a05_not_selected_user_input_alone(planner):
    """has_user_input 단독으로는 A05 미선정 (과탐 방지)."""
    fs = FeatureSet(has_user_input=True)
    out = planner.plan(fs)
    assert "A05" not in out.owasp_candidates


def test_a06_state_changing(planner):
    """is_state_changing + has_state_field → A06 선정."""
    fs = FeatureSet(is_state_changing=True, has_state_field=True)
    out = planner.plan(fs)
    assert "A06" in out.owasp_candidates


def test_a06_not_selected_partial(planner):
    """is_state_changing만 있고 has_state_field=False → A06 미선정."""
    fs = FeatureSet(is_state_changing=True, has_state_field=False)
    out = planner.plan(fs)
    assert "A06" not in out.owasp_candidates


def test_a07_login_endpoint(planner):
    """is_login_endpoint=True → A07 선정."""
    fs = FeatureSet(is_login_endpoint=True)
    out = planner.plan(fs)
    assert "A07" in out.owasp_candidates
    for tid in OWASP_TOOL_MAP["A07"]:
        assert tid in out.tool_ids


def test_a07_credential_fields(planner):
    """has_credential_fields=True → A07 선정."""
    fs = FeatureSet(has_credential_fields=True)
    out = planner.plan(fs)
    assert "A07" in out.owasp_candidates


def test_a07_requires_auth(planner):
    """requires_auth=True만으로도 A07 선정 (자격 증명 검증 필요)."""
    fs = FeatureSet(requires_auth=True, has_resource_identifier=True, resource_context=True)
    out = planner.plan(fs)
    assert "A07" in out.owasp_candidates


def test_a08_file_surface(planner):
    """has_file_or_config_surface=True → A08 선정."""
    fs = FeatureSet(has_file_or_config_surface=True)
    out = planner.plan(fs)
    assert "A08" in out.owasp_candidates
    for tid in OWASP_TOOL_MAP["A08"]:
        assert tid in out.tool_ids


def test_a09_logging_feature(planner):
    """has_logging_feature=True → A09 선정."""
    fs = FeatureSet(has_logging_feature=True)
    out = planner.plan(fs)
    assert "A09" in out.owasp_candidates


# ------------------------------------------------------------------
# tool_ids
# ------------------------------------------------------------------

def test_tool_ids_deduplicated(planner):
    """A06과 A01이 공유하는 tool_id(http_method_tamper 등)가 중복 없이 한 번만 포함된다."""
    fs = FeatureSet(
        requires_auth=True,
        has_resource_identifier=True,
        resource_context=True,
        is_state_changing=True,
        has_state_field=True,
    )
    out = planner.plan(fs)
    assert len(out.tool_ids) == len(set(out.tool_ids))


def test_tool_ids_order_preserved(planner, empty_fs):
    """A02 baseline tool_ids가 A10보다 먼저 등장한다."""
    out = planner.plan(empty_fs)
    first_a02 = out.tool_ids.index(A02_BASELINE_TOOL_IDS[0])
    first_a10 = out.tool_ids.index(A10_BASELINE_TOOL_IDS[0])
    assert first_a02 < first_a10


# ------------------------------------------------------------------
# FeatureSet 타입
# ------------------------------------------------------------------

def test_feature_set_as_dataclass(planner):
    """dataclass 타입 FeatureSet을 정상적으로 읽는다."""
    fs = FeatureSet(has_logging_feature=True)
    out = planner.plan(fs)
    assert "A09" in out.owasp_candidates


def test_feature_set_as_dict(planner):
    """dict 타입 FeatureSet을 정상적으로 읽는다."""
    fs = {"has_logging_feature": True}
    out = planner.plan(fs)
    assert "A09" in out.owasp_candidates


# ------------------------------------------------------------------
# 복합
# ------------------------------------------------------------------

def test_full_featured_endpoint(planner):
    """모든 feature가 활성화된 엔드포인트에서 전체 OWASP 후보가 선정된다."""
    fs = FeatureSet(
        requires_auth=True,
        has_resource_identifier=True,
        auth_contexts=2,
        resource_context=True,
        has_dependency_exposure=True,
        has_secret_handling=True,
        has_user_input=True,
        has_free_text_input=True,
        has_file_or_config_surface=True,
        is_state_changing=True,
        has_state_field=True,
        is_login_endpoint=True,
        has_credential_fields=True,
        has_logging_feature=True,
    )
    out = planner.plan(fs)
    expected = {"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"}
    assert expected.issubset(set(out.owasp_candidates))
    assert out.need_more_context is False
    assert out.missing == []
