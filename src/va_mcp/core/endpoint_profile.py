from __future__ import annotations

# NOTE: 이 파일은 feature_extractor 팀이 V3.1 §2 스펙을 기반으로 작성한 stub입니다.
#       endpoint_profile 팀과 협의 후 최종 확정합니다.

from dataclasses import dataclass


@dataclass
class EndpointProfile:
    """
    분석 대상 API 엔드포인트의 행위/권한/데이터 흐름을 표현한 입력 구조체.
    FeatureExtractor의 입력이자 전체 파이프라인의 시작점이다.
    V3.1 §2 스펙 기준으로 정의되며, endpoint_profile 팀과 협의하여 확정한다.
    """

    # ===== 필수 필드 =====
    base_url: str       # 대상 서버 주소 (예: "https://api.example.com")
    method: str         # HTTP method (예: "GET", "POST")
    path: str           # API 경로 (예: "/api/users/{userId}")

    # ===== 요청 파라미터 =====
    headers: dict | None = None     # 요청 헤더
    query: dict | None = None       # query params (?key=value)
    params: dict | None = None      # path params ({userId} 등)
    body: dict | None = None        # request body

    # ===== 인증 =====
    auth_required: bool = False     # 인증 필요 여부
    # mutable default 금지 → None 기본값, 사용 시 `profile.auth_contexts or []` 패턴 사용
    auth_contexts: list | None = None

    # ===== 행위 설명 =====
    description: str = ""           # 행위 + 주체 + 대상 포함 설명

    # ===== 예시 (선택) =====
    normal_request_example: dict | None = None
    normal_response_example: dict | None = None

    # ===== 리소스/상태 =====
    resource_context: dict | None = None    # ownership 구조 포함
    side_effect: str = "read"               # read / create / update / delete
    returns_sensitive_data: bool = False    # 민감 데이터 반환 여부
