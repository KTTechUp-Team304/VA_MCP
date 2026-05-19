from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from va_mcp.endpoint_profile.auth_config import AuthConfig


class SideEffect(str, Enum):
    """허용되는 side_effect 값."""

    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


@dataclass
class EndpointProfile:
    """
    정규화·검증 완료 후 하위 모듈(FeatureExtractor 등)에 전달되는 단일 엔드포인트 계약.
    """

    base_url: str
    method: str
    path: str
    headers: dict[str, Any] = field(default_factory=dict)
    query: dict[str, Any] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    body: dict[str, Any] | None = None
    auth_required: bool = False
    auth_contexts: list[Any] = field(default_factory=list)
    auth: AuthConfig | None = None
    required_roles: list[str] = field(default_factory=list)
    description: str = ""
    normal_request_example: dict[str, Any] | None = None
    normal_response_example: dict[str, Any] | None = None
    resource_context: dict[str, Any] | None = None
    side_effect: str = SideEffect.READ.value
    returns_sensitive_data: bool = False
    # 논리 키(username, password) → 실제 요청 body 필드명 (예: email, passwd)
    credential_fields: dict[str, str] = field(default_factory=dict)

    def to_serializable_dict(self) -> dict[str, Any]:
        """JSON 등 직렬화용 고정 shape (키 이름과 중첩 구조 고정)."""
        return asdict(self)
