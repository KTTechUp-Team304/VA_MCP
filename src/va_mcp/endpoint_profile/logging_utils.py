from __future__ import annotations

import json
import logging
from typing import Any

_DEFAULT_MAX_CHARS = 12_000


def format_structure_for_log(obj: Any, *, max_chars: int = _DEFAULT_MAX_CHARS) -> str:
    """디버그 로그용으로 객체를 JSON 문자열로 바꾼다 (순환·비직렬화 값은 default=str)."""
    if obj is None:
        return "null"
    try:
        s = json.dumps(obj, default=str, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        s = repr(obj)
    if len(s) > max_chars:
        return f"{s[:max_chars]}... <truncated total_chars={len(s)}>"
    return s


def log_stage_io(
    logger: logging.Logger,
    stage: str,
    *,
    input_data: Any = None,
    output_data: Any = None,
) -> None:
    """
    파이프라인 한 단계의 입력/출력을 DEBUG로 남긴다.

    운영 환경에서 DEBUG를 켜면 headers/body 등에 민감값이 포함될 수 있다.
    """
    prefix = f"[endpoint_profile:{stage}]"
    if input_data is not None:
        logger.debug("%s input:\n%s", prefix, format_structure_for_log(input_data))
    if output_data is not None:
        logger.debug("%s output:\n%s", prefix, format_structure_for_log(output_data))
