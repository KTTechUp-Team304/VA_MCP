from __future__ import annotations

import logging
import sys

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """
    .env의 LOG_LEVEL을 반영해 로깅을 초기화한다.

    va_mcp.config를 import하면 load_dotenv()가 실행되어 LOG_LEVEL을 읽는다.
    테스트만 실행할 때도 endpoint_profile 등의 DEBUG 로그가 필터되지 않도록 한다.
    """
    from va_mcp import config as app_config

    level_name = str(app_config.LOG_LEVEL).upper()
    level = getattr(logging, level_name, logging.INFO)

    # pytest가 이미 핸들러를 둔 뒤일 수 있어 force로 레벨·핸들러를 맞춘다.
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
        force=True,
    )
    logging.getLogger("va_mcp").setLevel(level)
