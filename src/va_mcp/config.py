from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parents[2]
APP_NAME = os.getenv("APP_NAME", "va-mcp")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
DUMP_ARTIFACTS = os.getenv("DUMP_ARTIFACTS", "false").lower() == "true"

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", BASE_DIR / "outputs"))
RAW_OUTPUT_DIR = OUTPUT_DIR / "raw"
FINDINGS_OUTPUT_DIR = OUTPUT_DIR / "findings"
REPORTS_OUTPUT_DIR = OUTPUT_DIR / "reports"
LOGS_OUTPUT_DIR = OUTPUT_DIR / "logs"
RUNS_OUTPUT_DIR = OUTPUT_DIR / "runs"

_LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_LOG_DATEFMT = "%Y-%m-%dT%H:%M:%S"
_LOGGING_INITIALIZED_FLAG = "_va_mcp_logging_initialized"


def ensure_output_dirs() -> None:
    """va-mcp가 사용하는 출력 디렉토리들을 생성한다."""
    for d in (
        RAW_OUTPUT_DIR,
        FINDINGS_OUTPUT_DIR,
        REPORTS_OUTPUT_DIR,
        LOGS_OUTPUT_DIR,
        RUNS_OUTPUT_DIR,
    ):
        d.mkdir(parents=True, exist_ok=True)


def init_logging() -> None:
    """va_mcp 로거에 stderr + rotating file 핸들러를 부착한다.

    MCP stdio 모드에서 stdout은 JSON-RPC 프로토콜 전용이므로 stderr와 파일에만 출력한다.
    중복 호출 시 핸들러를 다시 부착하지 않는다.
    """
    logger = logging.getLogger("va_mcp")
    if getattr(logger, _LOGGING_INITIALIZED_FLAG, False):
        return

    level = getattr(logging, LOG_LEVEL, logging.INFO)
    logger.setLevel(level)

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)

    LOGS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        LOGS_OUTPUT_DIR / "va-mcp.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    setattr(logger, _LOGGING_INITIALIZED_FLAG, True)
