from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from dotenv import load_dotenv

# 설치 경로와 무관하게 pyproject.toml이 있는 디렉토리를 프로젝트 루트로 찾는다.
# (개발 시: src/va_mcp/ 위 2단계 / uv tool install 시: 설치 경로와 다를 수 있음)
load_dotenv()

BASE_DIR = Path(__file__).resolve().parents[2]
APP_NAME = os.getenv("APP_NAME", "va-mcp")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
DUMP_ARTIFACTS = os.getenv("DUMP_ARTIFACTS", "false").lower() == "true"


def _find_repo_root(start: Path | None = None) -> Path | None:
    """실행 cwd 기준으로 VA-MCP 저장소 루트(src/va_mcp)를 찾는다."""
    for base in [start or Path.cwd(), *list((start or Path.cwd()).parents)]:
        if (base / "src" / "va_mcp").is_dir() and (base / "pyproject.toml").is_file():
            return base
    return None


def resolve_output_dir() -> Path:
    """산출물 루트 경로. OUTPUT_DIR은 상대 경로면 cwd 기준으로 해석한다."""
    raw = os.getenv("OUTPUT_DIR")
    if raw:
        path = Path(raw)
        if path.is_absolute():
            return path.resolve()
        return (Path.cwd() / path).resolve()

    repo = _find_repo_root()
    if repo is not None:
        return (repo / "outputs").resolve()
    return (BASE_DIR / "outputs").resolve()


def resolve_reports_dir() -> Path:
    """
    사람용 취약점 분석 리포트 저장 경로 (저장소 루트 /reports).

    OUTPUT_DIR(outputs/)와 분리 — outputs는 개발·디버깅 산출물용.
    """
    raw = os.getenv("REPORTS_DIR")
    if raw:
        path = Path(raw)
        if path.is_absolute():
            return path.resolve()
        return (Path.cwd() / path).resolve()

    repo = _find_repo_root()
    if repo is not None:
        return (repo / "reports").resolve()
    return (BASE_DIR / "reports").resolve()


OUTPUT_DIR = resolve_output_dir()
REPORTS_OUTPUT_DIR = resolve_reports_dir()
RAW_OUTPUT_DIR = OUTPUT_DIR / "raw"
FINDINGS_OUTPUT_DIR = OUTPUT_DIR / "findings"
LOGS_OUTPUT_DIR = OUTPUT_DIR / "logs"
RUNS_OUTPUT_DIR = OUTPUT_DIR / "runs"

_LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_LOG_DATEFMT = "%Y-%m-%dT%H:%M:%S"
_LOGGING_INITIALIZED_FLAG = "_va_mcp_logging_initialized"


def ensure_output_dirs() -> None:
    """va-mcp가 사용하는 출력 디렉토리들을 생성한다."""
    for d in (
        OUTPUT_DIR,
        REPORTS_OUTPUT_DIR,
        RAW_OUTPUT_DIR,
        FINDINGS_OUTPUT_DIR,
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
