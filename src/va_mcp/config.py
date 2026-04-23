from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()

BASE_DIR = Path(__file__).resolve().parents[2]
APP_NAME = os.getenv("APP_NAME", "va-mcp")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", BASE_DIR / "outputs"))
RAW_OUTPUT_DIR = OUTPUT_DIR / "raw"
FINDINGS_OUTPUT_DIR = OUTPUT_DIR / "findings"
REPORTS_OUTPUT_DIR = OUTPUT_DIR / "reports"


def ensure_output_dirs() -> None:
    RAW_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)