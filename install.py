#!/usr/bin/env python3
"""
VA-MCP Claude Desktop 자동 설치 스크립트

사용법:
    python install.py              # 설치
    python install.py --uninstall  # 제거
    python install.py --dry-run    # 미리보기 (파일 변경 없음)
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

MCP_SERVER_NAME = "va-mcp"


# ── 출력 헬퍼 ─────────────────────────────────────────────────────────────────

def ok(msg: str) -> None:
    print(f"  ✓ {msg}")

def warn(msg: str) -> None:
    print(f"  ⚠ {msg}")

def err(msg: str) -> None:
    print(f"  ✗ {msg}", file=sys.stderr)

def info(msg: str) -> None:
    print(f"  → {msg}")


# ── va-mcp 실행 파일 탐지 ──────────────────────────────────────────────────────

def find_va_mcp_exe() -> Path | None:
    """va-mcp 실행 파일의 절대 경로를 반환한다."""
    cmd = "where" if platform.system() == "Windows" else "which"
    try:
        result = subprocess.run(
            [cmd, MCP_SERVER_NAME],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            first_line = result.stdout.strip().splitlines()[0].strip()
            return Path(first_line)
    except FileNotFoundError:
        pass
    return None


def ensure_va_mcp(dry_run: bool) -> Path | None:
    """va-mcp가 없으면 uv tool install . 로 설치한다."""
    exe = find_va_mcp_exe()
    if exe:
        ok(f"va-mcp 확인: {exe}")
        return exe

    warn("va-mcp를 찾을 수 없습니다. 설치를 시도합니다...")
    if dry_run:
        info("[dry-run] uv tool install . 건너뜀")
        return None

    try:
        subprocess.run(["uv", "tool", "install", "."], check=True)
    except FileNotFoundError:
        err("uv를 찾을 수 없습니다. https://docs.astral.sh/uv/ 에서 설치하세요.")
        return None
    except subprocess.CalledProcessError as e:
        err(f"uv tool install 실패: {e}")
        return None

    exe = find_va_mcp_exe()
    if exe:
        ok(f"va-mcp 설치 완료: {exe}")
    else:
        warn("설치 후에도 va-mcp를 찾지 못했습니다. PATH를 확인하세요.")
    return exe


# ── Claude Desktop 설정 파일 탐지 ─────────────────────────────────────────────

def find_claude_config() -> Path | None:
    """OS 및 설치 방식에 따라 claude_desktop_config.json 경로를 반환한다."""
    system = platform.system()

    if system == "Windows":
        # 1) 직접 설치
        appdata = os.environ.get("APPDATA", "")
        candidate = Path(appdata) / "Claude" / "claude_desktop_config.json"
        if candidate.parent.exists():
            return candidate

        # 2) Microsoft Store 설치 (파일이 이미 있는 경우)
        localappdata = os.environ.get("LOCALAPPDATA", "")
        store_files = glob.glob(str(
            Path(localappdata)
            / "Packages" / "Claude_*"
            / "LocalCache" / "Roaming" / "Claude"
            / "claude_desktop_config.json"
        ))
        if store_files:
            return Path(store_files[0])

        # 3) Microsoft Store 설치 (폴더는 있지만 파일이 없는 경우)
        store_dirs = glob.glob(str(
            Path(localappdata)
            / "Packages" / "Claude_*"
            / "LocalCache" / "Roaming" / "Claude"
        ))
        if store_dirs:
            return Path(store_dirs[0]) / "claude_desktop_config.json"

    elif system == "Darwin":  # macOS
        candidate = (
            Path.home()
            / "Library" / "Application Support" / "Claude"
            / "claude_desktop_config.json"
        )
        if candidate.parent.exists():
            return candidate

    return None


def prompt_config_path() -> Path | None:
    """자동 탐지 실패 시 사용자에게 경로를 직접 입력받는다."""
    print()
    warn("Claude Desktop 설정 파일 경로를 자동으로 찾지 못했습니다.")
    print("  직접 입력해주세요 (Enter 입력 시 중단):")
    if platform.system() == "Windows":
        print(r"  예) C:\Users\user\AppData\Roaming\Claude\claude_desktop_config.json")
    else:
        print("  예) /Users/user/Library/Application Support/Claude/claude_desktop_config.json")
    path_str = input("  경로: ").strip()
    return Path(path_str) if path_str else None


# ── Claude Desktop 실행 감지 ──────────────────────────────────────────────────

def is_claude_running() -> bool:
    """Claude Desktop 프로세스가 실행 중인지 확인한다."""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq Claude.exe"],
                capture_output=True, text=True,
            )
            return "Claude.exe" in result.stdout
        else:
            result = subprocess.run(
                ["pgrep", "-x", "Claude"],
                capture_output=True, text=True,
            )
            return result.returncode == 0
    except Exception:
        return False


# ── 설정 파일 읽기/쓰기 ───────────────────────────────────────────────────────

def read_config(config_path: Path) -> dict:
    """설정 파일을 읽어 dict로 반환한다. 없으면 빈 dict, 손상 시 사용자에게 묻는다."""
    if not config_path.exists():
        return {}
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        warn(f"설정 파일 JSON 파싱 실패: {e}")
        answer = input("  손상된 파일을 새로 만들까요? 기존 내용이 삭제됩니다. [y/N]: ").strip().lower()
        if answer == "y":
            return {}
        raise SystemExit("설치를 중단합니다.")


def backup_config(config_path: Path) -> None:
    """기존 설정 파일을 .bak으로 백업한다."""
    if config_path.exists():
        bak = config_path.with_name(config_path.name + ".bak")
        shutil.copy2(config_path, bak)
        ok(f"백업: {bak}")


def write_config(config_path: Path, config: dict, dry_run: bool) -> None:
    """설정 파일을 저장한다."""
    content = json.dumps(config, indent=2, ensure_ascii=False)
    if dry_run:
        print()
        info(f"[dry-run] 저장 예정 파일: {config_path}")
        print()
        for line in content.splitlines():
            print(f"    {line}")
        return
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(content, encoding="utf-8")
    ok(f"설정 저장: {config_path}")


# ── 설치 ──────────────────────────────────────────────────────────────────────

def install(dry_run: bool) -> None:
    print("\n[ VA-MCP  →  Claude Desktop 설치 ]\n")

    # 1. va-mcp 실행 파일 확인 / 설치
    exe = ensure_va_mcp(dry_run)
    command = str(exe) if exe else MCP_SERVER_NAME

    # 2. Claude Desktop 실행 중 확인
    if is_claude_running():
        warn("Claude Desktop이 실행 중입니다. 설치 후 반드시 재시작하세요.")

    # 3. 설정 파일 경로 탐지
    config_path = find_claude_config() or prompt_config_path()
    if not config_path:
        err("설정 파일 경로를 확인할 수 없어 설치를 중단합니다.")
        sys.exit(1)
    info(f"설정 파일: {config_path}")

    # 4. 기존 설정 읽기
    config = read_config(config_path)
    config.setdefault("mcpServers", {})

    # 5. 중복 확인
    if MCP_SERVER_NAME in config["mcpServers"]:
        existing = config["mcpServers"][MCP_SERVER_NAME]
        warn(f"이미 등록되어 있습니다: {existing}")
        answer = input("  덮어쓸까요? [y/N]: ").strip().lower()
        if answer != "y":
            print("  설치를 건너뜁니다.")
            return

    # 6. 백업
    if not dry_run:
        backup_config(config_path)

    # 7. mcpServers에 추가
    config["mcpServers"][MCP_SERVER_NAME] = {"command": command}
    info(f"등록: {MCP_SERVER_NAME} → {command}")

    # 8. 저장
    write_config(config_path, config, dry_run)

    if not dry_run:
        print()
        print("  ✓ 설치 완료!")
        print("  Claude Desktop을 완전히 종료 후 재실행하세요.")


# ── 제거 ──────────────────────────────────────────────────────────────────────

def uninstall(dry_run: bool) -> None:
    print("\n[ VA-MCP  →  Claude Desktop 제거 ]\n")

    config_path = find_claude_config() or prompt_config_path()
    if not config_path or not config_path.exists():
        err("설정 파일을 찾을 수 없습니다.")
        sys.exit(1)
    info(f"설정 파일: {config_path}")

    config = read_config(config_path)
    if MCP_SERVER_NAME not in config.get("mcpServers", {}):
        warn(f"{MCP_SERVER_NAME}이 등록되어 있지 않습니다.")
        return

    if not dry_run:
        backup_config(config_path)

    del config["mcpServers"][MCP_SERVER_NAME]
    write_config(config_path, config, dry_run)

    if not dry_run:
        print()
        print("  ✓ 제거 완료!")
        print("  Claude Desktop을 완전히 종료 후 재실행하세요.")


# ── 진입점 ────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="VA-MCP를 Claude Desktop에 자동으로 등록/해제합니다."
    )
    parser.add_argument(
        "--uninstall", action="store_true",
        help="Claude Desktop에서 va-mcp를 제거합니다.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="실제 변경 없이 결과를 미리 확인합니다.",
    )
    args = parser.parse_args()

    if args.dry_run:
        print("\n  [dry-run 모드] 실제 파일은 변경되지 않습니다.")

    try:
        if args.uninstall:
            uninstall(dry_run=args.dry_run)
        else:
            install(dry_run=args.dry_run)
    except KeyboardInterrupt:
        print("\n  중단되었습니다.")
        sys.exit(0)


if __name__ == "__main__":
    main()
