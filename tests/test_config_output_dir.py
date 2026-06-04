"""OUTPUT_DIR 해석 테스트."""

from pathlib import Path

import pytest

from va_mcp import config


def test_resolve_reports_dir_finds_repo_reports(monkeypatch, tmp_path):
    repo = tmp_path / "VA-MCP"
    (repo / "src" / "va_mcp").mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\nname = 'va-mcp'\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    monkeypatch.delenv("REPORTS_DIR", raising=False)
    assert config.resolve_reports_dir() == (repo / "reports").resolve()


def test_resolve_output_dir_finds_repo_from_cwd(monkeypatch, tmp_path):
    repo = tmp_path / "VA-MCP"
    (repo / "src" / "va_mcp").mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\nname = 'va-mcp'\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    assert config.resolve_output_dir() == (repo / "outputs").resolve()


def test_resolve_output_dir_relative_env(monkeypatch, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setenv("OUTPUT_DIR", "artifacts/out")
    assert config.resolve_output_dir() == (work / "artifacts" / "out").resolve()
