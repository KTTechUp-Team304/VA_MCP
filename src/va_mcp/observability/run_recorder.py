from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from va_mcp.config import DUMP_ARTIFACTS, RUNS_OUTPUT_DIR

logger = logging.getLogger(__name__)

_LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_LOG_DATEFMT = "%Y-%m-%dT%H:%M:%S"


def _to_serializable(obj: Any) -> Any:
    """JSON 직렬화 가능한 형태로 안전하게 변환한다."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if hasattr(obj, "to_serializable_dict"):
        return obj.to_serializable_dict()
    if isinstance(obj, dict):
        return {str(k): _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_serializable(v) for v in obj]
    return str(obj)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_to_serializable(data), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


class RunRecorder:
    """`analyze_endpoint` 1회 호출 단위로 산출물을 폴더에 떨군다.

    `DUMP_ARTIFACTS=false`이면 메서드들이 no-op로 동작한다 (run_id는 항상 생성).

    사용 흐름:
        recorder = RunRecorder()
        recorder.dump("00_input.json", raw_input)
        ...
        recorder.finalize(status="analyzed", summary_extra={...})
    """

    def __init__(self, *, enabled: bool | None = None) -> None:
        self.enabled = DUMP_ARTIFACTS if enabled is None else enabled
        self.started_at = datetime.now(timezone.utc)
        ts = self.started_at.strftime("%Y-%m-%dT%H-%M-%S")
        self.run_id = f"{ts}_{uuid.uuid4().hex[:6]}"
        self.run_dir: Path | None = None
        self._log_handler: logging.Handler | None = None
        self._meta: dict[str, Any] = {
            "run_id": self.run_id,
            "started_at": self._iso(self.started_at),
        }

        if self.enabled:
            self.run_dir = RUNS_OUTPUT_DIR / self.run_id
            self.run_dir.mkdir(parents=True, exist_ok=True)
            self._attach_run_log_handler()
            logger.debug("RunRecorder enabled run_id=%s dir=%s", self.run_id, self.run_dir)

    @staticmethod
    def _iso(dt: datetime) -> str:
        return dt.isoformat().replace("+00:00", "Z")

    def _attach_run_log_handler(self) -> None:
        """va_mcp 루트 로거에 이 run 전용 파일 핸들러를 부착한다."""
        if self.run_dir is None:
            return
        handler = logging.FileHandler(self.run_dir / "run.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
        handler.setLevel(logging.DEBUG)
        logging.getLogger("va_mcp").addHandler(handler)
        self._log_handler = handler

    def _detach_run_log_handler(self) -> None:
        if self._log_handler is None:
            return
        logging.getLogger("va_mcp").removeHandler(self._log_handler)
        self._log_handler.close()
        self._log_handler = None

    def dump(self, filename: str, data: Any) -> None:
        """run_dir 바로 아래에 JSON 파일을 떨군다."""
        if not self.enabled or self.run_dir is None:
            return
        _write_json(self.run_dir / filename, data)

    def dump_tool_result(self, tool_id: str, data: Any) -> None:
        """`04_tool_results/<tool_id>.json` 으로 떨군다."""
        if not self.enabled or self.run_dir is None:
            return
        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in tool_id)
        _write_json(self.run_dir / "04_tool_results" / f"{safe_id}.json", data)

    def finalize(
        self,
        *,
        status: str,
        summary_extra: dict[str, Any] | None = None,
    ) -> None:
        """meta.json과 summary.md를 작성하고 핸들러를 분리한다."""
        try:
            if not self.enabled or self.run_dir is None:
                return
            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - self.started_at).total_seconds() * 1000)
            self._meta.update(
                {
                    "ended_at": self._iso(ended_at),
                    "duration_ms": duration_ms,
                    "status": status,
                }
            )
            extra = summary_extra or {}
            self._meta.update(extra)

            _write_json(self.run_dir / "meta.json", self._meta)
            self._write_summary_md(extra)
        finally:
            self._detach_run_log_handler()

    def _write_summary_md(self, extra: dict[str, Any]) -> None:
        if self.run_dir is None:
            return
        lines: list[str] = [
            f"# Run {self.run_id}",
            "",
            f"- Started:  {self._meta.get('started_at')}",
            f"- Ended:    {self._meta.get('ended_at')}",
            f"- Duration: {self._meta.get('duration_ms')} ms",
            f"- Status:   `{self._meta.get('status')}`",
            "",
            "## 핵심 결과",
        ]

        method = extra.get("method")
        path = extra.get("path")
        if method and path:
            lines.append(f"- Endpoint: `{method} {path}`")

        owasp = extra.get("owasp_candidates")
        if owasp:
            lines.append(f"- OWASP candidates: {', '.join(owasp)}")

        tool_ids = extra.get("tool_ids")
        if tool_ids is not None:
            lines.append(f"- Tools selected: {len(tool_ids)}")

        counts = extra.get("status_counts")
        if counts:
            parts = ", ".join(f"{k}={v}" for k, v in counts.items())
            lines.append(f"- Tool status: {parts}")

        missing = extra.get("missing")
        if missing:
            lines.append(f"- Missing context: {', '.join(missing)}")

        errors = extra.get("errors")
        if errors:
            lines.append("")
            lines.append("## Validation errors")
            for err in errors:
                lines.append(
                    f"- `{err.get('field')}` — {err.get('code')}: {err.get('message')}"
                )

        vulnerable = extra.get("vulnerable_findings")
        if vulnerable:
            lines.append("")
            lines.append("## 🔴 취약점 발견")
            for v in vulnerable:
                lines.append(
                    f"- **{v.get('tool_id')}** ({v.get('severity')}): {v.get('title')}"
                )

        report_paths = extra.get("report_paths")
        if report_paths:
            lines.append("")
            lines.append("## 취약점 분석 리포트")
            md = report_paths.get("report_md")
            js = report_paths.get("report_json")
            if md:
                lines.append(f"- Markdown: `{md}`")
            if js:
                lines.append(f"- JSON: `{js}`")
            run_md = report_paths.get("run_report_md")
            if run_md:
                lines.append(f"- Run copy: [05_vulnerability_report.md](./05_vulnerability_report.md)")

        lines.extend(
            [
                "",
                "## 단계별 산출물",
                "- [00_input.json](./00_input.json)",
                "- [01_endpoint_profile.json](./01_endpoint_profile.json)",
                "- [02_feature_set.json](./02_feature_set.json)",
                "- [03_planner_output.json](./03_planner_output.json)",
                "- [04_tool_results/](./04_tool_results/)",
                "- [05_endpoint_report.json](./05_endpoint_report.json)",
                "- [05_vulnerability_report.md](./05_vulnerability_report.md)",
                "- [run.log](./run.log)",
                "",
            ]
        )

        (self.run_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")
