from __future__ import annotations

import base64
import json
from typing import Any, Dict, List

from va_mcp.core import AuthContext
from va_mcp.core.base import BaseTool
from va_mcp.core.schemas import ToolInput, ToolResult, Evidence
from va_mcp.core.constants import ToolStatus, Severity, Confidence, ErrorCode
from va_mcp.core.utils import build_tool_error, utc_now_iso


class InsecureJwtTool(BaseTool):
    tool_id = "insecure_jwt"
    tool_name = "Insecure JWT Analyzer"
    tool_version = "0.1.0"

    def run(self, tool_input: ToolInput) -> ToolResult:
        start = utc_now_iso()

        auth: List[AuthContext] = tool_input.auth or []
        if not auth:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="No auth provided",
                description="auth가 존재하지 않습니다.",
                evidence=[],
                started_at=start,
                ended_at=start,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        token = auth[0].token if auth[0] else None
        if not token:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="Empty token",
                description="token이 비어 있습니다.",
                evidence=[],
                started_at=start,
                ended_at=start,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        parts = token.split(".")
        if len(parts) != 3:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="Invalid JWT format",
                description="JWT 형식 오류 (3-part 필요)",
                evidence=[],
                errors=[build_tool_error(ErrorCode.INVALID_INPUT.value, "invalid jwt", False)],
                started_at=start,
                ended_at=start,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        def decode(seg: str) -> Dict[str, Any]:
            padded = seg + "=" * (-len(seg) % 4)
            return json.loads(base64.urlsafe_b64decode(padded.encode()).decode())

        try:
            header = decode(parts[0])
            payload = decode(parts[1])
        except Exception as e:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                title="Decode failure",
                description=str(e),
                evidence=[],
                errors=[build_tool_error(ErrorCode.INVALID_INPUT.value, str(e), False)],
                started_at=start,
                ended_at=start,
                duration_ms=0,
                tool_version=self.tool_version,
            )

        alg = header.get("alg")
        issues: List[str] = []
        evidences: List[Evidence] = []

        status = ToolStatus.PASSED.value
        severity = Severity.INFO.value
        confidence = Confidence.HIGH.value

        # -------------------------
        # alg=none
        # -------------------------
        if not alg:
            status = ToolStatus.VULNERABLE.value
            severity = Severity.HIGH.value
            confidence = Confidence.HIGH.value
            issues.append("alg missing")

        elif str(alg).lower() == "none":
            status = ToolStatus.VULNERABLE.value
            severity = Severity.HIGH.value
            confidence = Confidence.HIGH.value
            issues.append("alg=none")

        elif alg == "HS256":
            if status != ToolStatus.VULNERABLE.value:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.MEDIUM.value
                confidence = Confidence.MEDIUM.value
            issues.append("HS256")

        # -------------------------
        # exp check
        # -------------------------
        if "exp" not in payload:
            if status != ToolStatus.VULNERABLE.value:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.MEDIUM.value
                confidence = Confidence.MEDIUM.value
            issues.append("exp missing")

        # -------------------------
        # sensitive payload
        # -------------------------
        if "password" in payload:
            status = ToolStatus.VULNERABLE.value
            severity = Severity.HIGH.value
            confidence = Confidence.HIGH.value
            issues.append("password")

        # evidence 반드시 포함
        if issues:
            evidences.append(
                Evidence(
                    request={"token": token},
                    response_status=200,
                    response_headers={},
                    response_body_sample=str(payload),
                    note="JWT issue detected: " + ", ".join(issues),
                )
            )

        description = f"JWT 분석 결과: {', '.join(issues) if issues else 'no issues'}"

        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=status,
            severity=severity,
            confidence=confidence,
            title="JWT analysis result",
            description=description,
            cwe=["CWE-347", "CWE-327"],
            evidence=evidences,
            started_at=start,
            ended_at=start,
            duration_ms=0,
            tool_version=self.tool_version,
        )