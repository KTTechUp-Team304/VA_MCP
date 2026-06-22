# extra keys consumed: resource_context (dict) — runtime, dependencies
from __future__ import annotations

import logging

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from va_mcp.core.base import BaseTool
from va_mcp.core.constants import Confidence, ErrorCode, Severity, ToolStatus
from va_mcp.core.schemas import Evidence, ToolInput, ToolResult
from va_mcp.core.utils import build_tool_error, utc_now_iso

logger = logging.getLogger(__name__)

# runtime 키로 분리 — 동일 패키지명이 npm/PyPI 양쪽에 존재하는 경우 혼동 방지
# 새 생태계 추가 시 해당 runtime 키 아래 항목만 추가하면 로직 변경 불필요
KNOWN_VULNERABLE: dict[str, dict[str, list[tuple[str, str, str, str]]]] = {
    "node": {
        "lodash":       [("<4.17.21", "Prototype Pollution",  "HIGH",     "CVE-2019-10744")],
        "jsonwebtoken": [("<9.0.0",   "Algorithm Confusion",  "CRITICAL", "CVE-2022-23529")],
        "express":      [("<4.19.2",  "Open Redirect",        "MEDIUM",   "CVE-2024-29041")],
    },
    "python": {},  # 추후 항목만 추가하면 로직 변경 없이 탐지 가능
}

# Severity enum 선언 순서를 인덱스로 변환 — 복수 취약점 발견 시 최고 심각도 선택에 사용
_SEVERITY_RANK: dict[str, int] = {s.value: i for i, s in enumerate(Severity)}


class DependencyCheck(BaseTool):
    """
    의존성 라이브러리의 알려진 CVE 취약 버전을 탐지한다.
    resource_context.dependencies에 담긴 패키지 목록을 KNOWN_VULNERABLE과 대조하여
    취약한 버전이 사용되고 있는지 검사한다. 외부 네트워크 요청 없이 오프라인으로 동작한다.
    """

    tool_id = "dependency_check"
    tool_name = "Dependency Check"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()

        try:
            # ToolInput에 resource_context 직접 필드 없음 — options.extra를 통해 수신
            rc = tool_input.options.extra.get("resource_context", {})
            deps = rc.get("dependencies")

            # dependencies 키 자체가 없으면 검사 전제조건 미충족 → SKIPPED
            if deps is None:
                ended_at = utc_now_iso()
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="의존성 정보 없음",
                    description="resource_context에 dependencies 키가 없어 검사를 건너뜁니다.",
                    owasp=["A03 Software Supply Chain Failures"],
                    cwe=["CWE-1395"],
                    started_at=started_at,
                    ended_at=ended_at,
                )

            runtime = rc.get("runtime", "unknown").lower()
            # 알 수 없는 런타임은 빈 딕셔너리 — 추후 runtime 키 추가만으로 확장 가능
            vuln_db = KNOWN_VULNERABLE.get(runtime, {})

            findings: list[Evidence] = []
            top_severity = Severity.INFO

            for package, version_str in deps.items():
                pkg_lower = package.lower()
                if pkg_lower not in vuln_db:
                    continue
                # SpecifierSet.contains()는 일부 버전에서 잘못된 형식을 False로 무시함
                # Version()으로 먼저 명시적 검증 — InvalidVersion → outer except → ERROR 분기
                Version(version_str)
                for constraint, description, sev_str, cve_id in vuln_db[pkg_lower]:
                    if SpecifierSet(constraint).contains(version_str):
                        findings.append(
                            Evidence(
                                request={
                                    "package": package,
                                    "version": version_str,
                                    "constraint": constraint,
                                    "cve": cve_id,
                                },
                                response_status=0,  # HTTP 요청 없음
                                note=f"{package}@{version_str} — {description} ({cve_id})",
                            )
                        )
                        # 복수 취약점 발견 시 가장 높은 심각도를 결과 severity로 채택
                        candidate = Severity(sev_str.lower())
                        if _SEVERITY_RANK[candidate.value] > _SEVERITY_RANK[top_severity.value]:
                            top_severity = candidate

            ended_at = utc_now_iso()

            if findings:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_name=self.tool_name,
                    status=ToolStatus.VULNERABLE,
                    severity=top_severity,
                    confidence=Confidence.HIGH,
                    title=f"취약한 의존성 {len(findings)}건 발견",
                    description="알려진 CVE가 있는 취약한 버전의 패키지가 사용되고 있습니다.",
                    owasp=["A03 Software Supply Chain Failures"],
                    cwe=["CWE-1395"],
                    evidence=findings,
                    recommendation="취약한 패키지를 안전한 버전으로 업그레이드하세요.",
                    started_at=started_at,
                    ended_at=ended_at,
                )

            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.PASSED,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                title="알려진 취약 의존성 없음",
                description="검사한 패키지에서 알려진 CVE가 발견되지 않았습니다.",
                owasp=["A03 Software Supply Chain Failures"],
                cwe=["CWE-1395"],
                started_at=started_at,
                ended_at=ended_at,
            )

        except Exception as exc:
            ended_at = utc_now_iso()
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="의존성 검사 실행 오류",
                description="의존성 검사 중 예상치 못한 오류가 발생했습니다.",
                owasp=["A03 Software Supply Chain Failures"],
                cwe=["CWE-1395"],
                started_at=started_at,
                ended_at=ended_at,
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR, str(exc), retryable=False)],
            )
