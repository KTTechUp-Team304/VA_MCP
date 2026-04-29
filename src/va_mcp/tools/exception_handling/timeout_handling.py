from __future__ import annotations

import requests
from va_mcp.core import (
    BaseTool,
    Confidence,
    ErrorCode,
    Evidence,
    Severity,
    ToolInput,
    ToolResult,
    ToolStatus,
)
from va_mcp.core.utils import (
    build_tool_error,
    mask_sensitive,
    sanitize_request_body,
    sanitize_response_sample,
    utc_now_iso,
)

class TimeoutHandlingTool(BaseTool):
    """
    서버의 타임아웃 처리 및 가용성(Availability)을 점검하는 도구입니다.
    인위적인 지연을 유발하는 요청에 대해 서버가 적절한 에러(504 등)로 대응하는지,
    혹은 내부 오류(500)가 발생하거나 응답을 무한 대기하여 자원을 고갈시키는지 확인합니다.
    """

    tool_id = "timeout_handling"
    tool_name = "Timeout Handling Check"

    def run(self, tool_input: ToolInput) -> ToolResult:
        started_at = utc_now_iso()
        
        target = tool_input.target
        request_info = tool_input.request
        
        if tool_input.request is None:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                evidence=[],  # SKIPPED 규정 준수
                started_at=started_at,
                ended_at=utc_now_iso()
            )

        # 🎯 불법 파라미터(delay_seconds) 삭제 및 표준 timeout 옵션 사용
        timeout_sec = tool_input.options.timeout / 1000.0
        
        target_url = f"{target.base_url.rstrip('/')}/{request_info.path.lstrip('/')}"
        method = request_info.method.upper()
        
        # 🎯 원본 데이터 변조 방지 (얕은 복사)
        headers = dict(request_info.headers)
        headers.setdefault("X-Test-Delay", "true")  # 기존 서버 페이로드 유지
        
        evidence_list = []
        status = ToolStatus.PASSED.value
        severity = Severity.INFO.value
        confidence = Confidence.LOW.value
        
        try:
            response = requests.request(
                method=method,
                url=target_url,
                headers=headers,
                params=request_info.query,
                json=request_info.body,
                timeout=timeout_sec  # 🎯 표준 timeout 적용
            )
            
            status_code = response.status_code
            
            # 오탐 방지: 정상 응답은 안전, 500 에러만 취약점
            is_vulnerable = (status_code == 500)
            
            if is_vulnerable:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.HIGH.value
                confidence = Confidence.HIGH.value
            
            # 유틸리티 강제 통과 (마스킹, 바디 2000자 제한)
            evidence_list.append(Evidence(
                request={
                    "method": method,
                    "path": target_url,
                    "headers": mask_sensitive(headers),
                    "body": sanitize_request_body(request_info.body)
                },
                response_status=status_code,
                response_headers=dict(response.headers),
                response_body_sample=sanitize_response_sample(response.text),
                note="서버 내부 오류(500) 발생으로 인한 가용성 저하 확인" if is_vulnerable else "정상 응답 혹은 적절한 에러 처리로 방어됨"
            ))

        except requests.exceptions.Timeout:
            status = ToolStatus.VULNERABLE.value
            severity = Severity.HIGH.value
            confidence = Confidence.HIGH.value
            
            evidence_list.append(Evidence(
                request={
                    "method": method,
                    "path": target_url,
                    "headers": mask_sensitive(headers),
                    "body": sanitize_request_body(request_info.body)
                },
                response_status=0,
                note=f"서버가 설정된 {timeout_sec}초 내에 응답을 반환하지 못해 타임아웃 발생"
            ))
            
        except Exception as e:
            # [규정 준수] ERROR 상태 시 고정값 세팅 및 build_tool_error 규격(Enum.value) 사용
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR.value, str(e))],
                started_at=started_at,
                ended_at=utc_now_iso(),
            )

        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=status,
            severity=severity,
            confidence=confidence,
            title="불충분한 서버 측 타임아웃 처리" if status == ToolStatus.VULNERABLE.value else "안전한 타임아웃 처리",
            description="인위적인 지연 요청 시 서버가 내부 오류를 일으키거나 응답을 무한 대기하여 가용성에 영향을 줄 수 있음" if status == ToolStatus.VULNERABLE.value else "지연 요청 시에도 서버에 영향이 가지 않음을 확인하였음(정상)",
            owasp=["A10:2025 Mishandling of Exceptional Conditions"],
            cwe=["CWE-770"],
            recommendation="글로벌 타임아웃 적용 및 자원 점유 방지 조치가 필요합니다." if status == ToolStatus.VULNERABLE.value else "조치가 필요하지 않습니다.",
            evidence=evidence_list,
            started_at=started_at,
            ended_at=utc_now_iso(),
        )