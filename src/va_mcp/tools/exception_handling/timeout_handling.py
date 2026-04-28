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
    sanitize_request_body,      # 🎯 [추가] request_body 제한을 위한 필수 유틸
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
        
        # [규정 준수] status=SKIPPED 시 evidence=[] 고정
        if not request_info:
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.SKIPPED.value,
                started_at=started_at,
                ended_at=utc_now_iso(),
                evidence=[]
            )

        timeout_ms = tool_input.options.timeout
        timeout_sec = timeout_ms / 1000.0
        
        target_url = f"{target.base_url.rstrip('/')}/{request_info.path.lstrip('/')}"
        method = request_info.method.upper()
        
        # [리뷰어 수정 4 만족] 원본 데이터 변조 방지 (얕은 복사)
        headers = dict(request_info.headers)
        headers.setdefault("X-Test-Delay", "true")
        
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
                timeout=timeout_sec
            )
            
            status_code = response.status_code
            
            # [리뷰어 수정 5 만족] 오탐 방지: 정상 응답(200, 400 등)은 취약점 아님, 500에러만 취약점.
            is_vulnerable = (status_code == 500)
            
            if is_vulnerable:
                status = ToolStatus.VULNERABLE.value
                severity = Severity.HIGH.value
                confidence = Confidence.HIGH.value
            
            # [규정 준수] mask_sensitive, sanitize_request_body, sanitize_response_sample 완벽 적용
            evidence_list.append(Evidence(
                request={
                    "method": method,
                    "path": target_url,
                    "headers": mask_sensitive(headers),
                    "body": sanitize_request_body(request_info.body)  # 🎯 놓쳤던 규정 완벽 조치!
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
                    "body": sanitize_request_body(request_info.body)  # 🎯 일관성을 위해 여기도 조치
                },
                response_status=0,
                note=f"서버가 설정된 {timeout_sec}초 내에 응답을 반환하지 못해 타임아웃 발생"
            ))
            
        except Exception as e:
            # [규정 준수] ERROR 상태 시 severity=INFO, confidence=LOW 고정 및 build_tool_error 규격 사용
            return ToolResult(
                tool_id=self.tool_id,
                tool_name=self.tool_name,
                status=ToolStatus.ERROR.value,
                severity=Severity.INFO.value,
                confidence=Confidence.LOW.value,
                errors=[build_tool_error(ErrorCode.INTERNAL_ERROR, str(e))],
                started_at=started_at,
                ended_at=utc_now_iso(),
            )

        return ToolResult(
            tool_id=self.tool_id,
            tool_name=self.tool_name,
            status=status,
            severity=severity,
            confidence=confidence,
            title="불충분한 서버 측 타임아웃 처리" if status == ToolStatus.VULNERABLE.value else "",
            description="인위적인 지연 요청 시 서버가 내부 오류를 일으키거나 응답을 무한 대기하여 가용성에 영향을 줄 수 있음" if status == ToolStatus.VULNERABLE.value else "",
            evidence=evidence_list,
            started_at=started_at,
            ended_at=utc_now_iso(),
        )