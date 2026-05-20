# [KT Tech up] 사이버 보안 2기 TEAM 304

### 팀장: 이윤재 / 팀원: 김태우, 윤지훈, 최민준

**Vulnerability Analyzer MCP** — API 엔드포인트 정보를 받아 OWASP Top 10 관점의 취약점 점검을 수행하고, 결과 리포트를 반환하는 [Model Context Protocol](https://modelcontextprotocol.io/) 서버입니다.

저장소: [github.com/KTTechUp-Team304/VA_MCP](https://github.com/KTTechUp-Team304/VA_MCP)

Cursor·Claude Desktop 등 MCP를 지원하는 에이전트에 연결해 사용합니다.

## 제공 기능

| MCP Tool                | 설명                                                                                    |
| ----------------------- | --------------------------------------------------------------------------------------- |
| `analyze_endpoint`      | 엔드포인트 프로필 분석 → 시나리오 계획 → OWASP 점검 도구 자동 실행 → 결과 요약          |
| `list_supported_checks` | 지원 점검 목록 조회                                                                     |
| `ping`                  | 서버 연결 확인                                                                          |
| _(개별 점검 도구)_      | `sql_injection`, `idor_bola`, `jwt_validation` 등 — Planner가 선택하거나 직접 호출 가능 |

- **사람용 분석 보고서**: `reports/{METHOD}_{path}_{시각}.md` (저장소 루트)
- **개발·디버깅 산출물**: `outputs/runs/<run_id>/`, `outputs/logs/` (`DUMP_ARTIFACTS=true` 시)

## 요구 사항

- **Git**
- **[uv](https://docs.astral.sh/uv/)** (Python 패키지·실행 관리)
- **Python 3.11+**
- MCP 클라이언트: [Cursor](https://cursor.com/) 또는 [Claude Desktop](https://claude.ai/download)

```bash
git --version
uv --version
python3 --version
```

## 설치

```bash
git clone https://github.com/KTTechUp-Team304/VA_MCP.git
cd VA_MCP
uv sync
uv tool install .
```

- `uv tool install .` → `~/.local/bin/va-mcp` CLI 등록 (`which va-mcp`로 확인)
- `~/.local/bin`이 PATH에 없으면 셸 설정에 추가한 뒤 **MCP 클라이언트를 재시작**하세요.

## MCP 클라이언트 연동

### Cursor

이 저장소에 `.cursor/mcp.json`이 포함되어 있습니다.

1. Cursor에서 **VA-MCP 폴더**를 엽니다.
2. **Settings → MCP**에서 `va-mcp` 서버가 활성화되어 있는지 확인합니다.

다른 프로젝트(예: `broken_regist_frontend`)만 연 상태에서 쓰려면, 위 설치 후 **전역** `~/.cursor/mcp.json`에 동일 설정을 넣거나, 워크스페이스에 `VA-MCP` 폴더를 추가합니다.

```json
{
  "mcpServers": {
    "va-mcp": {
      "command": "va-mcp"
    }
  }
}
```

### Claude Desktop

macOS 기준 설정 파일: `~/Library/Application Support/Claude/claude_desktop_config.json`

`mcpServers` 블록에 위와 동일하게 추가한 뒤 Claude Desktop을 **완전히 종료 후 재실행**합니다.

## 사용 방법

### 1) 연결 확인

에이전트 채팅에서 MCP 도구 `ping`을 호출해 응답이 오는지 확인합니다.

### 2) 엔드포인트 점검 (`analyze_endpoint`)

점검할 API의 메서드·경로·베이스 URL·(선택) 인증·요청/응답 예시를 전달합니다. 에이전트가 `analyze_endpoint` 도구를 호출하면 내부적으로 프로필 파싱 → 기능 추출 → 시나리오 계획 → 점검 실행이 이어집니다.

입력 스키마 상세: [docs/endpointProfile.md](docs/endpointProfile.md)

**예시 (개념)**

```json
{
  "base_url": "http://localhost:4000",
  "method": "GET",
  "path": "/api/enrollments/me",
  "auth_required": true,
  "headers": { "Authorization": "Bearer <access_token>" }
}
```

- `status: "analyzed"` — 점검 완료
- `status: "need_more_context"` — `missing` 필드를 보완한 뒤 다시 호출

### 3) 결과 확인

결과는 **두 갈래**로 제공됩니다.

#### A. MCP 응답 (에이전트 → 대화창)

`analyze_endpoint`가 반환하는 JSON을 Cursor 에이전트가 읽고 채팅으로 요약합니다. 파일을 열지 않아도 동작합니다.

| 필드              | 설명                                                                    |
| ----------------- | ----------------------------------------------------------------------- |
| `status`          | `analyzed` / `need_more_context` / `invalid_input`                      |
| `run_id`          | 실행 추적 ID (`outputs/runs/` 폴더명과 동일)                            |
| `tool_results`    | 도구별 점검 결과 (status, severity, evidence, 권고 등)                  |
| `endpoint_report` | OWASP 시나리오별 집계 JSON                                              |
| `report_paths`    | 저장된 리포트 파일 경로 (`report_md`, `report_json`, `report_basename`) |

#### B. 사람용 분석 보고서 (`reports/`)

저장소 **루트**의 `reports/` 폴더에 Markdown·JSON이 저장됩니다. IDE에서 직접 열어 보거나 팀과 공유할 때 사용합니다.

| 파일                                           | 설명                                            |
| ---------------------------------------------- | ----------------------------------------------- |
| `reports/{METHOD}_{path}_{시각}_{접미사}.md`   | 가독성 좋은 분석 보고서 (요약 표, OWASP별 상세) |
| `reports/{METHOD}_{path}_{시각}_{접미사}.json` | 동일 내용의 구조화 JSON                         |

예: `reports/GET_api_admin_2026-05-20T05-42-56_9ddf04.md`

MCP 연결 문제는 Cursor **Output → MCP Logs**, 서버 내부 로그는 `outputs/logs/va-mcp.log`를 참고하세요.

## 업데이트

```bash
cd VA_MCP
git pull
uv sync
uv tool install --reinstall .
```

이후 MCP 클라이언트를 재시작합니다.

## 환경 변수 (선택)

프로젝트 루트 `.env` 또는 MCP 설정의 `env` 블록으로 지정할 수 있습니다.

| 변수             | 기본값                  | 설명                                         |
| ---------------- | ----------------------- | -------------------------------------------- |
| `LOG_LEVEL`      | `INFO`                  | 로그 상세도 (`DEBUG` 등)                     |
| `OUTPUT_DIR`     | (자동) `저장소/outputs` | 개발·디버깅 산출물 (runs, logs)              |
| `REPORTS_DIR`    | (자동) `저장소/reports` | 사람용 취약점 분석 리포트 (.md / .json)      |
| `DUMP_ARTIFACTS` | `false`                 | `true` 시 `outputs/runs/`에 단계별 JSON 덤프 |

## 문제 해결

| 증상                    | 확인                                                       |
| ----------------------- | ---------------------------------------------------------- |
| MCP 서버를 찾을 수 없음 | `which va-mcp`, PATH에 `~/.local/bin` 포함 여부            |
| 도구 목록이 비어 있음   | Cursor/Claude 재시작, MCP 설정 JSON 문법                   |
| 점검 중 통신 오류       | 대상 API(예: `localhost:4000`)가 실행 중인지               |
| JSON 파싱 실패          | 서버 코드에 `print()`로 stdout 사용 금지 — stdio 전용 채널 |

## 관련 프로젝트

취약점 학습용 수강신청 웹서버와 함께 사용할 수 있습니다. 같은 상위 폴더에 clone한 경우:

- `../broken_regist_backend` — NestJS API (기본 `http://localhost:4000`)
- `../broken_regist_frontend` — Next.js UI

## 개발자용 문서

기능 개발·브랜치 전략·테스트 작성 규칙은 팀 내부 문서를 참고하세요.

- [docs/dev_docs/DEV_GUIDE.md](docs/dev_docs/DEV_GUIDE.md) — 개발 워크플로우
- [docs/dev_docs/OBSERVABILITY.md](docs/dev_docs/OBSERVABILITY.md) — 로그·산출물 디버깅
- [docs/architecture/](docs/architecture/) — 아키텍처·구현 가이드

## 제한 사항

- 현재 배포 형태는 **로컬 stdio MCP**입니다. Cursor/Claude가 자식 프로세스로 `va-mcp`를 실행합니다.
- 원격 HTTP MCP·다중 사용자 호스팅은 추후 별도 배포 단계에서 검토 예정입니다.
