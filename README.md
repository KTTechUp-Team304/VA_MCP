# VA-MCP
개발단계중 기능 단위 테스트시에, OWASP TOP10에 해당하는 취약점을 점검하고 넘어가기 위한 MCP 입니다. 해당 MCP는 API에 대한 정보를 받고, 분석하여 분석에 대한 산출물을 반환할 예정입니다.

## Scope (MVP)

- MCP stdio 서버 실행
- 기본 도구 제공:
  - `ping`
  - `list_supported_checks`
- 향후 OWASP Top 10 시나리오 확장

## 사전 준비 (Prerequisites)

팀원이 개발을 시작하기 전에 아래가 설치되어 있어야 합니다.

- Git
- `uv`
- (권장) Python 3.11+

설치 확인:

```bash
git --version
uv --version
python3 --version
```

## Quick Start

```bash
# 1) 저장소 클론
git clone <repo-url>
cd VA-MCP

# 2) 의존성/가상환경 동기화
uv sync

# 3) 테스트 확인
uv run pytest -q

# 4) MCP 서버 실행
uv run va-mcp
```

`va-mcp`는 stdio transport로 동작하므로 MCP 클라이언트(IDE/Agent)에서 서버로 연결해 사용합니다.

## 개발 규칙

팀 개발 규칙(브랜치 전략, 테스트, PR, 커밋 규칙)은 [docs/dev_docs/DEV_GUIDE.md](docs/dev_docs/DEV_GUIDE.md)를 참고하세요.

## 테스트 가이드

기능 개발 후 아래 순서로 테스트합니다.

```bash
# 1) 의존성 동기화
uv sync

# 2) 테스트 실행
uv run pytest -q
```

- 테스트 코드는 루트 `tests/` 폴더에 작성합니다.
- 새 기능을 추가하면 대응하는 테스트를 반드시 함께 추가합니다.
- 최소 기준:
  - 기능 단위 테스트 1개 이상
  - `tests/test_smoke.py`가 계속 통과해야 함

## 디렉토리 역할

- `src/va_mcp/`: 애플리케이션 소스 코드 루트
- `src/va_mcp/server.py`: MCP 서버 진입점 (`va-mcp` 실행 시 시작되는 파일)
- `src/va_mcp/app.py`: `FastMCP` 앱 생성 및 초기화
- `src/va_mcp/config.py`: 환경변수 로드, 출력 디렉토리 설정
- `src/va_mcp/registry/`: 어떤 기능(tool)과 데이터(resource)를 MCP에 보여줄지 등록하는 곳
- `src/va_mcp/tools/`: MCP가 실제로 실행하는 기능 함수들 (예: `ping`, 점검 실행)
- `src/va_mcp/resources/`: 기능에서 공통으로 쓰는 기준 데이터 모음 (예: 지원 점검 목록)
- `tests/`: 테스트 코드 (개발 완료 후 필수 실행)
- `outputs/`: 실행 결과 산출물 저장

## Notes

- 현재는 로컬 연동(stdio) 기준으로 설계되어 있습니다.
- 추후 AWS 배포 단계에서 HTTP 방식으로 전환할 예정입니다.
