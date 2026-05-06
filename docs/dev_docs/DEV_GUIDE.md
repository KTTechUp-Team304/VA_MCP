# Dev Guide

이 문서는 304 팀의 개발 규칙을 정리한 문서입니다.  
반드시 준수해 주세요 !!

> **작성일**: 2026.04.23
> **작성자**: 이윤재
> **버전**: 1.0.0

## 0) 사전 준비 (필수)

다음 항목이 설치되어 있어야 합니다.

- Git
- uv
- (권장) Python 3.11+

설치 확인:

```bash
git --version
uv --version
python3 --version
```

## 1) 브랜치 전략

- 기본 브랜치: `dev`
- 기능 개발 브랜치: `feature/기능명`
- 버그 수정 브랜치: `fix/이슈명` (선택)

브랜치 이름 예시:

- `feature/add-xss-check`
- `feature/update-scan-registry`
- `fix/ping-tool-response`

개발 시작 전:

```bash
git checkout dev
git pull origin dev
git checkout -b feature/기능명
```

git 명령어 정리
```bash
git checkout -b 브랜치명  :브랜치 생성 후 이동
git checkout 브랜치명     : 해당 브랜치로 이동
```

개발과 테스트 후 pr올리는 과정
```bash
git add .                  : 스테이징
git commit -m '커밋 메시지'   : 커밋메시지 남기기
git push origin 브랜치명      : 원격저장소로 작업상황 푸쉬
깃 레포로 이동후 pr 생성         : 헷갈리실경우 구글링 부탁드립니다.
```

## 2) 개발 워크플로우

1. 기능 브랜치 생성
2. 기능 구현 (`src/va_mcp/`)
3. 테스트 코드 작성/수정 (`tests/`)
4. 로컬 테스트 실행
5. 커밋/푸시
6. PR 생성 및 리뷰 반영

## 3) 테스트 규칙

기능 개발 후 아래 명령은 필수로 실행합니다.

```bash
uv sync
uv run pytest -q
```

테스트 규칙:

- 새 기능에는 최소 1개 이상의 테스트를 추가합니다.
- 기존 테스트가 깨지면 머지하지 않습니다.
- `tests/test_smoke.py`는 항상 통과 상태를 유지합니다.

## 4) 커밋 메시지 규칙

권장 형식:

- `feat: 새로운 기능 추가`
- `fix: 버그 수정`
- `refactor: 구조 개선 (동작 변화 없음)`
- `test: 테스트 추가/수정`
- `docs: 문서 수정`

예시:

- `feat: SQLI 스크립트 추가`
- `test: XSS 기능 테스트 코드 수정`

## 5) PR 규칙

PR에는 아래 내용을 포함합니다.

- 무엇을 변경했는지
- 왜 변경했는지
- 어떻게 테스트했는지 (`uv run pytest -q` 결과)
- 필요하면 스크린샷/로그

PR 체크리스트:

- [ ] `dev` 최신 기준으로 작업함
- [ ] 기능 코드와 테스트를 함께 수정함
- [ ] 로컬 테스트 통과
- [ ] 불필요한 파일(산출물, 임시 파일) 제외

## 6) 디렉토리 역할

- `src/va_mcp/`: 애플리케이션 소스 코드 루트
- `src/va_mcp/server.py`: MCP 서버 진입점 (`va-mcp`)
- `src/va_mcp/app.py`: `FastMCP` 앱 생성 및 초기화
- `src/va_mcp/config.py`: 환경변수 및 출력 디렉토리 설정
- `src/va_mcp/registry/`: tool/resource 등록 담당
- `src/va_mcp/tools/`: MCP tool 구현
- `src/va_mcp/resources/`: 정적 데이터(단일 소스)
- `tests/`: 테스트 코드
- `outputs/`: 실행 산출물

## 7) 하지 말아야 할 것

- `dev` 브랜치에 직접 커밋하지 않기
- 테스트 없이 기능만 올리지 않기
- 민감 정보(`.env`)를 커밋하지 않기
