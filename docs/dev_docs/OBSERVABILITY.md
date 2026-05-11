# Observability Guide

VA-MCP 개발 단계의 디버깅에 대한 방법과 코드 내용을 정리한 문서입니다.

> **작성일**: 2026.05.11
> **작성자**: 이윤재
> **버전**: 1.0.0 (개발 단계 기준)
> **적용 범위**: `src/va_mcp/` 전 모듈

---

## 0) 한 줄 요약

- **로그**는 사람이 흐름을 따라가는 짧은 메시지, **아티팩트**는 모듈 간 주고받은 데이터(JSON) 통째.
- 둘 다 파일로만 남긴다. **`print()` 금지** — MCP stdio 프로토콜이 깨진다.
- run 1회당 폴더 1개를 만들고 그 안에 모든 산출물을 모은다.
- 운영 환경 분리는 코드 수정이 아니라 **환경변수 토글**로 한다. (다만 본 버전에선 dump 코드 자체를 배포 전 제거하기로 합의 — §6 참고)

---

## 1) 왜 신경 써야 하는가 (MCP stdio 제약)

`va-mcp`는 stdio transport로 동작하는 MCP 서버다 (`src/va_mcp/server.py`). 즉 클라이언트(Cursor)와 다음 채널로 통신한다.

| 표준 채널 | 줄임말 | 번호 | 이 프로젝트에서의 용도 |
|---|---|---|---|
| standard input | stdin | 0 | Cursor → va-mcp로 들어오는 JSON-RPC 요청 |
| standard output | stdout | 1 | **MCP 프로토콜 응답 전용**. 다른 출력 금지 |
| standard error | stderr | 2 | 로그/진단 메시지. Cursor MCP 패널에서 조회 |

핵심 규칙:

- `stdout`에는 **JSON-RPC 외 어떤 것도 들어가면 안 된다**. `print("here")` 같은 한 줄이 끼면 Cursor가 JSON 파싱에 실패해 MCP 통신이 즉시 깨진다.
- 디버그 메시지는 **반드시 `logging` 모듈** 또는 **파일 dump**로만 보낸다.
- `print(file=sys.stderr)`도 가능하지만 통일성을 위해 `logger.debug/info(...)`를 사용한다.

서버 진입점이 stderr로 가는 예시:

```7:9:src/va_mcp/server.py
def main() -> None:
    print("[va-mcp] stdio server starting...", file=sys.stderr, flush=True)
    mcp.run(transport="stdio")
```

---

## 2) 폴더 구조

`outputs/`는 전체가 `.gitignore`로 추적 제외되어 있다. 디버깅 산출물은 마음껏 쌓아도 git 부담 없음.

```
outputs/
├── logs/
│   └── va-mcp.log                           # 글로벌 로그 (모든 run 누적, rotating)
├── runs/
│   └── 2026-05-11T22-30-15_a3f2c1/          # run 1회 = 폴더 1개
│       ├── summary.md                        # 사람용 요약 (run 끝나면 자동 생성)
│       ├── run.log                           # 이 run의 로그만
│       ├── 00_input.json                     # Cursor가 보낸 raw input
│       ├── 01_endpoint_profile.json          # parser/normalizer/validator 통과 후
│       ├── 02_feature_set.json               # FeatureExtractor 결과
│       ├── 03_planner_output.json            # ScenarioPlanner 결과
│       ├── 04_tool_results/
│       │   ├── sql_injection.json
│       │   ├── retry_handling.json
│       │   └── ...
│       └── meta.json                         # run_id, started/ended, status
├── raw/        # (기존) Evidence raw 저장
├── findings/   # (기존) Finding 산출물
└── reports/    # (기존) 최종 리포트
```

원칙:

- 한 run의 모든 정보는 **그 run 폴더 하나로 자급자족**해야 한다. 옆 폴더를 참조하지 않는다.
- 같은 input을 두 번 돌려도 폴더가 분리되어야 한다 → 폴더명에 타임스탬프 + 짧은 uuid.
- 회의/슬랙 공유는 **폴더 통째 zip**으로 한다.

---

## 3) 두 채널 — 로그 vs 아티팩트

| 항목 | 로그 (logger) | 아티팩트 dump (JSON 파일) |
|---|---|---|
| 목적 | 흐름 파악 | 시점 데이터 분석 |
| 형식 | 한 줄 텍스트 | JSON 통째 |
| 크기 | 작음 | 큼 (수 KB~수 MB) |
| 위치 | `outputs/logs/va-mcp.log` (글로벌), `outputs/runs/<id>/run.log` (run별) | `outputs/runs/<id>/<NN>_<stage>.json` |
| 도구 | `tail -f`, `grep`, `less` | `jq`, `diff`, 에디터 |
| 켜기/끄기 | `LOG_LEVEL` 환경변수 | `DUMP_ARTIFACTS` 환경변수 |

### 3.1 로그 사용 패턴

모든 모듈은 파일 상단에 logger를 선언한다:

```python
import logging
logger = logging.getLogger(__name__)
```

단계의 입력/출력은 기존 헬퍼를 그대로 재사용한다 (`src/va_mcp/endpoint_profile/logging_utils.py`):

```python
from va_mcp.endpoint_profile.logging_utils import log_stage_io

log_stage_io(logger, "feature_extractor",
             input_data=profile.to_serializable_dict(),
             output_data=feature_set_dict)
```

일반 메시지는 표준 `logging` 레벨로:

```python
logger.debug("planner candidates=%s tools=%d", candidates, len(tool_ids))
logger.info("orchestrator: ran %d tools, vulnerable=%d", n_total, n_vuln)
logger.warning("A05 not selected (has_free_text_input=False)")
logger.error("tool %s raised %s", tool_id, exc)
```

### 3.2 아티팩트 dump 사용 패턴

단계마다 직렬화 가능한 dict를 받아 파일로 떨군다. `services/endpoint_analysis.py`의 파이프라인 각 단계 사이에 호출한다.

```python
from va_mcp.config import DUMP_ARTIFACTS, OUTPUT_DIR

if DUMP_ARTIFACTS:
    run_dir = OUTPUT_DIR / "runs" / f"{ts}_{short_uuid}"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "01_endpoint_profile.json").write_text(
        json.dumps(profile.to_serializable_dict(), ensure_ascii=False, indent=2)
    )
```

---

## 4) 환경변수 (`.env`)

| 변수 | 기본값 | 의미 | 운영 권장값 |
|---|---|---|---|
| `LOG_LEVEL` | `INFO` | `logger.<level>` 출력 임계값 (`DEBUG/INFO/WARNING/ERROR`) | `WARNING` |
| `DUMP_ARTIFACTS` | `false` | per-run 폴더 dump 활성화 여부 | `false` |
| `OUTPUT_DIR` | `./outputs` | 산출물 루트 디렉토리 | 상황별 |

개발자의 일반적인 `.env`:

```env
APP_NAME=va-mcp
LOG_LEVEL=DEBUG
DUMP_ARTIFACTS=true
OUTPUT_DIR=./outputs
```

> 변수만 바꾸면 같은 코드가 환경별로 다르게 동작한다. **코드 수정 없이** 디버그 출력을 끌 수 있는 게 핵심.

---

## 5) 마스킹 정책 (개발 단계 vs 배포 단계)

VA-MCP는 취약점 분석 도구라는 도메인 특성상, 분석 evidence에 **실제 사용된 페이로드/credential/응답 원문이 그대로 보존되어야** 의미가 있다. 따라서 본 버전(개발 단계)에서는 아래 정책을 따른다.

### 5.1 개발 단계 (현재) — **마스킹 OFF**

- `outputs/runs/<id>/` 안의 모든 JSON은 **마스킹 없이 raw**로 기록한다.
- 포함될 수 있는 민감 정보 (의도된 노출):
  - `Authorization` / `Cookie` / `Set-Cookie` 헤더 원문
  - body의 `password`, `passwordHash`, `token`, `secret`, `apiKey`, `refreshToken`, `accessToken` 등
  - 응답의 access/refresh token 원문
- `outputs/`는 `.gitignore`로 추적 제외되므로 외부 유출 위험은 로컬 디스크 범위로 한정된다.
- 디버깅이 끝난 run 폴더는 **본인이 직접 삭제**한다. (`rm -rf outputs/runs/<id>/`)

> 따라서 `core/utils.py`의 `mask_sensitive` / `sanitize_request_body` / `sanitize_response_sample`은 본 버전 dump 경로에서는 **호출하지 않는다**. 단, 기존에 이 헬퍼를 쓰는 Evidence 생성 경로는 그대로 둔다 (그쪽 정책은 별도).

### 5.2 배포 단계 (예정) — **dump 코드 자체 제거**

배포 직전 PR에서 다음을 수행한다:

1. `services/endpoint_analysis.py` 등에 추가된 per-run dump 호출 코드를 제거한다.
2. `config.py`의 `DUMP_ARTIFACTS` 관련 분기와 변수 선언을 제거한다.
3. `.env.production` 또는 운영 env에 `LOG_LEVEL=WARNING`을 박는다.
4. 회귀 테스트: `analyze_endpoint`가 정상 동작하면서 `outputs/runs/`가 생성되지 않는지 확인.

> **회의 재논의 대상**: "dump 코드 자체를 제거"하는 대신 "운영에선 절대 켜질 수 없도록 시작 시 가드"로 가는 안도 검토 가능 (예: `APP_ENV=production`이면 `DUMP_ARTIFACTS=true`를 거부). 현 시점에선 제거 방식으로 결정함.

---

## 6) 금지 사항 / 권장 사항

### 금지

- ❌ `print(...)` — stdout 오염, MCP 통신 즉시 파괴
- ❌ `import pdb; pdb.set_trace()` — 자식 프로세스에서 input 받을 수 없음, hang 발생
- ❌ 임시 파일을 모듈마다 자기 마음대로 만드는 것 (예: `/tmp/debug.json`)
- ❌ 로그 메시지에 거대한 dict/list를 그대로 박는 것 — 아티팩트로 분리

### 권장

- ✅ 새 모듈 최상단: `logger = logging.getLogger(__name__)` 한 줄
- ✅ 단계의 입력/출력 지점에 `log_stage_io(logger, "<stage>", input_data=..., output_data=...)`
- ✅ run 폴더에서 디버깅이 끝나면 폴더 통째 삭제 (`rm -rf outputs/runs/<id>/`)
- ✅ 회의/슬랙 공유 시 해당 run 폴더만 zip해서 첨부

---

## 7) 자주 쓰는 CLI 도구 (퀵 레퍼런스) - 터미널에서 디버깅 하고싶은경우 참고.

| 도구 | 한 줄 용도 | 대표 예시 |
|---|---|---|
| `tail -f` | 파일 끝을 실시간 follow | `tail -f outputs/logs/va-mcp.log` |
| `grep` | 패턴 매치 줄 출력 | `grep -rn "A05" outputs/runs/` |
| `less` | 큰 파일 페이지 단위 탐색 | `less outputs/runs/<id>/03_planner_output.json` |
| `diff` | 두 파일/폴더 비교 | `diff -ur outputs/runs/<before>/ outputs/runs/<after>/` |
| `jq` | JSON 조회/필터 | `jq '.tool_ids' outputs/runs/<id>/03_planner_output.json` |

`grep` 자주 쓰는 옵션: `-i`(대소문자 무시), `-n`(줄번호), `-r`(재귀), `-A N`(매치 뒤 N줄), `-B N`(앞 N줄), `-C N`(앞뒤 N줄).
요즘은 `grep` 대신 `rg`(ripgrep)도 권장 — 더 빠르고 `.gitignore` 자동 인식.

`less` 단축키: `Space`(다음 페이지), `b`(이전), `g/G`(맨 처음/끝), `/단어`(검색), `n/N`(다음/이전 결과), `q`(종료).

`diff -u` 형식이 git diff와 같으므로 기본으로 권장.

### 우리 케이스에서의 흐름 예시

> "`/api/auth/login` 분석 결과에 `sql_injection`이 왜 없지?"

1. `tail -f outputs/logs/va-mcp.log` — 다른 터미널에서 켜둔 채로 Cursor에서 `analyze_endpoint` 호출 → 실시간 로그 확인
2. `less outputs/runs/<id>/03_planner_output.json` → `/tool_ids` 검색
3. 버그 수정 후 다시 호출 → 새 run 생성
4. `diff -u outputs/runs/<before>/03_planner_output.json outputs/runs/<after>/03_planner_output.json` → 변경 확인

---

## 8) 배포 전 체크리스트 (운영 전환 시)

- [ ] `services/endpoint_analysis.py` 등에서 per-run dump 호출부 제거
- [ ] `config.py`의 `DUMP_ARTIFACTS` 변수/분기 제거
- [ ] 운영 env에 `LOG_LEVEL=WARNING` 설정
- [ ] `outputs/runs/`, `outputs/logs/` 디렉토리가 생성되지 않는지 회귀 테스트
- [ ] `core/utils.py`의 `mask_sensitive` 등은 그대로 유지 (Evidence 경로에서 사용 중)
- [ ] `.env`가 실수로 커밋되지 않았는지 확인 (`git ls-files | grep ".env$"`)

---

## 9) 변경 이력

| 일자 | 버전 | 변경 |
|---|---|---|
| 2026.05.11 | 1.0.0 | 최초 작성. 개발 단계 마스킹 OFF 정책, 배포 전 dump 코드 제거 방침 확정. |

