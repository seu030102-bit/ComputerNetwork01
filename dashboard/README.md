# dashboard/ — 대시보드와 알림 (P5)

실험 결과(경보)를 사람이 보기 좋게 보여주고, 디스코드로 알립니다.
데이터 로딩은 `load.py`(순수 함수, Streamlit 불필요)에 모여 있어 테스트가 쉽습니다.

## 구성

| 파일 | 내용 | 의존성 |
|---|---|---|
| `load.py` | 실험 폴더 → 요약·경보 표 | 표준 라이브러리만 |
| `app.py` | Streamlit 대시보드(경보 목록·탐지기별 집계·호스트) | streamlit |
| `notify.py` | 디스코드 웹훅 알림 (기본 미리보기) | 표준 라이브러리만 |

## 대시보드 실행

Streamlit은 시스템 numpy와 충돌해서 **전용 venv**에 설치합니다(탐지 파이프라인과 분리).

```bash
python3 -m venv ~/.venvs/dash
~/.venvs/dash/bin/pip install streamlit requests
~/.venvs/dash/bin/streamlit run dashboard/app.py
# 브라우저에서 http://localhost:8501
```

대시보드는 JSONL 파일만 읽으므로, 탐지 파이프라인(scapy/sklearn)이 도는 시스템 파이썬과
섞이지 않습니다.

## 디스코드 알림

```bash
# 미리보기(기본): 전송 없이 보낼 내용만 출력 — 외부로 아무것도 안 나감
python3 dashboard/notify.py data/runs/<run_id>

# 실제 전송: 각자 디스코드에서 웹훅 URL 발급 후
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
python3 dashboard/notify.py data/runs/<run_id> --send
```

⚠️ 웹훅 URL은 비밀입니다. 저장소·채팅에 올리지 마세요.

## 구성 (12주차 추가)

| 함수/상수 | 내용 |
|---|---|
| `ACTION_FILE` | `"actions.jsonl"` 상수 |
| `action_rows(run_dir)` | SDN 차단 기록 → 표 행 |
| `file_sizes(run_dir)` | 경보·행동 파일 크기 → 갱신 감지용 |
| `is_live(run_dir, threshold=60)` | 최근 N초 내 파일 변경 여부 → 실험 진행 중 판단 |

## 자동 갱신 동작

- 사이드바 **"실시간 자동 갱신"** 체크박스 (기본 ON)
- 갱신 주기 슬라이더: 2~30초 (기본 5초)
- 경보·행동 파일 크기를 세션 상태에 보관해 변화 감지 → `🔄 갱신됨` 뱃지
- 라이브 실험(`is_live`) 감지 시 → `🔴 LIVE` 뱃지, 목록에서 자동 선택
- `actions.jsonl` (SDN 차단 결과) 별도 테이블로 표시

## 검증 상태 (2026-11-24)

- ✅ `load.py` / `notify.format_alert`: `tests/test_dashboard.py` 16 → 121 전체 통과
- ✅ `file_sizes`, `is_live`, `action_rows` 단위 테스트 (9개) 추가
- ✅ `notify.py` 미리보기: 실제 arp_spoof 경보를 디스코드 payload로 변환 확인(전송 안 함)
- ✅ `app.py`: 전용 venv에서 headless 실행 시 정상 기동(HTTP 200)
