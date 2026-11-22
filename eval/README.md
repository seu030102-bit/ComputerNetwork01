# eval/ — 비교 실험과 성능 평가 (P5)

실험 폴더의 `labels / alerts / actions / features`를 읽어
[`../docs/data-format.md`](../docs/data-format.md) 4장 정의대로 성능표를 자동 계산합니다.

## 스크립트

| 파일 | 역할 |
|------|------|
| `evaluate.py` | 실험 폴더(들) 평가 → 터미널/MD 테이블 출력 |
| `report.py`   | 주차별 보고서 생성 → PNG 3개 + summary.md + report.html |

---

## evaluate.py — 빠른 평가

```bash
python3 eval/evaluate.py data/runs/<run_id> [...]       # 특정 실험
python3 eval/evaluate.py --all                           # data/runs 전체
python3 eval/evaluate.py --all --out eval/results/summary.md
```

---

## report.py — 주차별 보고서

```bash
# w11 실험 전체 보고서 생성
python3 eval/report.py data/runs/*/ --week w11

# 출력 폴더를 직접 지정할 때
python3 eval/report.py data/runs/*/ --week w11 --out eval/results/w11
```

### 출력 파일 (`eval/results/w11/`)

| 파일 | 내용 |
|------|------|
| `summary.md`       | 공격별 탐지율 · 탐지 시간 · 정상 구간 오탐 표 |
| `detect_rate.png`  | 공격별 탐지율 막대 차트 (탐지기별 색상) |
| `detect_time.png`  | 공격별 평균 탐지 시간 막대 차트 |
| `false_pos.png`    | 정상 구간 오탐 막대 차트 |
| `report.html`      | 실험 카드 보고서 (PNG base64 삽입, CDN 없음) |

### 탐지기 자동 확장

현재 `alerts_rule.jsonl`만 있으면 **rule** 막대만 그려집니다.
나중에 `alerts_ai.jsonl`이 추가되면 **ai** 막대가 자동으로 추가됩니다.
(`alerts.jsonl`, `alerts_rule.jsonl`, `alerts_ai.jsonl` 중 존재하는 파일을 모두 읽습니다.)

여러 탐지기의 경보 파일을 모두 읽어 `detector`별(규칙/AI/혼합)로 나눠 집계합니다
(`alerts.jsonl`, `alerts_rule.jsonl`, `alerts_ai.jsonl` 중 있는 것).

## 지표 (data-format 4장)

| 열 | 뜻 |
|---|---|
| 탐지 | 경보가 1개 이상 난 공격 수 / 전체 공격 수 |
| TP / FP | 맞은 경보 / 틀린 경보 |
| 탐지시간 | 첫 TP 경보 시각 − 공격 시작 시각 (평균) |
| 대응시간 | 첫 block action 시각 − 공격 시작 시각 (SDN 연결 후, 12주차) |
| 공격자특정 | 경보의 `attacker.mac`이 정답과 일치(O) / 불일치(X) / 미지정(-) |
| 정상구간오탐 | 공격 밖(정상)에서 난 경보 수 |

판정 기준(팀 공통): `attack`이 같고 `ts`가 `[start, end + 5초]` 안이면 TP.
`attack`은 맞아도 `attacker.mac`이 정답과 다르면 **FP**(엉뚱한 PC를 차단하게 되므로).
`attacker.mac`이 `null`이면 '미지정'으로 보고 FP로 세지 않음(오프라인 MAC 플러딩 등).

## 현재 결과 (2026-11-13, 규칙 탐지기)

| 공격 | 탐지 | TP | FP | 탐지시간 | 공격자특정 | 정상구간오탐 |
|---|---|---|---|---|---|---|
| arp_spoof | 1/1 | 2 | 0 | 1.56초 | O (`…04`) | 0 |
| mac_flood | 1/1 | 2 | 0 | 1.30초 | X (오프라인 한계) | 0 |

지표 계산 로직은 `../tests/test_evaluate.py`(7개)로 검증됨: 공격자 오지정·정상구간
경보가 실제로 FP로 집계되고, GRACE 경계·대응시간·탐지율이 정의대로 나옴.
`results/`에는 생성된 요약표가 들어갑니다(용량이 작아 올려도 됨).
