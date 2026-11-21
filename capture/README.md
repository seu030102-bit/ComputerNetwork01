# capture/ — 패킷 캡처와 특징 추출 (P2)

캡처(`capture.pcap`)에서 탐지기가 쓸 특징(`feat_host`, `feat_seg`)을 뽑습니다.
형식은 [`../docs/data-format.md`](../docs/data-format.md) 2.2, 2.3.

## 사용

```bash
# project/ 폴더에서 (WSL)
python3 capture/extract.py data/runs/<run_id>
# → features_1s.jsonl, features_5s.jsonl 생성
python3 common/records.py check data/runs/<run_id>
```

## 11주차: 데이터 수집·라벨링

| 파일 | 하는 일 | root |
|---|---|---|
| `collect.py` | 공격 시나리오 반복 실행 + 정상 전용 실험 → 실험마다 `extract.py` → 끝나면 `verify.py`, `label.py` 자동 실행 | 필요 |
| `verify.py` | **라벨 검증**: labels.jsonl이 실제 캡처 흔적과 맞는지 + 수집량 체크리스트 | 불필요 |
| `label.py` | 특징 창마다 정답을 붙인 CSV 데이터셋 (P3 학습, P4 임계치용) | 불필요 |

```bash
export PYTHONPATH=$PWD
python3 capture/collect.py --dry-run          # 실행 계획·예상 시간만 확인
sudo python3 capture/collect.py               # 공격 6종 × 3회 + 정상 30분(10분 × 3), 약 1시간
sudo python3 capture/collect.py --repeat 5 --with-evasive   # 반복 5회, *_slow 회피 공격 포함

# 수집 뒤 따로 다시 돌릴 때 (sudo 불필요)
python3 capture/verify.py --all               # → data/dataset/verify.md
python3 capture/label.py --all                # → data/dataset/{host,seg}_{1s,5s}.csv
```

- 공격 실험은 `env/run.py`(P1)를 그대로 부릅니다. P1의 11주차 공격(`dhcp_starve`, `dhcp_rogue`,
  `port_scan`, `syn_flood`)이 `scenarios.py`에 없으면 건너뛰고 알려 줍니다.
- 정상 실험(`<시각>-normal`)은 run.py의 망 구성·캡처 함수를 재사용하고 공격만 뺍니다.
  `labels.jsonl`은 빈 파일(= 전부 normal)입니다.
- 회차별로 섞어 실행하므로(1회차 6종 → 2회차 6종 …) 중간에 멈춰도 공격 종류가 고르게 남습니다.
- 진행 기록은 `data/collect_log.jsonl`. sudo로 만든 파일은 끝날 때 원래 사용자 소유로 돌려놓습니다.

### 라벨 규칙 (`label.py`)

창 `[ts − win, ts]`와 공격 구간이 겹친 비율(`overlap`)이 **0.5 이상**이면 그 공격, 아니면 `normal`.
`0 < overlap < 0.5`인 경계 창은 `ambiguous=1`로 표시합니다(학습에서 빼거나 따로 다룸).

| 행 | 공격 행이 되는 조건 |
|---|---|
| `host_*.csv` (feat_host) | 출발지 MAC = 공격자 MAC, 또는 meta에 없는 MAC(가짜 MAC)이고 공격이 `mac_flood`·`dhcp_starve` |
| `seg_*.csv` (feat_seg) | 포트 = 공격자 포트, 또는 포트 null(가짜 MAC 구간)이고 공격이 `mac_flood`·`dhcp_starve` |

열: `run_id, scenario, rep(반복 회차), ts, win, …특징…, label, overlap, ambiguous, evasive, attack_id`.
**학습/테스트는 `run_id`(또는 `rep`)로 나누세요.** 같은 실험의 창이 양쪽에 들어가면 점수가 부풀려집니다.

### 라벨 검증 기준 (`verify.py`)

| 결과 | 조건 |
|---|---|
| 실패 → 다시 수집 | label 없음/형식 오류/attack_id 중복, 공격 종류 ≠ 시나리오, 공격자 MAC이 meta의 attacker가 아님, 공격 구간이 실험 밖, **공격 구간에 흔적이 전혀 없음** |
| 경고 → 확인 | 흔적 약함(임계치 미만), 흔적이 start_ts보다 3초 넘게 늦음, end_ts보다 3초 넘게 일찍 끝남, 라벨 구간 밖에도 같은 흔적, 정상 구간에 ARP 충돌·가짜 MAC·등록 안 된 DHCP OFFER |

공격별 "흔적"은 1초 특징에서 셉니다: ARP 스푸핑 = 공격자 `arp_rep`, MAC 플러딩 = null 구간 `new_src_macs`,
DHCP 고갈 = null 구간 `dhcp_discover`, 가짜 DHCP = 공격자 `dhcp_offer+ack`, 스캔·SYN flood = 공격자 `tcp_syn`.
마지막에 11주차 체크리스트(공격별 반복, 라벨 검증, 정상 30분)를 ✅/❌로 출력합니다.

## 무엇을 계산하나

- **ARP 충돌(`arp_ip_conflicts`)**: 캡처를 시각 순서로 훑으며 IP-MAC 대응표를 **학습**하고
  (처음 본 쌍 등록, DHCP ACK로 갱신), 그 표와 다른 MAC이 같은 IP를 주장하면 충돌로 셈.
- **미요청 ARP 응답(`arp_rep_unsolicited`)**: 최근 5초 내 who-has 요청이 없던 ARP 응답.
- **구간별 새 MAC(`feat_seg.new_src_macs`)**: MAC 플러딩 신호.
- 그 외 패킷/바이트 수, DHCP·TCP·DNS 카운트 등(11주차 규칙용, 없으면 0).

## 검증 상태 (2026-11-13, 실제 pcap)

- ✅ arp_spoof/mac_flood 캡처에서 features 생성 → 형식 검사 통과
- ✅ ARP 스푸핑 캡처에서 공격자(`…04`)의 `arp_ip_conflicts=1` 정확히 계산
- ✅ MAC 플러딩 캡처에서 1초당 새 MAC 19~27개 계산

## 한계 (의도된 것)

- **오프라인 pcap은 '들어온 스위치 포트'를 담지 않음.** 미러 캡처에는 입력 포트 정보가 없어서,
  포트는 `meta.json`의 MAC→포트로 역산함. meta에 없는 MAC(플러딩용 가짜 MAC)은 포트 `null`
  구간으로 묶음(data-format 2.3의 null 허용). **포트별 정확 집계는 실시간 캡처(12주차)**에서.
- **대응표 학습은 "정상 통신이 먼저"임을 가정.** 시나리오의 워밍업 구간에서 진짜 IP-MAC이
  먼저 학습되므로 이후 사칭이 충돌로 잡힘. 워밍업 없이 공격이 가장 먼저 오면 오학습 가능.
