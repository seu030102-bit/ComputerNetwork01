# sdn/ — SDN 컨트롤러와 자동 차단 (P4)

Mininet 스위치를 OS-Ken이 제어합니다. 경보(`alert`)가 오면 공격자 MAC·포트에
**drop 흐름**을 설치하고 `action` 기록을 남깁니다 (12주차 사후 차단 시제품).

> Ryu 대신 **OS-Ken** (`apt install python3-os-ken`).

## 파일

| 파일 | 내용 |
|---|---|
| `l2_switch.py` | L2 학습 스위치 + inbox 경보 → drop + `actions.jsonl` |
| `policy.py` | 경보 → 차단 대상(MAC/포트) 결정 (OS-Ken 불필요) |
| `apply_alerts.py` | 실험 폴더 경보를 inbox로 보내거나 offline action 기록 |

## 차단 규칙

| 경보 attacker | drop 매칭 | 예 |
|---|---|---|
| MAC (+ port) | `eth_src` (+ `in_port`) | arp_spoof, dhcp_rogue, port_scan, syn_flood |
| port만 (MAC null) | `in_port` | mac_flood, dhcp_starve |
| 둘 다 없음 | 차단 안 함 | — |

우선순위 100 (학습 규칙 1·table-miss 0보다 높음). 같은 대상은 10초에 한 번만 설치/기록.

## 실행 (라이브)

터미널 2~3개가 필요합니다.

```bash
# 1) 컨트롤러 (프로젝트 루트)
mkdir -p data/sdn
: > data/sdn/inbox.jsonl
: > data/sdn/actions.jsonl
SDN_INBOX=$PWD/data/sdn/inbox.jsonl SDN_ACTIONS=$PWD/data/sdn/actions.jsonl \
  PYTHONPATH=$PWD osken-manager sdn.l2_switch

# 2) 실험망
sudo python3 env/run.py arp_spoof --controller remote

# 3) (실험 중·후에) 경보를 inbox에 넣기 — 스위치가 아직 연결돼 있어야 drop이 먹음
python3 sdn/apply_alerts.py data/runs/<run_id> --inbox data/sdn/inbox.jsonl \
  --copy-actions data/sdn/actions.jsonl
```

경보 한 줄만 시험:

```bash
python3 sdn/apply_alerts.py --inbox data/sdn/inbox.jsonl --inject-json \
  '{"v":1,"type":"alert","ts":1e9,"alert_id":"t1","detector":"rule","source":"x","attack":"arp_spoof","score":1,"attacker":{"mac":"00:00:00:00:00:04","ip":"10.0.0.4","sw":"s1","port":4},"victim":null,"feature_ts":1e9,"win":1,"summary":"","evidence":{}}'
# 확인: ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100
```

## 오프라인 (평가·데모 파이프라인)

실험이 끝난 뒤에도 P5 평가가 `actions.jsonl`을 쓸 수 있게, 스위치 없이 action만 기록:

```bash
python3 rules/detect.py data/runs/<run_id>
python3 sdn/apply_alerts.py data/runs/<run_id> --offline
```

`reason` 끝에 `[offline]`이 붙습니다. 실제 패킷 drop은 라이브 경로에서만 확인하세요.

`run_demo.sh`는 탐지 후 자동으로 `--offline` action을 남깁니다.
`--controller=remote`면 컨트롤러도 띄우지만, 실험 종료 후엔 스위치가 끊겨
inbox drop은 보통 실패합니다 → 라이브 검증은 위 “실행 (라이브)”를 따르세요.

## 검증 상태

- ✅ OS-Ken L2 제어 (2026-11-13): failMode=secure pingall 0% 손실
- ✅ 단위 테스트: `python -m unittest tests.test_sdn_policy`
- ⏳ WSL 라이브: 경보 inject → priority=100 drop → 공격자 ping 실패 (로컬에서 확인)

## 다음 (13주차)

- ★ 사전 차단: DHCP 응답으로 IP-MAC-포트 표, 안 맞는 ARP `pre_drop`
- 차단 시간 제한(`expires_ts`)·허용 목록
- 5종 공격 차단을 데모 스크립트에 고정
