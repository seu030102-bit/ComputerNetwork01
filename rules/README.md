# rules/ — 규칙 기반 탐지기 (P4)

특징(`features_*.jsonl`)을 읽어 공격을 판정하고 경보(`alerts_rule.jsonl`)를 만듭니다.
형식은 [`../docs/data-format.md`](../docs/data-format.md) 2.4.

## 사용

```bash
# w11 데이터 (저장소 루트)
tar xzf datasets/w11_lab.tar.gz
python3 rules/detect.py data/runs/<run_id>
# → alerts_rule.jsonl
python3 eval/evaluate.py --all
```

## 규칙 (11주차, 6종)

| 규칙 | 조건 | 판정 |
|---|---|---|
| `arp_conflict` | `feat_host.arp_ip_conflicts > 0` | ARP 스푸핑 |
| `arp_unsolicited` | `arp_rep_unsolicited ≥ 5` (5초창) | ARP 스푸핑 |
| `mac_flood` | `new_src_macs ≥ 15` (1초창), DHCP 신호 없을 때 | MAC 플러딩 |
| `dhcp_rogue` | 정상 `meta.dhcp_servers` 밖 MAC이 `dhcp_offer`/`dhcp_ack` | 가짜 DHCP |
| `dhcp_starve` | `dhcp_discover ≥ 15` 또는 `dhcp_chaddrs ≥ 5` (1초창) | DHCP 고갈 |
| `port_scan` | `dst_ports ≥ 40` 이고 `tcp_syn ≥ 15` | 포트 스캔 |
| `syn_flood` | `tcp_syn ≥ 25` 이고 `dst_ports ≤ 5` | SYN flood |

- 임계치는 `detect.py` 상단 상수. w11_lab(정상 32분) 대비 잡음.
- 같은 (공격자, 공격)은 10초에 한 번만 경보.
- `dhcp_starve`를 `mac_flood`보다 먼저 판정(가짜 MAC+DISCOVER가 겹침).

## 검증 (w11_lab, 2026-11-22)

| 공격 | 탐지 | 정상구간 오탐 | 공격자 특정 |
|---|---|---|---|
| arp_spoof (×3) | 1/1 | 0 | O |
| mac_flood (×3) | 1/1 | 0 | X (가짜 MAC) |
| dhcp_rogue (×3) | 1/1 | 0 | O |
| dhcp_starve (×3) | 1/1 | 0 | X (가짜 chaddr) |
| port_scan (×3) | 1/1 | 0 | O |
| syn_flood (×3) | 1/1 | 0 | O |
| normal (×3) | — | 0 | — |

→ **11주차 완료 기준 충족**: 캡처 폴더로 규칙 탐지·평가 가능.

## 다음 (12주차)

- 경보 → SDN drop 차단 (`sdn/`)
- ★ 사전 차단은 13주차
