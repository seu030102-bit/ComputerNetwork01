# 실험망 데이터 수집·라벨 검증 결과

## 시나리오별 수집 현황

| 시나리오 | 공격 | 실험 수 | 통과 | 경고 | 실패 | 공격 시간(초) |
|---|---|---|---|---|---|---|
| arp_spoof | arp_spoof | 3 | 3 | 0 | 0 | 93 |
| dhcp_rogue | dhcp_rogue | 3 | 3 | 0 | 0 | 98 |
| dhcp_starve | dhcp_starve | 3 | 3 | 0 | 0 | 92 |
| mac_flood | mac_flood | 3 | 3 | 0 | 0 | 62 |
| normal | normal | 3 | 3 | 0 | 0 | 0 |
| port_scan | port_scan | 3 | 0 | 3 | 0 | 42 |
| syn_flood | syn_flood | 3 | 3 | 0 | 0 | 63 |

## 11주차 체크리스트

- ✅ 공격별 반복 수집 (공격마다 실패 없는 실험 3회 이상): arp_spoof 3, mac_flood 3, dhcp_rogue 3, dhcp_starve 3, port_scan 3, syn_flood 3
- ✅ 라벨 검증: 실험 21개 중 실패 0개
- ✅ 정상 30분 이상: 정상 전용 실험 32.0분 (공격 실험의 워밍업·쿨다운 정상 구간 5.8분 별도)

## 실패·경고 상세

- **20261121-141115-port_scan** (경고)
  - 경고: [a01 port_scan] 흔적이 start_ts 보다 12.4초 늦게 시작
- **20261121-141606-port_scan** (경고)
  - 경고: [a01 port_scan] 흔적이 start_ts 보다 13.1초 늦게 시작
- **20261121-142059-port_scan** (경고)
  - 경고: [a01 port_scan] 흔적이 start_ts 보다 12.3초 늦게 시작
