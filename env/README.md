# env/ — 실험 환경과 공격·정상 트래픽 (P1)

격리된 Mininet LAN을 띄우고, 정상 트래픽과 공격을 재현해서 `data/runs/<run_id>/`에
캡처(`capture.pcap`), 정답(`labels.jsonl`), 실험 정보(`meta.json`)를 남깁니다.
형식은 [`../docs/data-format.md`](../docs/data-format.md)를 따릅니다.

## 안전 수칙 (반드시)

- **격리된 Mininet 환경에서만** 실행합니다. 공격 스크립트는 실제 LAN(학교망, 공용 와이파이)에서
  실행되지 않도록 `attacks/labguard.py`가 코드로 막습니다(Mininet 네임스페이스 + `LAB_OK=1` 확인).
- Mininet 가상 MAC(`00:00:00:00:00:0X`)만 씁니다.

## 공용 환경 세팅 (팀원 전원 동일)

모든 팀원이 **Ubuntu 24.04**에서 같은 패키지로 실험망을 돌립니다. 아래 둘 중 하나를 고르세요.

**A. Windows: WSL2 (권장)** — PowerShell(관리자)에서
```powershell
wsl --install -d Ubuntu-24.04    # 설치 후 재부팅, 사용자 생성
```
**B. VM(VirtualBox/VMware 등):** Ubuntu 24.04 Desktop/Server ISO로 새 VM
(CPU 2코어, 메모리 4GB, 디스크 20GB 이상).

이후 Ubuntu 터미널에서 (A, B 공통):
```bash
sudo apt update
sudo apt install -y git mininet openvswitch-switch python3-scapy python3-pip      dsniff hping3 nmap tcpdump iperf3 dnsmasq-base dnsutils wget
sudo systemctl enable --now openvswitch-switch   # WSL에서 systemd가 없으면: sudo service openvswitch-switch start

git clone https://github.com/seu030102-bit/ComputerNetwork01.git
cd ComputerNetwork01          # 팀 저장소는 project/ 폴더 없이 루트에 env/, capture/ 등이 있음
sudo python3 env/selfcheck.py                    # 환경 점검 (전부 [OK]여야 함)
```
- Mininet은 Linux 전용입니다. root 권한이 필요합니다(`sudo`).
- `selfcheck.py`가 확인하는 것: 필수 프로그램, scapy, ping, DNS, **DHCP 서버 OFFER**.
  `[FAIL]`이 나오면 그 줄의 안내대로 패키지를 설치하세요.
- Windows 드라이브(`/mnt/c/...`)에 저장소를 두면 느립니다. 가능하면 `~/` 아래에 clone 하세요.

## 실행

```bash
# project/ 폴더에서
sudo python3 env/run.py arp_spoof          # ARP 스푸핑 시나리오
sudo python3 env/run.py mac_flood          # MAC 플러딩
sudo python3 env/run.py arp_spoof_slow     # 느린 ARP 스푸핑(회피 공격)
sudo python3 env/run.py dhcp_starve        # DHCP 고갈 (w11)
sudo python3 env/run.py dhcp_rogue         # 가짜 DHCP 서버 (w11)
sudo python3 env/run.py port_scan          # nmap 포트 스캔 (w11)
sudo python3 env/run.py port_scan_slow     # 느린 포트 스캔(회피) (w11)
sudo python3 env/run.py syn_flood          # SYN flood (w11)
sudo python3 env/run.py syn_flood_slow     # 저속 SYN flood(회피) (w11)
sudo python3 env/run.py mixed_attack       # 정상 트래픽에 섞은 공격(회피) (w12)
sudo python3 env/run.py mixed_arp_spoof   # 정상 트래픽에 섞은 느린 ARP 스푸핑(회피)
sudo python3 env/run.py mixed_syn_flood   # 정상 트래픽에 섞은 저속 SYN flood(회피)
sudo ./integration_test.sh --variants              # 속도·대상·포트 변형 29개 한 번에(VARIANTS)
sudo python3 env/run.py arp_spoof --no-pcap        # 캡처 생략(빠름)
sudo python3 env/run.py arp_spoof --controller remote  # OS-Ken 붙일 때(P4)

# 결과 검사
python3 common/records.py check data/runs/<run_id>
```

각 실험은 `워밍업 → 공격 → 쿨다운` 순서로 진행합니다(시간은 `scenarios.py`에서 조정).

## 데모·통합 테스트 (w12)

공격 재현부터 평가까지 한 번에 돌리는 스크립트를 저장소 루트에 뒀습니다
(`run.py`가 아니라 **repo 루트**에서 실행합니다).

```bash
# 저장소 루트(ComputerNetwork01)에서
sudo ./run_demo.sh arp_spoof                    # 실험→캡처→추출→규칙탐지→평가→형식검사
sudo ./run_demo.sh mixed_attack                 # 회피 시나리오도 동일하게
sudo ./run_demo.sh arp_spoof --controller=remote  # OS-Ken 자동 기동 후 실행 (osken-manager 필요)
sudo ./run_demo.sh mac_flood --no-model --quiet   # AI 추론 생략, 진행 메시지 생략

sudo ./integration_test.sh                      # 빠른 확인(arp_spoof, arp_spoof_slow)
sudo ./integration_test.sh --all                 # 전체 10개 시나리오
sudo ./integration_test.sh port_scan syn_flood   # 지정한 시나리오만
```

- `run_demo.sh`는 `model/rf.joblib`·`eval/report.py`가 있으면 자동으로 쓰고, 없으면 건너뜁니다
  (P3/P5 모듈이 아직 머지되지 않아도 그대로 동작).
- `integration_test.sh`는 파이프라인이 오류 없이 끝까지 돌고 기록 형식이 맞는지만 봅니다.
  회피 시나리오가 탐지되지 않는 것은 실패가 아닙니다(13주차 규칙 vs AI 비교의 연구 대상).

## 구성 파일

| 파일 | 내용 |
|---|---|
| `hosts.py` | **호스트 정의(단일 기준).** MAC·IP·포트를 여기만 고치면 토폴로지와 meta.json에 함께 반영됨 |
| `topo.py` | Mininet 토폴로지(스위치 1대 + 호스트 6대) |
| `scenarios.py` | 시나리오 정의(공격자, 대상, 속도, 회피 여부 → label에 반영) |
| `run.py` | 실험 실행기: 망 구성(DNS·DHCP 서버 포함) → meta.json → 캡처 → 정상 트래픽 → 공격 → labels.jsonl |
| `selfcheck.py` | 환경 점검(프로그램, ping, DNS, DHCP). 새로 세팅한 뒤 한 번 실행 |
| `traffic/normal.py` | 정상 트래픽(ping, web, DNS, video-UDP, file-TCP) |
| `attacks/arp_spoof.py` | ARP 스푸핑 (w07) |
| `attacks/mac_flood.py` | MAC 플러딩 (w07) |
| `attacks/dhcp_exhaust.py` | DHCP 고갈 (`dhcp_starve`, w11) |
| `attacks/dhcp_rogue.py` | 가짜 DHCP 서버 (w11) |
| `attacks/port_scan.py` | nmap/scapy 포트 스캔 (w11) |
| `attacks/syn_flood.py` | SYN flood (w11) |
| `attacks/mixed_attack.py` | 정상 트래픽에 섞은 공격(회피, w12) — 배경 트래픽 뒤에 다른 공격을 숨김 |
| `attacks/labguard.py` | 격리 환경 안전장치 |
| `../run_demo.sh` | 데모 실행기(w12): 실험→캡처→추출→탐지→평가→형식검사를 한 번에 |
| `../integration_test.sh` | 통합 테스트(w12): 여러 시나리오로 `run_demo.sh`를 돌려 파이프라인 확인 |

## 토폴로지

```
  h1(10.0.0.1)  h2(10.0.0.2)  h3(10.0.0.3)  h4(10.0.0.4, 공격자)
      │p1           │p2            │p3            │p4
      └─────────────┴──────[ s1 ]──┴─────────────┘
                           │p5          │p6
                      gw(10.0.0.254)  dhcp(10.0.0.253)
```

## 검증 상태 (2026-11-13, WSL2에서 실제 실행)

- ✅ (2026-11-17) **DHCP 서버**: `dhcp` 호스트에서 dnsmasq가 풀 `10.0.0.100~150`을 제공, gw를 기본 경로·DNS로 안내. `selfcheck.py`에서 OFFER 확인.
  호스트 고정 IP(.1~.4, .253, .254)와 풀이 겹치지 않음. 11주차 가짜 DHCP·DHCP 고갈 공격 대상.

- ✅ 6호스트 토폴로지가 run.py로 정상 구성됨(정상 트래픽 ping·HTTP 상호 통신 확인)
- ✅ `arp_spoof`: 캡처에 공격자(`...04`)와 게이트웨이(`...fe`)가 둘 다 `10.0.0.254`를
  주장하는 ARP 충돌이 찍힘 → 규칙 탐지기의 핵심 근거. meta/labels 형식 검사 통과
- ✅ `mac_flood`: 짧은 시간에 서로 다른 출발지 MAC 171개 관측 → `feat_seg` 신호
- ✅ 안전장치: Mininet 밖에서 공격 스크립트 직접 실행 시 거부(종료코드 3)

### w11 추가 (2026-11-17, WSL2에서 실제 실행)

- ✅ `dhcp_starve`: DHCPDISCOVER 전송 확인(캡처에 2,100개 — 스위치 브로드캐스트 플러딩으로
  한 전송당 여러 사본이 찍힘). `attack` 값은 data-format.md 기준 `dhcp_starve`
  (모듈 파일명은 `attacks/dhcp_exhaust.py`).
- ✅ `dhcp_rogue`: 처음엔 캡처에 DHCP 패킷이 0개였음 — 이 실습망 호스트는 정적 IP라
  실제 DHCPDISCOVER가 발생하지 않아 "스니핑 후 응답"만으로는 공격이 보이지 않았음.
  주기적 불특정 OFFER 브로드캐스트를 추가해 해결(수정 후 30개 OFFER, 출처 `10.0.0.4` 확인).
- ✅ `port_scan` / `port_scan_slow`: nmap SYN 스캔 정상 실행, labels 형식 검사 통과.
  `-T4`(기본)는 응답 없는 포트 재시도로 다소 오래 걸림 — 실제 소요는 `attack_dur`보다 짧게
  끝날 수 있음(스캔이 먼저 끝나면 조기 종료).
- ✅ `syn_flood` / `syn_flood_slow`: 가짜 출발지 IP로 SYN 전송, labels 형식 검사 통과.
- 🐛 **발견 및 수정**: 정상 트래픽에 `video`/`file`(iperf3) 종류를 추가했을 때, iperf3 TCP를
  대역폭 제한(`-b`) 없이 돌리자 Mininet 가상 링크에 대역폭 제한이 없어 45초 실행의
  캡처가 **약 5GB**로 폭주함. `-b 5M`(파일)/`-b 1M`(영상, UDP)로 제한해 9MB대로 정상화.
  **새 트래픽 종류를 추가할 때는 항상 속도 제한을 걸 것.**

### w12 추가 (2026-11-23, WSL2에서 실제 실행)

- ✅ `mixed_attack`: 공격자(h4)가 배경 트래픽(web/dns/video/file)을 보내는 동시에 느린
  `port_scan`을 끼워 넣음. labels/features 형식 검사 통과. 규칙 탐지기는 예상대로
  이 공격을 놓침(0/1) — 느린 단독 공격(`*_slow`)은 그래도 잡힘(예: `arp_spoof_slow` 6경보).
  13주차 규칙 vs AI 비교 자료로 쓸 것.
- ✅ `run_demo.sh`: `mac_flood`, `mixed_attack`으로 전체 파이프라인(실험→캡처→추출→
  규칙탐지→평가→형식검사) 끝까지 확인. `model/rf.joblib`·`eval/report.py`가 없을 때
  건너뛰는 분기도 확인.
- ✅ `integration_test.sh`: `mac_flood`+`arp_spoof_slow` 2개 시나리오로 통과 2/실패 0 확인.
- SDN 차단(P4)·대시보드 실시간 연결(P5)은 아직 main에 없어 `run_demo.sh`가 직접 확인하지
  못함. 두 모듈이 올라오면 `--controller=remote` 경로와 대시보드 안내를 그대로 이어 쓸 수 있음.

## 알려진 한계 (다음 주 보완)

- ✅ **정상 DNS 트래픽 캡처됨** (`dnsutils` 설치 후 확인, `*.lab.test` 질의·응답). ping·HTTP·DNS 혼합.
- **MAC 플러딩 실제 전송 속도는 설정값보다 낮음**(scapy 파이썬 루프 한계, ~수백 pps).
  CAM 테이블을 실제로 넘치게 하려면 `tcpreplay`/`sendpfast`로 교체 가능하나,
  *탐지*에는 "짧은 시간 내 다수의 새 MAC"만으로 충분함.
- 아직 P2(캡처→특징)·P4(규칙) 모듈과 연결 전. pcap은 만들어지므로 오프라인 입력으로 바로 쓸 수 있음.

## 시나리오 변형 (VARIANTS, 29개)

`scenarios.py`의 `_variant()`가 기본 시나리오에서 **속도·대상·포트·방식만** 바꿔 등록합니다.
공격 모듈과 label의 `attack` 종류는 그대로라서 data-format.md 변경이 없습니다.

| 공격 | 변형 |
|---|---|
| arp_spoof | `_mid`, `_fast`, `_gratuitous`, `_broadcast`(피해자 없음), `_h2`, `_h3`, `arp_spoof_slow_h2` |
| mac_flood | `_slow`(회피), `_mid`, `_fast` |
| dhcp_starve | `_slow`(회피), `_mid`, `_fast` |
| dhcp_rogue | `_slow`(OFFER 간격 10초, 회피), `_fast`(1초) |
| port_scan | `_narrow`(1-100), `_wide`(1-5000), `_h2`, `_h3`, `port_scan_slow_h2` |
| syn_flood | `_mid`, `_fast`, `_h2`, `_ssh`(22번 포트), `syn_flood_slow_h2` |
| 섞은 공격 | `mixed_attack_h2`, `mixed_attack_seed2`, `mixed_arp_spoof_h2`, `mixed_syn_flood_h2` |

공격자는 항상 h4입니다(hosts.py의 `attacker` 역할이 정답이므로 바꾸려면 hosts.py와 평가 기준을 함께 고쳐야 합니다).

