# model/ — AI 모델 (P3)

규칙과 **같은 특징**(`feat_host`)을 입력받아 공격을 판정하고, **같은 경보 형식**
(`alerts_ai.jsonl`, data-format 2.4)을 출력합니다. 그래서 `eval/`로 규칙 vs AI를
바로 비교할 수 있습니다.

## 사용

```bash
tar xzf datasets/w11_lab.tar.gz                        # 11주차 실험망 데이터 → data/runs/

# 학습 (기본: 실험 단위 분할, 경계 창·흔적 없는 공격 창 제외)
python3 model/train.py --all --exclude-run kitsune --tag lab     # 실험망만
python3 model/train.py --all --test-run kitsune --tag lab2kit    # 실험망 학습 → Kitsune 평가
python3 model/train.py --all --tag labkit                        # 실험망+Kitsune 학습

# 추론 → alerts_ai.jsonl, 비교
python3 model/infer.py data/runs/<run_id> --model model/rf_lab.joblib --threshold 0.5
python3 eval/evaluate.py data/runs/<run_id> ...
```

`--tag` 없이 돌리면 `model/rf.joblib`, `model/metrics.json`에 저장합니다(`infer.py` 기본값).
산출물(`rf*.joblib`, `metrics*.json`)은 재생성되므로 저장소에 올리지 않습니다(`.gitignore`).

### train.py 옵션

| 옵션 | 뜻 |
|---|---|
| `--split run` (기본) | 시나리오마다 마지막 실험을 test로. 같은 실험의 인접 창이 train/test에 섞이면 점수가 부풀려짐 |
| `--split random` | 예전 방식(행 단위 랜덤 분할). 비교용 |
| `--test-run TEXT` | 실험 이름이나 출처(`lab`/`kitsune`)에 TEXT가 있으면 test로 |
| `--exclude-run TEXT` | 같은 조건으로 아예 뺌 |
| `--keep-ambiguous` | 경계 창(공격과 조금만 겹친 창)도 넣음 |
| `--keep-no-evidence` | 흔적 없는 공격 창도 넣음 |
| `--tag NAME` | 결과를 `rf_NAME.joblib`, `metrics_NAME.json`으로 저장 |

test에 실험망과 Kitsune가 함께 있으면 출처별 성능표도 따로 출력합니다.

## 구성

| 파일 | 내용 |
|---|---|
| `dataset.py` | 실험 폴더들의 `feat_host`에 라벨을 붙여 (X, y) 생성 |
| `train.py` | 랜덤포레스트 학습·평가(혼동행렬·특징중요도)·저장 |
| `infer.py` | 학습된 모델로 경보 생성 |
| `kitsune_import.py` | Kitsune ARP MitM pcap → 실험 폴더(meta.json, labels.jsonl) 변환 |

## 라벨링

**P2의 `capture/label.py` 규칙을 그대로 호출**합니다. 그래서 `data/dataset/host_*.csv`의
`label`과 행 단위로 같습니다(11주차 데이터 15,197행 전부 일치 확인).

- 창 `[ts - win, ts]`와 공격 구간의 겹친 비율이 0.5 이상이면 그 공격, 아니면 normal.
  분모는 창 길이와 공격 길이 중 짧은 쪽이라 0.3초짜리 포트 스캔도 라벨됩니다.
- 해당 행: `host.mac == 공격자 MAC`, 또는 meta에 없는 MAC(가짜 MAC)이고 공격이
  `mac_flood`/`dhcp_starve`인 경우.
- 0 < 겹친 비율 < 0.5 인 **경계 창**은 학습·평가에서 기본 제외.

학습에서는 여기에 하나를 더 뺍니다(라벨은 바꾸지 않음).

- **흔적 없는 공격 창**: 공격 구간과 겹쳐 공격 라벨이 붙었지만 그 공격의 흔적이 전혀 없는 창
  (`dataset.EVIDENCE`. 예: dhcp_rogue인데 OFFER/ACK 0개). 11주차 데이터에서 이런 창은
  모든 호스트가 보내는 배경 패킷(1초에 3개, 210바이트)뿐이었고, `class_weight="balanced"`
  때문에 이 3행이 같은 모양의 정상 148행을 이겨 **정상 실험에서 오탐 15개**를 냈습니다.
  제외 후 오탐 0개.

가짜 MAC 행에서 나온 경보는 공격자를 `mac: null`(미지정)으로 적습니다. 가짜 MAC을 공격자로
적으면 `eval`이 '공격자 오지정'(FP)으로 셉니다. 규칙 탐지기와 같은 방식입니다.

## 결과 (2026-11-23, 11주차 실험망 21개 + Kitsune 3개)

### 실험망 (`--tag lab`: 실험 14개로 학습, 시나리오별 마지막 실험 7개로 평가)

학습 10,026행 / 평가 5,008행. 아래 수치는 `python3 model/train.py --all --exclude-run kitsune --tag lab`로
다시 만들 수 있습니다(`model/metrics_lab.json`).

**혼동행렬** (행 단위, 행 = 정답, 열 = 예측, 대각선 = 맞힘)

| 정답 \ 예측 | arp_spoof | dhcp_rogue | dhcp_starve | mac_flood | normal | port_scan | syn_flood |
|---|---|---|---|---|---|---|---|
| arp_spoof | **35** | 0 | 0 | 0 | 0 | 0 | 0 |
| dhcp_rogue | 0 | **17** | 0 | 0 | 0 | 0 | 0 |
| dhcp_starve | 0 | 0 | **564** | 0 | 0 | 0 | 0 |
| mac_flood | 0 | 0 | 0 | **680** | 4 | 0 | 0 |
| normal | 0 | 0 | 0 | 0 | **3,682** | 0 | 0 |
| port_scan | 0 | 0 | 0 | 0 | 0 | **2** | 0 |
| syn_flood | 0 | 0 | 0 | 0 | 1 | 0 | **23** |

**클래스별 탐지율(재현율)·정밀도**

| 클래스 | 평가 행 | 탐지율 (맞힌 공격 / 실제 공격) | 정밀도 (맞은 판정 / 그 클래스로 판정) |
|---|---|---|---|
| arp_spoof | 35 | 1.000 (35/35) | 1.000 |
| dhcp_rogue | 17 | 1.000 (17/17) | 1.000 |
| dhcp_starve | 564 | 1.000 (564/564) | 1.000 |
| mac_flood | 684 | 0.994 (680/684) | 1.000 |
| port_scan | 2 | 1.000 (2/2) | 1.000 |
| syn_flood | 24 | 0.958 (23/24) | 1.000 |
| normal | 3,682 | – | 0.999 (공격 5행을 정상으로 놓침) |

**오탐율** (정상을 공격으로 판정한 비율)

- 행 단위: 정상 3,682행 중 0행 → **0.0%**
- 경보 단위(아래 표): 정상 전용 실험 10분 동안 AI 경보 0개, 공격 실험들의 정상 구간에서도 0개

`eval/evaluate.py` 결과(경보 단위):

| 공격 | AI 탐지 | AI 오탐 | AI 탐지시간 | 규칙 탐지 | 규칙 탐지시간 |
|---|---|---|---|---|---|
| arp_spoof | 1/1 | 0 | 1.43초 | 1/1 | 1.43초 |
| mac_flood | 1/1 | 0 | 1.01초 | 1/1 | 2.01초 |
| dhcp_starve | 1/1 | 0 | 1.10초 | 경보 없음 | – |
| dhcp_rogue | 1/1 | 0 | 1.29초 | 경보 없음 | – |
| syn_flood | 1/1 | 0 | 1.23초 | 경보 없음 | – |
| port_scan | 1/1 | 0 | 0.22초 | 경보 없음 | – |
| 정상(10분) | – | 0 | – | – | – |

특징 중요도 상위: `tcp_syn` 0.15, `dhcp_offer` 0.11, `dhcp_discover` 0.11, `bytes` 0.11, `pkts` 0.09.

### Kitsune (실제 IoT/사무망)

Kitsune 9종 중 우리 탐지 대상과 맞는 3종의 pcap을 `kitsune_import.py --kind …` →
`capture/extract.py`로 우리 `feat_host` 형식으로 바꿨습니다(115개 특징 CSV는 쓰지 않음).
Kitsune의 패킷 라벨은 실제 공격과 어긋나서, 공격 구간은 pcap에서 확인한 공격자 패킷 시각으로
정했습니다(근거는 `kitsune_import.py`의 PROFILES 주석).

| Kitsune | 우리 실험 | 내용 | 행(공격) |
|---|---|---|---|
| ARP MitM | `20170809-…-arp_spoof` | 공격자 `00:0c:29:6a:6c:64`, IP 사칭 ARP 응답 46개, 450초 | 4,735 (115) |
| OS Scan | `20170807-…-port_scan` | 같은 공격자가 게이트웨이 포트 65,535개를 24.5초에 스캔 + OS 탐지 프로브 0.7초 | 11,359 (32) |
| SYN DoS | `20170225-…-normal` | **공격 SYN이 캡처에 없음**(피해자 SYN-ACK만 있음) → 공격 전 51분을 정상 데이터로 | 19,774 (0) |

실험망으로만 학습한 모델로 Kitsune 3개 실험만 평가(`--test-run kitsune --tag lab2kit`,
`metrics_lab2kit.json`의 `report_by_source.kitsune`):

**혼동행렬** (Kitsune 35,819행, 학습한 7개 클래스 중 나온 것만)

| 정답 \ 예측 | arp_spoof | mac_flood | normal | port_scan |
|---|---|---|---|---|
| arp_spoof | **54** | 0 | 61 | 0 |
| normal | 0 | 66 | **35,606** | 0 |
| port_scan | 0 | 0 | 2 | **30** |

| 클래스 | 평가 행 | 탐지율 | 정밀도 |
|---|---|---|---|
| arp_spoof | 115 | **0.470** (54/115) | 1.000 |
| port_scan | 32 | **0.938** (30/32) | 1.000 |
| normal | 35,672 | – | 0.998 |

- 행 단위 오탐율: 정상 35,672행 중 66행(전부 mac_flood로 판정) → **0.19%**
- 경보 단위: 같은 호스트의 연속 창은 10초에 한 번만 경보하므로 66행 → 경보 25개

| 평가 | 결과 |
|---|---|
| 경보: ARP MitM | AI 탐지시간 **46.6초**, 규칙 448.6초(마지막 사칭에서야 충돌 감지) |
| 경보: OS Scan | AI가 포트 스캔은 탐지(0.66초), OS 탐지 프로브(SYN 9개)는 놓침 → 1/2 |
| 경보: 실제 망 정상 51분 | **AI 오탐 25개**, 규칙 0개 |

- ARP 재현율이 낮은 이유: 실험망 공격은 ARP 응답을 계속 보내지만 Kitsune 공격자는 46번
  간헐적으로 보냈습니다. 실험망에서 배운 "응답 양" 기준이 맞지 않습니다.
- 실제 망 오탐 25개는 전부 **mac_flood**, 한 호스트(`00:0c:29:da:09:84`, 1초에 62바이트
  패킷 1개)에서 나왔습니다(확률 0.57). 실험망의 가짜 MAC 행도 "MAC 하나가 작은 패킷 1개"라
  호스트 특징만으로는 구분되지 않습니다. 규칙은 구간 단위(`feat_seg`의 새 MAC 수)로 봐서 오탐이
  없습니다.
- 임계치를 0.7로 올리면 실제 망 오탐은 0개가 되지만 ARP MitM 탐지시간도 448.6초로 늦어져
  규칙보다 빠른 이점이 사라집니다(실험망 7종 탐지는 그대로). 14주차 임계치 조정 과제로 둡니다.
- 실험망+Kitsune로 학습(`labkit`)해도 실험망 test 결과는 같습니다. 이 모델로 Kitsune를
  평가하면 학습에 쓴 데이터라 점수가 의미 없습니다(ARP 탐지 0.61초, 오탐 0은 참고용).

## 팀원 공유 사항 (P3 작업 중 알게 된 것)

모듈 담당자별로 알아 두면 좋은 내용입니다. 코드는 P3 폴더(`model/`)만 고쳤습니다.

### 전체

- **Kitsune 115개 특징 CSV는 쓰지 않기로 했습니다(A안 폐기, B안 채택).**
  CSV는 "패킷 1개 = 1행, AfterImage 115개 특징"이라 우리 `feat_host`(창 × 호스트, 20개)와 형식이
  다릅니다. ARP MitM CSV로 직접 학습해 보니 공격 "시기"를 외워 정상 재현율이 0.23에 그쳤습니다.
  그래서 pcap을 우리 `capture/extract.py`로 다시 처리했습니다. 이 때문에 README 10주차의
  "Kitsune 특징 추출기(AfterImage)와 특징을 맞춤"(P2) 작업은 **필요 없어졌습니다.**
- **Kitsune 9종 중 쓸 수 있는 것은 3종**(ARP MitM, OS Scan, SYN DoS)입니다. 나머지
  (Active Wiretap, SSDP Flood, SSL Renegotiation, Fuzzing, Video Injection, Mirai)는
  우리 탐지 대상이 아닙니다. MAC 플러딩·DHCP·DNS 공격은 Kitsune에 없어 실험망 데이터로만 학습합니다.
- **Kitsune의 패킷 라벨은 믿기 어렵습니다.** ARP MitM은 공격자가 나타나기 57초 전부터 '공격'이고
  위조 ARP 46개에는 '정상'이 붙어 있습니다. SYN DoS는 공격 SYN이 캡처에 없고 피해자 응답에
  라벨이 붙어 있습니다. Kitsune 수치를 인용할 때는 원본 라벨이 아닌 위 결과를 쓰세요.

### P2 (capture/)

- **Kitsune pcap은 패킷당 200바이트만 저장**되어 있어 `extract.py`의 `len(pkt)`로 센 `bytes`가
  작습니다. `pkt.wirelen`을 쓰면 해결됩니다(실험망 캡처는 값이 같음). 아래 "한계" 참고.
- **`label.py` 규칙은 흔적 없는 공격 창도 공격으로 라벨합니다.** 공격 구간과 겹치기만 하면
  배경 패킷 3개(210바이트)만 있는 창도 dhcp_rogue·dhcp_starve가 됩니다(11주차 데이터 14행,
  Kitsune ARP 46행). 이 행 때문에 AI가 정상 실험에서 오탐 15개를 냈습니다. P3는 라벨은 그대로 두고
  학습에서만 뺍니다(`dataset.EVIDENCE`). `host_*.csv`를 쓰는 다른 사람도 주의하세요.
- 예전 `model/dataset.py`는 자체 규칙이라 P2 CSV와 라벨이 달랐습니다(5초 창 port_scan 0개 등).
  지금은 `label.py`를 그대로 호출하므로 P2가 규칙을 고치면 자동으로 따라갑니다.

### P4 (rules/)

- 11주차 test 실험 7개에 `rules/detect.py`를 돌렸을 때 **dhcp_starve, dhcp_rogue, syn_flood,
  port_scan 실험에서 규칙 경보가 0개**였습니다(arp_spoof, mac_flood는 탐지). 11주차 규칙이
  아직 반영 전인지 확인이 필요합니다.
- Kitsune ARP MitM에서 규칙은 마지막 사칭 시점(448.6초)에야 충돌을 잡았습니다. IP-MAC 대응표를
  처음 본 쌍으로 학습하는 방식이라 사칭이 간헐적이면 늦습니다.

### P5 (eval/, dashboard/)

- `eval/evaluate.py`는 경보의 공격자 MAC이 라벨의 공격자와 다르면 FP로 셉니다. 플러딩류에서
  가짜 MAC을 공격자로 적은 AI 경보가 전부 FP(362개)로 잡혀서, `infer.py`는 이제 가짜 MAC 경보를
  `attacker.mac = null`(미지정)로 냅니다. 대시보드에서 AI 경보의 공격자가 비어 있을 수 있습니다.
- 비교표에 Kitsune 실험을 넣을 때는 **실험망으로만 학습한 모델(`rf_lab.joblib`)**로 추론하세요.
  Kitsune를 학습에 넣은 모델로 Kitsune를 평가하면 점수가 의미 없습니다.

### Kitsune 데이터 다시 만들기

`data/`와 pcap은 저장소에 없습니다. UCI "Kitsune Network Attack Dataset"에서 `ARP_MitM`,
`OS_Scan`, `SYN_DoS`의 pcap zip을 받은 뒤(Ubuntu, 저장소 루트):

```bash
mkdir -p ~/kitsune_work && cd ~/kitsune_work
unzip ARP_MitM_pcap.pcapng.zip; unzip OS_Scan_pcap.pcapng.zip; unzip SYN_DoS_pcap.pcap.zip
editcap -r SYN_DoS_pcap.pcap syn_normal.pcap 1-2682349      # 공격 전 정상 구간만
cd ~/ComputerNetwork01 && export PYTHONPATH=$PWD
python3 model/kitsune_import.py --kind arp_mitm       --pcap ~/kitsune_work/ARP_MitM_pcap.pcapng
python3 model/kitsune_import.py --kind os_scan        --pcap ~/kitsune_work/OS_Scan_pcap.pcapng
python3 model/kitsune_import.py --kind syn_dos_normal --pcap ~/kitsune_work/syn_normal.pcap
# 출력된 폴더마다 (3개 동시에 돌려도 됨, 각 5~10분)
python3 capture/extract.py data/runs/<run_id>
python3 common/records.py check data/runs/<run_id>
```

`editcap`, `capinfos`는 `sudo apt install wireshark-common`으로 설치합니다.

## 한계 / 다음 단계

- **평가 표본이 작음**: 실험망 test는 시나리오당 실험 1개. port_scan 2행, dhcp_rogue 17행이라
  1.00이라는 점수는 근거가 약합니다. Kitsune OS Scan(32행)이 port_scan을 보완하고,
  P2도 추가 수집 예정(datasets/README).
- **같은 토폴로지**: 실험망 데이터는 한 토폴로지에서 생성해 실제보다 쉬움. Kitsune(실제 망)에서
  ARP 재현율 0.47, 정상 51분 오탐 25개가 그 차이를 보여 줍니다.
- **호스트 단위 플러딩 판정의 한계**: 조용한 호스트(작은 패킷 1개)를 mac_flood로 오판.
  플러딩류는 규칙(`feat_seg`)에 맡기거나, "처음 본 MAC" 같은 특징 추가(P2와 협의) 검토.
- **syn_flood의 실제 망 데이터 없음**: Kitsune SYN DoS에는 공격 SYN이 캡처되지 않았습니다.
- **Kitsune의 `bytes`가 작게 계산됨**: Kitsune pcap 3개는 모두 패킷당 앞 200바이트만 저장된
  캡처입니다(패킷의 59~93%가 잘림). `capture/extract.py`(P2)는 저장된 길이 `len(pkt)`로
  `bytes`를 세므로 Kitsune 실험의 `bytes`(특징 중요도 4위, 0.11)는 실제보다 작습니다.
  패킷 수·ARP/SYN 개수 등 다른 특징은 영향 없습니다. 원래 길이 `pkt.wirelen`을 쓰면 해결되며
  (잘리지 않은 실험망 캡처는 값이 같음), P2와 협의 후 Kitsune 3개를 다시 추출해야 합니다.
- **경보 근거**: `infer.py`의 `top_features`는 모델이 중요하게 본 특징이 아니라 값이 큰 특징.
  13주차 SHAP 설명으로 바꿀 예정.
- **회피 공격 비교**: 13주차. "일반 공격은 규칙으로 충분, AI의 가치는 회피 공격에서"라는 논점을
  검증. Kitsune에서 AI가 규칙보다 400초 먼저 잡은 것이 첫 근거.
