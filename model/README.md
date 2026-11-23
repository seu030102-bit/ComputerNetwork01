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

학습 10,026행 / 평가 5,008행. 성능표상 모든 클래스의 정밀도·재현율 0.96~1.00.

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

실험망으로만 학습한 모델(`lab`)로 평가:

| 평가 | 결과 |
|---|---|
| 행 단위 (`lab2kit`) | arp_spoof 재현율 **0.47**, port_scan 재현율 **0.94**, 둘 다 정밀도 1.00 |
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
