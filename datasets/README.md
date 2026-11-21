# datasets/ — 공유용 실험망 데이터 (P2)

`data/`는 용량 때문에 저장소에 올리지 않으므로, 팀원이 쓸 데이터를 여기에 압축해 둡니다.

## w11_lab.tar.gz (11주차, 2026-11-21 수집)

- 공격 6종(arp_spoof, mac_flood, dhcp_starve, dhcp_rogue, port_scan, syn_flood) × 3회 + 정상 10분 × 3회 = 실험 21개
- 라벨 검증 결과: [w11_verify.md](w11_verify.md) (실패 0, port_scan 3개는 경고: nmap 역방향 DNS 대기로 실제 스캔이 라벨보다 약 12초 늦게 시작)
- 원본 `capture.pcap`(421MB)은 빠져 있습니다. 필요하면 P2에게 요청하세요.

### 풀기 (저장소 루트에서)

```bash
tar xzf datasets/w11_lab.tar.gz        # → data/runs/<실험>/, data/dataset/
```

Windows PowerShell에서도 `tar xzf datasets\w11_lab.tar.gz`로 풀 수 있습니다.

### 들어 있는 것

| 경로 | 내용 | 쓰는 사람 |
|---|---|---|
| `data/runs/<run_id>/meta.json, labels.jsonl` | 실험 정보, 정답 구간 | 모두 |
| `data/runs/<run_id>/features_1s.jsonl, features_5s.jsonl` | 특징 (feat_host, feat_seg) | P4 `rules/detect.py`, P5 `eval/evaluate.py` |
| `data/dataset/host_{1s,5s}.csv, seg_{1s,5s}.csv` | 창마다 정답(`label`)을 붙인 학습용 표 | P3 |
| `data/dataset/verify.md` | 라벨 검증 결과 | |

CSV 열과 라벨 규칙은 [`capture/README.md`](../capture/README.md)의 "11주차" 절을 보세요.
학습/테스트는 같은 실험이 양쪽에 섞이지 않게 `run_id`(또는 `rep`)로 나눕니다.
