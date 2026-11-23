"""실험 폴더들의 feat_host 기록 → 학습용 (X, y) 데이터셋 (P3).

라벨 붙이는 법: P2의 capture/label.py 규칙을 그대로 씁니다(label_record 호출).
  - 창 = [ts - win, ts]. 이 행에 해당하는 공격 구간과 겹친 비율(overlap)이 0.5 이상이면
    그 공격, 아니면 normal. 분모는 창 길이와 공격 길이 중 짧은 쪽(0.3초 스캔도 라벨됨).
  - 해당 여부: host.mac == 공격자 MAC, 또는 meta에 없는 MAC(가짜 MAC)이고 공격이
    mac_flood / dhcp_starve 인 경우.
  - 0 < overlap < 0.5 인 경계 창은 meta의 ambiguous=1 (train.py가 기본으로 뺌).
그래서 data/dataset/host_*.csv 의 label 열과 같은 결과가 나옵니다.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from capture.label import known_macs, label_record, load_meta  # noqa: E402
from common.records import read  # noqa: E402

# 학습에 쓰는 feat_host 숫자 특징 (신원/시각 제외)
FEATURES = [
    "win", "pkts", "bytes", "arp_req", "arp_rep", "arp_grat",
    "arp_rep_unsolicited", "arp_ip_claims", "arp_ip_conflicts",
    "dhcp_offer", "dhcp_ack", "dhcp_discover", "tcp_syn", "tcp_synack_in",
    "tcp_rst_in", "icmp_unreach_in", "dst_ips", "dst_ports",
    "top_dst_share", "dns_resp",
]

# 공격 라벨이 붙은 창에 그 공격의 흔적이 하나라도 있는지 보는 특징.
# 공격 구간과 겹치기만 하고 흔적이 없는 창(예: 배경 패킷 3개만 있는 창)은 라벨 잡음이라
# train.py가 기본으로 뺍니다. 라벨 자체는 P2 기준 그대로 둡니다.
EVIDENCE = {
    "arp_spoof": ("arp_rep", "arp_grat", "arp_req"),
    "dns_spoof": ("dns_resp",),
    "dhcp_rogue": ("dhcp_offer", "dhcp_ack"),
    "dhcp_starve": ("dhcp_discover",),
    "syn_flood": ("tcp_syn",),
    "port_scan": ("tcp_syn", "dst_ports"),
}


def has_evidence(rec: dict, label: str) -> bool:
    keys = EVIDENCE.get(label)
    return keys is None or any((rec.get(k) or 0) > 0 for k in keys)


def _labels(run_dir: Path) -> list:
    f = run_dir / "labels.jsonl"
    return list(read(f)) if f.exists() else []


def label_info(rec: dict, labels: list, known=frozenset()) -> dict:
    """P2 규칙의 라벨 정보 {label, overlap, ambiguous, evasive, attack_id}."""
    return label_record(rec, labels, set(known))


def label_for(rec: dict, labels: list, known=frozenset()) -> str:
    return label_info(rec, labels, known)["label"]


def run_info(run_dir: Path) -> dict:
    """meta.json에서 시나리오와 출처(lab / kitsune)를 읽습니다."""
    run_dir = Path(run_dir)
    scenario = run_dir.name.split("-", 2)[-1]
    source = "lab"
    if (run_dir / "meta.json").exists():
        m = load_meta(run_dir)
        scenario = m.get("scenario") or scenario
        if "source=kitsune" in (m.get("notes") or ""):
            source = "kitsune"
    return {"scenario": scenario, "source": source}


def rows_from_run(run_dir: Path):
    """(feature_dict, label_info, run_name) 들을 돌려줍니다."""
    labels = _labels(run_dir)
    meta_f = run_dir / "meta.json"
    known = known_macs(load_meta(run_dir)) if meta_f.exists() else set()
    out = []
    for w in (1, 5):
        f = run_dir / f"features_{w}s.jsonl"
        if not f.exists():
            continue
        for rec in read(f):
            if rec.get("type") != "feat_host":
                continue
            out.append((rec, label_info(rec, labels, known), run_dir.name))
    return out


def build(run_dirs):
    """여러 실험 폴더 → (X, y, meta). X는 리스트(행)×FEATURES 순서."""
    X, y, meta = [], [], []
    for d in run_dirs:
        d = Path(d)
        info = run_info(d)
        for rec, lab, run in rows_from_run(d):
            X.append([float(rec.get(k, 0) or 0) for k in FEATURES])
            y.append(lab["label"])
            meta.append({"run": run, "ts": rec["ts"], "mac": rec["host"]["mac"],
                         "win": rec["win"], "ambiguous": lab["ambiguous"],
                         "overlap": lab["overlap"],
                         "evidence": has_evidence(rec, lab["label"]), **info})
    return X, y, meta


def all_runs() -> list:
    base = ROOT / "data" / "runs"
    return [d for d in sorted(base.glob("*/"))
            if (d / "features_1s.jsonl").exists() or (d / "features_5s.jsonl").exists()]
