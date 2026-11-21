"""특징 창(window)에 정답 라벨 붙이기 → 학습·평가용 CSV 데이터셋 (P2, 11주차).

여러 실험 폴더의 features_1s/5s.jsonl 과 labels.jsonl 을 합쳐,
창 하나(feat_host / feat_seg 한 줄)마다 정답(`label`)을 붙인 CSV를 만듭니다.

    python3 capture/label.py data/runs/*               # 지정한 실험들
    python3 capture/label.py --all                     # data/runs 전체
    python3 capture/label.py --all --out data/dataset  # 출력 폴더 (기본값)

결과 (data/dataset/):
    host_1s.csv  host_5s.csv   feat_host 창마다 한 줄 (출발지 MAC 기준)
    seg_1s.csv   seg_5s.csv    feat_seg 창마다 한 줄 (스위치 포트 기준)

라벨 규칙 (창 = [ts - win, ts]):
  1. 그 창과 겹치는 공격 label 중 **이 행에 해당하는 것**만 봄
     - feat_host: host.mac == label.attacker.mac
                  또는 meta에 없는 MAC(가짜 MAC)이고 공격이 가짜 MAC을 쓰는 종류
     - feat_seg : port == label.attacker.port
                  또는 port가 null(가짜 MAC 구간)이고 공격이 가짜 MAC을 쓰는 종류
  2. 겹친 비율(`overlap`, 0~1)이 0.5 이상이면 그 공격, 아니면 normal
  3. 0 < overlap < 0.5 인 창은 `ambiguous=1` (경계 창. 학습에서 빼거나 따로 다룸)

label.jsonl 이 없거나 비어 있는 실험(정상 시나리오)은 모든 창이 normal 입니다.
학습/테스트는 같은 실험이 양쪽에 섞이지 않게 `run_id`로 나누세요.

표준 라이브러리만 씁니다(scapy 불필요). Windows에서도 실행됩니다.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.records import _COUNTS_HOST, _COUNTS_SEG, read  # noqa: E402

# 가짜 출발지 MAC을 대량으로 만드는 공격 (meta에 없는 MAC·포트 null 구간이 공격 행)
FAKE_MAC_ATTACKS = {"mac_flood", "dhcp_starve"}
MIN_OVERLAP = 0.5

HOST_FEATURES = _COUNTS_HOST + ["top_dst_share"]
SEG_FEATURES = list(_COUNTS_SEG)

HOST_COLS = ["run_id", "scenario", "rep", "ts", "win", "mac", "ip", "sw", "port",
             "known_host", *HOST_FEATURES, "label", "overlap", "ambiguous",
             "evasive", "attack_id"]
SEG_COLS = ["run_id", "scenario", "rep", "ts", "win", "sw", "port",
            *SEG_FEATURES, "label", "overlap", "ambiguous", "evasive", "attack_id"]


# ---------------------------------------------------------------- 읽기 도우미

def load_meta(run_dir: Path) -> dict:
    return json.loads((run_dir / "meta.json").read_text(encoding="utf-8-sig"))


def load_labels(run_dir: Path) -> list[dict]:
    f = run_dir / "labels.jsonl"
    return list(read(f)) if f.exists() else []


def load_features(run_dir: Path, win: int) -> list[dict]:
    f = run_dir / f"features_{win}s.jsonl"
    return list(read(f)) if f.exists() else []


def scenario_attack(meta: dict) -> str:
    """meta의 시나리오가 어떤 공격인지 ("normal" 포함). run.py가 notes에 attack=을 남김."""
    notes = meta.get("notes") or ""
    for part in notes.replace(",", " ").split():
        if part.startswith("attack="):
            return part.split("=", 1)[1]
    return "normal" if meta.get("scenario") == "normal" else meta.get("scenario", "?")


def known_macs(meta: dict) -> set[str]:
    return {h["mac"] for h in meta.get("hosts", [])}


# ---------------------------------------------------------------- 라벨 계산

def _overlap(ts: float, win: int, lab: dict) -> float:
    lo, hi = max(ts - win, lab["start_ts"]), min(ts, lab["end_ts"])
    return max(0.0, hi - lo) / win


def _applies_host(rec: dict, lab: dict, known: set[str]) -> bool:
    mac = rec["host"]["mac"]
    if mac == lab["attacker"]["mac"]:
        return True
    return lab["attack"] in FAKE_MAC_ATTACKS and mac not in known


def _applies_seg(rec: dict, lab: dict) -> bool:
    port = rec.get("port")
    if port is None:
        return lab["attack"] in FAKE_MAC_ATTACKS
    atk = lab["attacker"]
    return port == atk.get("port") and rec.get("sw") == atk.get("sw")


def label_record(rec: dict, labels: list[dict], known: set[str]) -> dict:
    """창 하나의 라벨 정보: {label, overlap, ambiguous, evasive, attack_id}."""
    best, best_ov = None, 0.0
    for lab in labels:
        ok = (_applies_host(rec, lab, known) if rec["type"] == "feat_host"
              else _applies_seg(rec, lab))
        if not ok:
            continue
        ov = _overlap(rec["ts"], rec["win"], lab)
        if ov > best_ov:
            best, best_ov = lab, ov
    is_attack = best is not None and best_ov >= MIN_OVERLAP
    return {
        "label": best["attack"] if is_attack else "normal",
        "overlap": round(best_ov, 3),
        "ambiguous": int(0 < best_ov < MIN_OVERLAP),
        "evasive": int(bool(best and best.get("evasive"))),
        "attack_id": best["attack_id"] if best else "",
    }


def rows_for_run(run_dir: Path, rep: int = 0) -> dict[str, list[dict]]:
    """실험 하나 → {"host_1s": [...], "host_5s": [...], "seg_1s": [...], "seg_5s": [...]}."""
    meta = load_meta(run_dir)
    labels = load_labels(run_dir)
    known = known_macs(meta)
    base = {"run_id": meta.get("run_id", run_dir.name),
            "scenario": meta.get("scenario"), "rep": rep}
    out: dict[str, list[dict]] = {}
    for win in (1, 5):
        host_rows, seg_rows = [], []
        for rec in load_features(run_dir, win):
            if rec.get("type") not in ("feat_host", "feat_seg"):
                continue
            lab = label_record(rec, labels, known)
            row = {**base, "ts": rec["ts"], "win": rec["win"]}
            if rec["type"] == "feat_host":
                h = rec["host"]
                row.update(mac=h["mac"], ip=h["ip"], sw=h["sw"], port=h["port"],
                           known_host=int(h["mac"] in known))
                row.update({k: rec.get(k, 0) for k in HOST_FEATURES})
                host_rows.append({**row, **lab})
            else:
                row.update(sw=rec.get("sw"), port=rec.get("port"))
                row.update({k: rec.get(k, 0) for k in SEG_FEATURES})
                seg_rows.append({**row, **lab})
        out[f"host_{win}s"] = host_rows
        out[f"seg_{win}s"] = seg_rows
    return out


def find_runs(base: Path) -> list[Path]:
    return [d for d in sorted(base.glob("*/")) if (d / "meta.json").exists()]


def repetition_index(run_dirs: list[Path]) -> dict[Path, int]:
    """같은 시나리오 안에서 몇 번째 반복인지 (run_id 시각 순, 1부터)."""
    seen: Counter = Counter()
    rep = {}
    for d in sorted(run_dirs, key=lambda p: p.name):
        try:
            scn = load_meta(d).get("scenario")
        except Exception:
            scn = None
        seen[scn] += 1
        rep[d] = seen[scn]
    return rep


def build(run_dirs: list[Path], out_dir: Path) -> dict[str, Counter]:
    """CSV 4개를 쓰고 파일별 라벨 개수를 돌려줍니다."""
    out_dir.mkdir(parents=True, exist_ok=True)
    reps = repetition_index(run_dirs)
    files = {name: open(out_dir / f"{name}.csv", "w", newline="", encoding="utf-8")
             for name in ("host_1s", "host_5s", "seg_1s", "seg_5s")}
    writers = {name: csv.DictWriter(fh, fieldnames=HOST_COLS if name.startswith("host")
                                    else SEG_COLS)
               for name, fh in files.items()}
    for w in writers.values():
        w.writeheader()
    counts = {name: Counter() for name in files}
    skipped = []
    try:
        for d in run_dirs:
            if not (d / "features_1s.jsonl").exists():
                skipped.append(d.name)
                continue
            for name, rows in rows_for_run(d, reps.get(d, 0)).items():
                for r in rows:
                    writers[name].writerow(r)
                    counts[name][r["label"] if not r["ambiguous"] else "(경계)"] += 1
    finally:
        for fh in files.values():
            fh.close()
    if skipped:
        print(f"[label] 특징 파일이 없어 건너뜀 {len(skipped)}개: "
              + ", ".join(skipped[:5]) + (" ..." if len(skipped) > 5 else ""))
        print("        먼저 python3 capture/extract.py <폴더> 를 실행하세요.")
    return counts


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="특징 창에 라벨 붙이기 → CSV (P2)")
    p.add_argument("runs", nargs="*", help="실험 폴더들")
    p.add_argument("--all", action="store_true", help="--runs-dir 안의 실험 전체")
    p.add_argument("--runs-dir", default=str(ROOT / "data" / "runs"),
                   help="--all 이 볼 폴더 (기본 data/runs)")
    p.add_argument("--out", default=str(ROOT / "data" / "dataset"))
    a = p.parse_args()
    run_dirs = [Path(r) for r in a.runs]
    if a.all:
        run_dirs += find_runs(Path(a.runs_dir))
    if not run_dirs:
        p.error("실험 폴더를 주거나 --all 을 쓰세요")
    counts = build(run_dirs, Path(a.out))
    for name, c in counts.items():
        total = sum(c.values())
        detail = ", ".join(f"{k} {v}" for k, v in c.most_common())
        print(f"[label] {name}.csv  {total}행  ({detail})")
    print(f"[label] 저장 위치: {a.out}")


if __name__ == "__main__":
    main()
