"""랜덤포레스트 기준 모델 학습·평가·저장 (P3).

    python3 model/train.py --all                 # data/runs 전체로 학습
    python3 model/train.py data/runs/<run_id> ...
    python3 model/train.py --all --exclude-run kitsune            # 실험망만
    python3 model/train.py --all --test-run kitsune --tag lab2kit  # 실험망 학습 → Kitsune 평가

분할(--split run, 기본): 시나리오마다 마지막 실험을 test로 씁니다. 같은 실험의
인접 창이 train/test에 섞이면 점수가 부풀려지기 때문입니다(capture/README).

출력:
  model/rf.joblib      학습된 모델 + 특징 이름 + 클래스
  model/metrics.json   평가 지표(정확도, 클래스별 precision/recall, 혼동행렬)

기준 모델이므로 목표는 "규칙과 비교할 출발점"입니다. 특징 중요도를 함께 출력해
어떤 특징이 판정을 주도하는지(예: arp_ip_conflicts) 확인합니다.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from model.dataset import FEATURES, all_runs, build  # noqa: E402


def main() -> None:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.model_selection import train_test_split
    import joblib

    p = argparse.ArgumentParser(description="RF 기준 모델 학습 (P3)")
    p.add_argument("run_dirs", nargs="*")
    p.add_argument("--all", action="store_true", help="data/runs 전체")
    p.add_argument("--split", choices=["run", "random"], default="run",
                   help="run: 시나리오마다 마지막 실험을 test로(기본, 인접 창 누수 없음). "
                        "random: 행 단위 랜덤 분할(점수가 부풀려질 수 있음)")
    p.add_argument("--test-run", action="append", default=[], metavar="TEXT",
                   help="실험 이름이나 출처(lab/kitsune)에 TEXT가 들어가면 test로 보냄 (여러 번 가능)")
    p.add_argument("--exclude-run", action="append", default=[], metavar="TEXT",
                   help="실험 이름이나 출처에 TEXT가 들어가면 아예 뺌 (여러 번 가능)")
    p.add_argument("--keep-ambiguous", action="store_true",
                   help="공격 구간과 조금만 겹친 경계 창(ambiguous=1)도 학습·평가에 넣음 "
                        "(기본은 뺌, capture/label.py 권장)")
    p.add_argument("--keep-no-evidence", action="store_true",
                   help="공격 라벨이지만 그 공격의 흔적(dataset.EVIDENCE)이 없는 창도 넣음 "
                        "(기본은 뺌: 배경 트래픽을 공격으로 배우는 라벨 잡음)")
    p.add_argument("--tag", default="",
                   help="결과 파일 이름 꼬리표: model/metrics_<tag>.json, model/rf_<tag>.joblib")
    p.add_argument("--test-size", type=float, default=0.3, help="--split random일 때만")
    p.add_argument("--seed", type=int, default=0)
    a = p.parse_args()

    runs = list(a.run_dirs) + (all_runs() if a.all else [])
    if not runs:
        sys.exit("학습할 실험 폴더가 없습니다. --all 또는 폴더를 지정하세요.")
    X, y, meta = build(runs)
    if not X:
        sys.exit("feat_host 기록이 없습니다. 먼저 capture/extract.py 실행.")

    def hit(m, texts):
        return any(t in m["run"] or t == m["source"] for t in texts)

    keep = [i for i, m in enumerate(meta) if not hit(m, a.exclude_run)
            and (a.keep_ambiguous or not m["ambiguous"])
            and (a.keep_no_evidence or m["evidence"])]
    print(f"[train] 경계 창 {sum(m['ambiguous'] for m in meta)}개",
          "포함" if a.keep_ambiguous else "제외",
          f"/ 흔적 없는 공격 창 {sum(not m['evidence'] for m in meta)}개",
          "포함" if a.keep_no_evidence else "제외")
    X = np.array(X, dtype=float)[keep]
    y = np.array(y)[keep]
    meta = [meta[i] for i in keep]
    classes, counts = np.unique(y, return_counts=True)
    print(f"[train] 표본 {len(y)}개, 클래스 분포:",
          {c: int(n) for c, n in zip(classes, counts)})
    if len(classes) < 2:
        sys.exit(f"클래스가 1개뿐({classes[0]})이라 학습 불가. 공격·정상 데이터가 모두 필요.")

    if a.split == "random":
        # 각 클래스 표본이 2개 이상이면 층화 분할
        stratify = y if min(counts) >= 2 else None
        idx_tr, idx_te = train_test_split(
            np.arange(len(y)), test_size=a.test_size, random_state=a.seed,
            stratify=stratify)
    else:
        idx_tr, idx_te, test_runs = run_split(meta, a.test_run)
        print("[split] test 실험:", ", ".join(test_runs))
    Xtr, Xte, ytr, yte = X[idx_tr], X[idx_te], y[idx_tr], y[idx_te]
    meta_te = [meta[i] for i in idx_te]
    print(f"[split] train {len(ytr)}행, test {len(yte)}행")

    clf = RandomForestClassifier(n_estimators=200, random_state=a.seed,
                                 class_weight="balanced", n_jobs=-1)
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)

    labels_sorted = sorted(classes.tolist())
    print("\n[평가] 테스트셋 분류 리포트")
    print(classification_report(yte, pred, labels=labels_sorted, zero_division=0))
    cm = confusion_matrix(yte, pred, labels=labels_sorted)
    print("혼동행렬 (행=정답, 열=예측):", labels_sorted)
    for name, row in zip(labels_sorted, cm):
        print(f"  {name:12s} {row.tolist()}")

    by_source = {}
    sources = sorted({m["source"] for m in meta_te})
    if len(sources) > 1:
        for src in sources:
            sel = np.array([m["source"] == src for m in meta_te])
            print(f"\n[평가] 출처={src} ({int(sel.sum())}행)")
            print(classification_report(yte[sel], pred[sel], labels=labels_sorted,
                                        zero_division=0))
            by_source[src] = classification_report(
                yte[sel], pred[sel], labels=labels_sorted, zero_division=0,
                output_dict=True)

    imp = sorted(zip(FEATURES, clf.feature_importances_),
                 key=lambda t: -t[1])[:8]
    print("\n[특징 중요도] 상위 8")
    for name, v in imp:
        print(f"  {name:22s} {v:.3f}")

    rep = classification_report(yte, pred, labels=labels_sorted,
                                zero_division=0, output_dict=True)
    metrics = {
        "samples": len(y), "classes": {c: int(n) for c, n in zip(classes, counts)},
        "split": a.split,
        "test_runs": sorted({m["run"] for m in meta_te}),
        "train_rows": int(len(ytr)), "test_rows": int(len(yte)),
        "report": rep, "report_by_source": by_source,
        "confusion_matrix": {"labels": labels_sorted, "matrix": cm.tolist()},
        "feature_importance": {k: float(v) for k, v in
                               zip(FEATURES, clf.feature_importances_)},
    }
    if a.split == "random":
        metrics["test_size"] = a.test_size
    sfx = f"_{a.tag}" if a.tag else ""
    (ROOT / "model" / f"metrics{sfx}.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    joblib.dump({"model": clf, "features": FEATURES,
                 "classes": clf.classes_.tolist()}, ROOT / "model" / f"rf{sfx}.joblib")
    print(f"\n[저장] model/rf{sfx}.joblib, model/metrics{sfx}.json")


def run_split(meta, force_test=()):
    """실험 단위 분할: 시나리오마다 실험 이름(시각순) 마지막 하나를 test로.

    force_test에 걸린 실험은 무조건 test로 가고, 나머지 실험으로 같은 규칙을
    적용합니다. 실험이 1개뿐인 시나리오는 train에 둡니다(test에 넣으면 학습에
    그 공격이 하나도 없게 되므로).
    """
    def forced(m):
        return any(t in m["run"] or t == m["source"] for t in force_test)

    by_scn = {}
    for m in meta:
        if not forced(m):
            by_scn.setdefault(m["scenario"], set()).add(m["run"])
    test_runs = {m["run"] for m in meta if forced(m)}
    for runs in by_scn.values():
        if len(runs) >= 2:
            test_runs.add(max(runs))
    idx_tr = [i for i, m in enumerate(meta) if m["run"] not in test_runs]
    idx_te = [i for i, m in enumerate(meta) if m["run"] in test_runs]
    return idx_tr, idx_te, sorted(test_runs)


if __name__ == "__main__":
    main()
