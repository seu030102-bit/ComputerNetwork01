"""대시보드·알림이 쓰는 데이터 로딩 (P5, Streamlit 불필요).

실험 폴더에서 meta / labels / alerts(규칙·AI) / actions 를 읽어
대시보드와 디스코드 알림이 공통으로 쓰는 형태로 정리합니다.
Streamlit에 의존하지 않으므로 그대로 테스트할 수 있습니다.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.records import read  # noqa: E402

ALERT_FILES = ("alerts.jsonl", "alerts_rule.jsonl", "alerts_ai.jsonl")
ACTION_FILE = "actions.jsonl"
_LIVE_THRESHOLD = 60.0  # 최근 N초 내 파일 변경 시 "실험 진행 중"으로 판단


def _load(run_dir: Path, name: str) -> list:
    f = run_dir / name
    return list(read(f)) if f.exists() else []


def load_meta(run_dir: Path) -> dict:
    import json
    f = run_dir / "meta.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}


def load_alerts(run_dir: Path) -> list:
    """모든 탐지기의 경보를 시각순으로. 각 경보에 읽기 좋은 필드 보강."""
    alerts = []
    for name in ALERT_FILES:
        alerts += _load(run_dir, name)
    alerts.sort(key=lambda a: a["ts"])
    return alerts


def list_runs(base: Path | None = None) -> list:
    base = base or (ROOT / "data" / "runs")
    return sorted((d for d in base.glob("*/") if (d / "meta.json").exists()),
                  key=lambda d: d.name, reverse=True)


def summarize(run_dir: Path) -> dict:
    """한 실험의 요약: 경보 수, 탐지기별 집계, 공격 목록."""
    meta = load_meta(run_dir)
    labels = _load(run_dir, "labels.jsonl")
    alerts = load_alerts(run_dir)
    actions = _load(run_dir, "actions.jsonl")
    by_det: dict[str, int] = {}
    for a in alerts:
        by_det[a.get("detector", "rule")] = by_det.get(a.get("detector", "rule"), 0) + 1
    return {
        "run_id": run_dir.name,
        "scenario": meta.get("scenario", "-"),
        "attacks": [l["attack"] for l in labels],
        "n_alerts": len(alerts),
        "by_detector": by_det,
        "n_actions": len(actions),
        "hosts": meta.get("hosts", []),
    }


def alert_rows(run_dir: Path) -> list[dict]:
    """경보를 표에 바로 쓸 수 있는 행(dict)으로 변환."""
    rows = []
    for a in load_alerts(run_dir):
        atk = a.get("attacker") or {}
        rows.append({
            "시각": round(a["ts"], 2),
            "탐지기": a.get("detector", "rule"),
            "공격": a["attack"],
            "확신도": a.get("score"),
            "공격자MAC": atk.get("mac") or "-",
            "포트": atk.get("port"),
            "근거": a.get("summary", ""),
            "규칙/모델": a.get("source", ""),
        })
    return rows


def action_rows(run_dir: Path) -> list[dict]:
    """SDN 차단 기록을 표에 바로 쓸 수 있는 행(dict)으로 변환."""
    rows = []
    for a in _load(run_dir, ACTION_FILE):
        tgt = a.get("target") or {}
        rows.append({
            "시각": round(a["ts"], 2),
            "조치": a.get("action", "-"),
            "대상MAC": tgt.get("mac") or "-",
            "포트": tgt.get("port"),
            "경보ID": a.get("alert_id") or "-",
            "소요(ms)": a.get("install_ms"),
            "결과": "✅" if a.get("ok") else "❌",
            "근거": a.get("reason", ""),
        })
    return rows


def file_sizes(run_dir: Path) -> dict[str, int]:
    """경보·행동 파일의 현재 크기(바이트). 화면 갱신 필요 여부 판단에 씁니다."""
    result: dict[str, int] = {}
    for name in (*ALERT_FILES, ACTION_FILE):
        f = run_dir / name
        if f.exists():
            result[name] = f.stat().st_size
    return result


def is_live(run_dir: Path, threshold: float = _LIVE_THRESHOLD) -> bool:
    """최근 threshold 초 내에 경보·행동 파일이 변경됐으면 True (실험 진행 중)."""
    cutoff = time.time() - threshold
    for name in (*ALERT_FILES, ACTION_FILE):
        f = run_dir / name
        if f.exists() and f.stat().st_mtime > cutoff:
            return True
    return False
