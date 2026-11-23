"""주차별 실험 보고서 생성 (P5).

eval/evaluate.py 의 evaluate_run / classify_alert / _load / _in_attack 함수를 재사용합니다.
새로운 지표 계산은 하지 않고, 집계·시각화·HTML 렌더링만 담당합니다.

    python3 eval/report.py data/runs/*/ --week w11
    python3 eval/report.py data/runs/*/ --week w11 --out eval/results/w11

출력 폴더 eval/results/<week>/ :
    summary.md        공격별 탐지율 · 탐지 시간 · 정상 구간 오탐 표
    detect_rate.png   공격별 탐지율 막대 차트
    detect_time.png   공격별 탐지 시간 막대 차트
    false_pos.png     정상 구간 오탐 막대 차트
    report.html       실험 카드 보고서 (PNG base64 삽입, CDN 없음)
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from collections import defaultdict
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

import evaluate as _ev  # noqa: E402  — 계산 함수 재사용

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    _HAS_MPL = True
except ImportError:  # pragma: no cover
    _HAS_MPL = False

# ── 탐지기 순서 / 색상 ──────────────────────────────────────────────────────
_DET_ORDER = ["rule", "ai", "hybrid"]
_DET_COLOR = {"rule": "#4c8bbe", "ai": "#e37c3c", "hybrid": "#6ab187"}
_ATK_COLOR = {
    "arp_spoof": "#ef5350", "mac_flood": "#ff7043",
    "dhcp_starve": "#ffa726", "dhcp_rogue": "#ffca28",
    "syn_flood": "#ab47bc", "port_scan": "#42a5f5", "dns_spoof": "#26a69a",
}


# ══════════════════════════════════════════════════════════════════════════════
# 1. 데이터 로드 / 집계
# ══════════════════════════════════════════════════════════════════════════════

def _load_raw(run_dir: Path) -> dict:
    """타임라인 SVG 생성을 위한 raw 레코드 로드.

    evaluate_run()은 집계 결과만 반환하므로 별도로 불러옵니다.
    _ev._load / _ev._in_attack 등은 evaluate.py에서 재사용합니다.
    """
    labels = _ev._load(run_dir, "labels.jsonl")
    alerts: list = []
    for name in ("alerts.jsonl", "alerts_rule.jsonl", "alerts_ai.jsonl"):
        alerts += _ev._load(run_dir, name)
    meta_f = run_dir / "meta.json"
    meta = json.loads(meta_f.read_text(encoding="utf-8")) if meta_f.exists() else {}
    return {"labels": labels, "alerts": alerts, "meta": meta}


def aggregate(results: list[dict]) -> dict:
    """evaluate_run() 결과 목록을 공격 종류 × 탐지기로 집계.

    반환 형식:
        { attack_key: { detector: {detected, attacks, det_times, fp_normals, resp_times} } }
    정상 실험은 "(normal)" 키로 묶습니다.
    """
    agg: dict = defaultdict(lambda: defaultdict(lambda: {
        "detected": 0, "attacks": 0,
        "det_times": [], "resp_times": [], "fp_normals": [],
    }))
    for r in results:
        atk_key = r["attacks"][0] if r["attacks"] else "(normal)"
        for det, m in r["per_det"].items():
            g = agg[atk_key][det]
            g["detected"] += m["detected"]
            g["attacks"] += m["attacks"]
            if m["det_time"] is not None:
                g["det_times"].append(m["det_time"])
            if m["resp_time"] is not None:
                g["resp_times"].append(m["resp_time"])
            g["fp_normals"].append(m["fp_normal"])
    return dict(agg)


def _dets_in(agg: dict, keys: list[str]) -> list[str]:
    """agg 안에 등장하는 탐지기를 _DET_ORDER 순으로 반환."""
    seen = {d for k in keys for d in agg.get(k, {})}
    ordered = [d for d in _DET_ORDER if d in seen]
    ordered += [d for d in sorted(seen) if d not in _DET_ORDER]
    return ordered


# ══════════════════════════════════════════════════════════════════════════════
# 2. 차트 (matplotlib)
# ══════════════════════════════════════════════════════════════════════════════

def _png_b64(fig) -> str:
    """matplotlib Figure → base64 PNG 문자열."""
    buf = BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()


def _grouped_bar(title: str, ylabel: str, categories: list[str],
                 det_vals: dict[str, list[float]],
                 fmt_pct: bool = False, placeholder: str = "") -> str:
    """탐지기별 그룹 막대 차트를 그려 base64 PNG로 반환.

    det_vals 가 비어 있거나 matplotlib 가 없으면 빈 문자열을 반환합니다.
    """
    if not _HAS_MPL:
        return ""
    dets = [d for d in _DET_ORDER if d in det_vals] + \
           [d for d in det_vals if d not in _DET_ORDER]
    if not dets or not categories:
        return ""

    n_dets = len(dets)
    fig, ax = plt.subplots(figsize=(max(6, len(categories) * 1.5 + 1), 5))
    xs = list(range(len(categories)))
    width = 0.7 / n_dets

    for i, det in enumerate(dets):
        offset = (i - n_dets / 2 + 0.5) * width
        vals = det_vals[det]
        bars = ax.bar(
            [x + offset for x in xs], vals, width,
            label=det, color=_DET_COLOR.get(det, "#888"), alpha=0.88,
        )
        # 막대 위 값 표시
        for bar, v in zip(bars, vals):
            if v > 0:
                label_txt = f"{v:.0%}" if fmt_pct else f"{v:.1f}"
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                        label_txt, ha="center", va="bottom", fontsize=8)

    ax.set_xticks(xs)
    ax.set_xticklabels(categories, rotation=20, ha="right")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if n_dets > 1:
        ax.legend()
    if fmt_pct:
        ax.set_ylim(0, 1.25)
        ax.yaxis.set_major_formatter(
            plt.FuncFormatter(lambda v, _: f"{v:.0%}"))
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    return _png_b64(fig)


def make_detect_rate_png(agg: dict) -> str:
    """공격별 탐지율 막대 차트 → base64 PNG."""
    attacks = [a for a in agg if a != "(normal)"]
    dets = _dets_in(agg, attacks)
    if not attacks or not dets:
        return ""
    det_vals = {}
    for det in dets:
        vals = []
        for atk in attacks:
            g = agg[atk].get(det, {"detected": 0, "attacks": 0})
            vals.append(g["detected"] / g["attacks"] if g["attacks"] else 0.0)
        det_vals[det] = vals
    return _grouped_bar("Detection Rate by Attack", "Detection Rate",
                        attacks, det_vals, fmt_pct=True)


def make_detect_time_png(agg: dict) -> str:
    """공격별 평균 탐지 시간 막대 차트 → base64 PNG."""
    attacks = [a for a in agg if a != "(normal)"]
    dets = _dets_in(agg, attacks)
    if not attacks or not dets:
        return ""
    det_vals = {}
    for det in dets:
        vals = []
        for atk in attacks:
            g = agg[atk].get(det, {"det_times": []})
            dt = sum(g["det_times"]) / len(g["det_times"]) if g["det_times"] else 0.0
            vals.append(dt)
        det_vals[det] = vals
    return _grouped_bar("Detection Time by Attack", "Detection Time (s)",
                        attacks, det_vals)


def make_false_pos_png(agg: dict) -> str:
    """정상 구간 오탐 막대 차트 → base64 PNG."""
    cats = list(agg.keys())
    dets = _dets_in(agg, cats)
    if not cats or not dets:
        return ""
    det_vals = {}
    for det in dets:
        vals = [sum(agg[k].get(det, {"fp_normals": []})["fp_normals"]) for k in cats]
        det_vals[det] = vals
    return _grouped_bar("False Positives (Normal Region)", "FP Count",
                        cats, det_vals)


# ══════════════════════════════════════════════════════════════════════════════
# 3. SVG 타임라인
# ══════════════════════════════════════════════════════════════════════════════

def _timeline_svg(labels: list, alerts: list, w: int = 560, h: int = 64) -> str:
    """공격 구간과 경보 시점을 SVG 타임라인으로 렌더링합니다."""
    if not labels:
        return (f'<svg width="{w}" height="24" xmlns="http://www.w3.org/2000/svg">'
                '<rect width="100%" height="100%" fill="#f5f5f5" rx="4"/>'
                '<text x="12" y="16" font-size="11" fill="#9e9e9e">'
                '정상 구간 (공격 없음)</text></svg>')

    t0 = min(l["start_ts"] for l in labels)
    t1 = max(l["end_ts"] for l in labels)
    pad = max((t1 - t0) * 0.12, 4.0)
    tmin = t0 - pad
    tmax = t1 + pad * 2
    if alerts:
        tmax = max(tmax, max(a["ts"] for a in alerts) + pad)
    span = max(tmax - tmin, 1.0)

    mg = 12  # 좌우 여백

    def tx(ts: float) -> float:
        return mg + (ts - tmin) / span * (w - 2 * mg)

    out: list[str] = []
    # 배경 트랙
    out.append(f'<rect x="{mg}" y="28" width="{w - 2*mg}" height="8" '
               f'rx="4" fill="#e0e0e0"/>')

    # 공격 구간
    for lab in labels:
        x1 = tx(lab["start_ts"])
        x2 = tx(lab["end_ts"])
        bw = max(x2 - x1, 5.0)
        col = _ATK_COLOR.get(lab["attack"], "#bdbdbd")
        out.append(f'<rect x="{x1:.1f}" y="22" width="{bw:.1f}" height="20" '
                   f'rx="3" fill="{col}" opacity="0.75"/>')
        mx = x1 + bw / 2
        out.append(f'<text x="{mx:.1f}" y="14" text-anchor="middle" '
                   f'font-size="9" fill="#616161">{lab["attack"]}</text>')

    # 경보 마커
    det_mk_col = {"rule": "#1565c0", "ai": "#bf360c", "hybrid": "#1b5e20"}
    for a in alerts:
        x = tx(a["ts"])
        col = det_mk_col.get(a.get("detector", "rule"), "#333")
        out.append(f'<line x1="{x:.1f}" y1="6" x2="{x:.1f}" y2="56" '
                   f'stroke="{col}" stroke-width="1.5" stroke-dasharray="2,2" opacity="0.9"/>')
        out.append(f'<circle cx="{x:.1f}" cy="32" r="4" fill="{col}" opacity="0.9"/>')

    # 시간 레이블
    out.append(f'<text x="{mg}" y="{h}" font-size="9" fill="#bdbdbd">0s</text>')
    out.append(f'<text x="{w - mg}" y="{h}" font-size="9" fill="#bdbdbd" '
               f'text-anchor="end">+{span:.0f}s</text>')

    return (f'<svg width="{w}" height="{h}" xmlns="http://www.w3.org/2000/svg">'
            + "".join(out) + "</svg>")


# ══════════════════════════════════════════════════════════════════════════════
# 4. summary.md 렌더링
# ══════════════════════════════════════════════════════════════════════════════

def render_summary_md(results: list[dict], agg: dict, week: str) -> str:
    """summary.md 텍스트를 생성합니다."""
    lines = [
        f"# {week} 실험 보고서 요약\n",
        f"- 주차: {week}",
        f"- 실험 수: {len(results)}",
        f"- 맞은 경보 인정 여유(GRACE): {_ev.GRACE:.0f}초\n",
    ]

    # ── 공격별 탐지 성능 ──────────────────────────────────────────────────────
    attacks = [a for a in agg if a != "(normal)"]
    if attacks:
        dets = _dets_in(agg, attacks)
        lines.append("## 공격별 탐지 성능\n")
        lines.append("| 공격 | 탐지기 | 탐지율 | 평균 탐지 시간(s) | 평균 대응 시간(s) | 정상구간 오탐 |")
        lines.append("|------|--------|--------|-----------------|-----------------|-------------|")
        for atk in attacks:
            for det in dets:
                g = agg[atk].get(det, {"detected": 0, "attacks": 0,
                                       "det_times": [], "resp_times": [], "fp_normals": []})
                rate = (f"{g['detected']}/{g['attacks']}"
                        f" ({g['detected']/g['attacks']:.0%})"
                        if g["attacks"] else "-")
                dt = (f"{sum(g['det_times'])/len(g['det_times']):.2f}"
                      if g["det_times"] else "-")
                rt = (f"{sum(g['resp_times'])/len(g['resp_times']):.2f}"
                      if g["resp_times"] else "-")
                fp = sum(g["fp_normals"])
                lines.append(f"| {atk} | {det} | {rate} | {dt} | {rt} | {fp} |")
        lines.append("")

    # ── 정상 구간 오탐 요약 ───────────────────────────────────────────────────
    if "(normal)" in agg:
        norm_dets = _dets_in(agg, ["(normal)"])
        lines.append("## 정상 구간 오탐 요약\n")
        lines.append("| 탐지기 | 정상 실험 수 | 정상구간 오탐 총수 |")
        lines.append("|--------|------------|-----------------|")
        for det in norm_dets:
            g = agg["(normal)"][det]
            lines.append(f"| {det} | {len(g['fp_normals'])} | {sum(g['fp_normals'])} |")
        lines.append("")

    # ── 전체 실험별 한 줄 요약 ────────────────────────────────────────────────
    lines.append("## 실험별 결과\n")
    lines.append("| 실험 | 공격 | 탐지기 | 탐지 | TP | FP | 탐지시간(s) | 정상구간오탐 |")
    lines.append("|------|------|--------|------|----|----|------------|------------|")
    for r in results:
        atk_str = ",".join(r["attacks"]) or "(normal)"
        for det, m in r["per_det"].items():
            dt = f"{m['det_time']:.2f}" if m["det_time"] is not None else "-"
            det_s = f"{m['detected']}/{m['attacks']}"
            lines.append(f"| {r['run'][:20]} | {atk_str} | {det} | {det_s} | "
                         f"{m['tp']} | {m['fp']} | {dt} | {m['fp_normal']} |")

    return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════════════
# 5. report.html 렌더링
# ══════════════════════════════════════════════════════════════════════════════

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, sans-serif; background: #f4f6f8; color: #212121; padding: 20px; }
h1 { font-size: 1.6rem; margin-bottom: 4px; color: #1a237e; }
.subtitle { font-size: 0.85rem; color: #757575; margin-bottom: 24px; }
h2 { font-size: 1.1rem; color: #37474f; margin: 20px 0 10px; }
/* summary charts */
.charts { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 32px; }
.charts img { max-width: 100%; height: auto; border-radius: 8px;
              box-shadow: 0 1px 4px rgba(0,0,0,.12); background: #fff; padding: 8px; }
/* cards */
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(560px, 1fr)); gap: 16px; }
.card { background: #fff; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,.1);
        padding: 16px; }
.card-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.run-id { font-size: 0.82rem; font-family: monospace; color: #546e7a;
          background: #eceff1; padding: 2px 7px; border-radius: 4px; }
.atk-tag { font-size: 0.78rem; padding: 2px 8px; border-radius: 10px;
           background: #e3f2fd; color: #0d47a1; }
.badge { font-size: 0.75rem; font-weight: 700; padding: 2px 10px;
         border-radius: 10px; letter-spacing: .05em; }
.badge-pass { background: #e8f5e9; color: #2e7d32; }
.badge-fail { background: #ffebee; color: #b71c1c; }
.badge-normal { background: #f3e5f5; color: #6a1b9a; }
/* timeline */
.timeline { margin: 10px 0; overflow-x: auto; }
/* metrics table */
table.metrics { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.82rem; }
table.metrics th { background: #eceff1; color: #455a64;
                   padding: 5px 8px; text-align: left; }
table.metrics td { padding: 4px 8px; border-bottom: 1px solid #f0f0f0; }
table.metrics tr:last-child td { border-bottom: none; }
.det-rule { color: #1565c0; font-weight: 600; }
.det-ai   { color: #bf360c; font-weight: 600; }
.det-hybrid { color: #1b5e20; font-weight: 600; }
"""


def _det_cls(det: str) -> str:
    return f"det-{det}" if det in ("rule", "ai", "hybrid") else ""


def _badge(result: dict) -> str:
    if not result["attacks"]:
        return '<span class="badge badge-normal">NORMAL</span>'
    detected = any(m["detected"] > 0 for m in result["per_det"].values())
    if detected:
        return '<span class="badge badge-pass">PASS</span>'
    return '<span class="badge badge-fail">FAIL</span>'


def _metrics_table(per_det: dict) -> str:
    rows = ["<table class='metrics'>",
            "<tr><th>탐지기</th><th>탐지</th><th>TP</th><th>FP</th>"
            "<th>탐지 시간(s)</th><th>대응 시간(s)</th><th>공격자특정</th><th>정상구간오탐</th></tr>"]
    for det, m in per_det.items():
        det_s = f"{m['detected']}/{m['attacks']}"
        dt = f"{m['det_time']:.2f}" if m["det_time"] is not None else "—"
        rt = f"{m['resp_time']:.2f}" if m["resp_time"] is not None else "—"
        at = {True: "✔", False: "✘", None: "—"}[m["attributed"]]
        cls = _det_cls(det)
        rows.append(f"<tr><td class='{cls}'>{det}</td><td>{det_s}</td>"
                    f"<td>{m['tp']}</td><td>{m['fp']}</td>"
                    f"<td>{dt}</td><td>{rt}</td><td>{at}</td>"
                    f"<td>{m['fp_normal']}</td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def _img_tag(b64: str, alt: str) -> str:
    if not b64:
        return f'<p style="color:#9e9e9e;font-size:0.8rem">[{alt} — matplotlib 없음]</p>'
    return f'<img src="data:image/png;base64,{b64}" alt="{alt}" style="max-width:500px">'


def render_html(results: list[dict], raw_map: dict[str, dict],
                agg: dict, week: str, pngs: dict[str, str]) -> str:
    """report.html 텍스트를 생성합니다.

    pngs: {"rate": b64, "time": b64, "fp": b64}
    raw_map: run_id → _load_raw() 반환값 (labels, alerts, meta)
    """
    # ── 카드 HTML ─────────────────────────────────────────────────────────────
    cards_html: list[str] = []
    for r in results:
        raw = raw_map.get(r["run"], {"labels": [], "alerts": [], "meta": {}})
        svg = _timeline_svg(raw["labels"], raw["alerts"])
        atk_str = r["attacks"][0] if r["attacks"] else "(normal)"
        cards_html.append(
            f'<div class="card">'
            f'<div class="card-header">'
            f'<span class="run-id">{r["run"]}</span>'
            f'{_badge(r)}'
            f'<span class="atk-tag">{atk_str}</span>'
            f'</div>'
            f'<div class="timeline">{svg}</div>'
            f'{_metrics_table(r["per_det"])}'
            f'</div>'
        )

    # ── 전체 HTML 조립 ────────────────────────────────────────────────────────
    chart_imgs = "".join([
        _img_tag(pngs.get("rate", ""), "detect_rate"),
        _img_tag(pngs.get("time", ""), "detect_time"),
        _img_tag(pngs.get("fp", ""), "false_pos"),
    ])

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{week} 실험 보고서</title>
<style>{_CSS}</style>
</head>
<body>
<h1>{week} 실험 보고서</h1>
<p class="subtitle">실험 수: {len(results)} · GRACE: {_ev.GRACE:.0f}초</p>

<h2>전체 요약 차트</h2>
<div class="charts">{chart_imgs}</div>

<h2>실험별 결과</h2>
<div class="cards">{"".join(cards_html)}</div>
</body>
</html>
"""


# ══════════════════════════════════════════════════════════════════════════════
# 6. 파일 저장 헬퍼
# ══════════════════════════════════════════════════════════════════════════════

def _save_png(b64: str, path: Path) -> None:
    """base64 PNG를 파일로 저장합니다."""
    if not b64:
        return
    path.write_bytes(base64.b64decode(b64))


# ══════════════════════════════════════════════════════════════════════════════
# 7. main
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    p = argparse.ArgumentParser(description="주차별 실험 보고서 생성 (P5)")
    p.add_argument("run_dirs", nargs="*", help="실험 폴더 경로들")
    p.add_argument("--week", default="w00", help="주차 태그 (기본: w00)")
    p.add_argument("--out", help="출력 폴더 경로 (기본: eval/results/<week>)")
    args = p.parse_args()

    dirs = [Path(d) for d in args.run_dirs]
    dirs = [d for d in dirs if (d / "labels.jsonl").exists()]
    if not dirs:
        sys.exit("평가할 실험 폴더가 없습니다 (labels.jsonl 필요).")

    out_dir = Path(args.out) if args.out else ROOT / "eval" / "results" / args.week
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── 평가 (evaluate.py 함수 재사용) ────────────────────────────────────────
    results = []
    raw_map: dict[str, dict] = {}
    for d in dirs:
        try:
            r = _ev.evaluate_run(d)
        except Exception as exc:
            print(f"[report] 경고: {d.name} 평가 실패 — {exc}")
            continue
        results.append(r)
        raw_map[r["run"]] = _load_raw(d)

    if not results:
        sys.exit("유효한 실험 결과가 없습니다.")

    agg = aggregate(results)

    # ── 차트 생성 ─────────────────────────────────────────────────────────────
    pngs: dict[str, str] = {
        "rate": make_detect_rate_png(agg),
        "time": make_detect_time_png(agg),
        "fp":   make_false_pos_png(agg),
    }
    _save_png(pngs["rate"], out_dir / "detect_rate.png")
    _save_png(pngs["time"], out_dir / "detect_time.png")
    _save_png(pngs["fp"],   out_dir / "false_pos.png")

    # ── summary.md ────────────────────────────────────────────────────────────
    md = render_summary_md(results, agg, args.week)
    (out_dir / "summary.md").write_text(md, encoding="utf-8")

    # ── report.html ───────────────────────────────────────────────────────────
    html = render_html(results, raw_map, agg, args.week, pngs)
    (out_dir / "report.html").write_text(html, encoding="utf-8")

    print(f"[report] 출력 폴더: {out_dir}")
    print(f"[report]   summary.md   ({len(md):,}B)")
    for name in ("detect_rate.png", "detect_time.png", "false_pos.png"):
        f = out_dir / name
        size = f.stat().st_size if f.exists() else 0
        print(f"[report]   {name:<20} ({size:,}B)")
    print(f"[report]   report.html  ({len(html.encode()):,}B)")


if __name__ == "__main__":
    main()
