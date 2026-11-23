"""eval/report.py 단위 테스트 (Mininet 불필요, 표준 라이브러리만)."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from common.records import endpoint, make, write  # noqa: E402
import evaluate as _ev                            # noqa: E402
import report                                     # noqa: E402

T = 1763357400.0
ATK = endpoint("00:00:00:00:00:04", "10.0.0.4", "s1", 4)


# ── 테스트 픽스처 ─────────────────────────────────────────────────────────────

def _build_run(d: Path, labels, alerts, feats=(), actions=()):
    import json
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps({"v": 1, "run_id": d.name}),
                                 encoding="utf-8")
    for fname, recs in (("labels.jsonl", labels),
                        ("alerts_rule.jsonl", alerts),
                        ("features_1s.jsonl", feats),
                        ("actions.jsonl", actions)):
        with open(d / fname, "w", encoding="utf-8") as fh:
            for r in recs:
                write(fh, r)


def _label(attack="arp_spoof", start=T + 30, end=T + 60):
    return make("label", ts=end, attack_id="a01", attack=attack,
                start_ts=start, end_ts=end, attacker=ATK,
                target=None, evasive=False, params={})


def _alert(ts, attack="arp_spoof", detector="rule"):
    return make("alert", ts=ts, alert_id=f"{detector}-{int(ts)}", detector=detector,
                source="x", attack=attack, score=1.0, attacker=ATK, victim=None,
                feature_ts=ts, win=1, summary="", evidence={})


def _eval(labels, alerts, feats=()):
    with tempfile.TemporaryDirectory() as t:
        d = Path(t) / "20260101-000000-arp_spoof"
        _build_run(d, labels=labels, alerts=alerts, feats=feats)
        return _ev.evaluate_run(d)


# ── aggregate() 테스트 ────────────────────────────────────────────────────────

class TestAggregate(unittest.TestCase):
    def test_attack_key_from_first_attack(self):
        r = _eval([_label()], [_alert(T + 45)])
        agg = report.aggregate([r])
        self.assertIn("arp_spoof", agg)

    def test_normal_key(self):
        r = _eval([], [])  # 라벨 없음 → 정상 실험
        agg = report.aggregate([r])
        self.assertIn("(normal)", agg)

    def test_multi_run_accumulation(self):
        r1 = _eval([_label()], [_alert(T + 45)])
        r2 = _eval([_label()], [_alert(T + 50)])
        agg = report.aggregate([r1, r2])
        g = agg["arp_spoof"]["rule"]
        self.assertEqual(g["attacks"], 2)
        self.assertEqual(g["detected"], 2)
        self.assertEqual(len(g["det_times"]), 2)

    def test_no_alerts_zero_detected(self):
        r = _eval([_label()], [])
        agg = report.aggregate([r])
        g = agg["arp_spoof"]["rule"]
        self.assertEqual(g["detected"], 0)
        self.assertEqual(g["attacks"], 1)
        self.assertEqual(g["det_times"], [])

    def test_multiple_detectors(self):
        rule_al = _alert(T + 45, detector="rule")
        ai_al = _alert(T + 46, detector="ai")
        # 직접 evaluate_run + aggregate
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "20260101-000000-arp_spoof"
            import json
            d.mkdir()
            (d / "meta.json").write_text(json.dumps({"v": 1, "run_id": d.name}),
                                         encoding="utf-8")
            with open(d / "labels.jsonl", "w", encoding="utf-8") as fh:
                write(fh, _label())
            with open(d / "alerts_rule.jsonl", "w", encoding="utf-8") as fh:
                write(fh, rule_al)
            with open(d / "alerts_ai.jsonl", "w", encoding="utf-8") as fh:
                write(fh, ai_al)
            r = _ev.evaluate_run(d)
        agg = report.aggregate([r])
        self.assertIn("rule", agg["arp_spoof"])
        self.assertIn("ai", agg["arp_spoof"])


# ── render_summary_md() 테스트 ────────────────────────────────────────────────

class TestSummaryMd(unittest.TestCase):
    def _run_md(self, labels, alerts):
        r = _eval(labels, alerts)
        agg = report.aggregate([r])
        return report.render_summary_md([r], agg, "w11")

    def test_contains_attack_header(self):
        md = self._run_md([_label()], [_alert(T + 45)])
        self.assertIn("arp_spoof", md)

    def test_no_attack_shows_normal(self):
        md = self._run_md([], [])
        self.assertIn("(normal)", md)

    def test_detection_rate_in_table(self):
        md = self._run_md([_label()], [_alert(T + 45)])
        self.assertIn("1/1", md)

    def test_zero_detection(self):
        md = self._run_md([_label()], [])
        self.assertIn("0/1", md)


# ── render_html() 테스트 ─────────────────────────────────────────────────────

class TestRenderHtml(unittest.TestCase):
    def _make_html(self, labels, alerts):
        r = _eval(labels, alerts)
        raw = {"labels": labels, "alerts": alerts, "meta": {}}
        raw_map = {r["run"]: raw}
        agg = report.aggregate([r])
        pngs = {"rate": "", "time": "", "fp": ""}
        return report.render_html([r], raw_map, agg, "w11", pngs)

    def test_html_structure(self):
        html = self._make_html([_label()], [_alert(T + 45)])
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("<title>w11 실험 보고서</title>", html)

    def test_badge_pass(self):
        html = self._make_html([_label()], [_alert(T + 45)])
        self.assertIn("badge-pass", html)

    def test_badge_fail(self):
        html = self._make_html([_label()], [])
        self.assertIn("badge-fail", html)

    def test_no_external_links(self):
        html = self._make_html([_label()], [])
        self.assertNotIn("cdn.", html)
        self.assertNotIn("https://", html)

    def test_normal_run_badge(self):
        html = self._make_html([], [])
        self.assertIn("badge-normal", html)


# ── _timeline_svg() 테스트 ────────────────────────────────────────────────────

class TestTimelineSvg(unittest.TestCase):
    def test_empty_labels(self):
        svg = report._timeline_svg([], [])
        self.assertIn("정상 구간", svg)

    def test_with_label(self):
        lab = _label()
        svg = report._timeline_svg([lab], [])
        self.assertIn("<rect", svg)
        self.assertIn("arp_spoof", svg)

    def test_with_alert(self):
        lab = _label()
        al = _alert(T + 45)
        svg = report._timeline_svg([lab], [al])
        self.assertIn("<circle", svg)
        self.assertIn("<line", svg)


# ── _dets_in() 테스트 ─────────────────────────────────────────────────────────

class TestDetsIn(unittest.TestCase):
    def test_order(self):
        agg = {
            "arp_spoof": {"ai": {}, "rule": {}, "hybrid": {}}
        }
        dets = report._dets_in(agg, ["arp_spoof"])
        self.assertEqual(dets, ["rule", "ai", "hybrid"])

    def test_unknown_detector_appended(self):
        agg = {"arp_spoof": {"custom": {}, "rule": {}}}
        dets = report._dets_in(agg, ["arp_spoof"])
        self.assertEqual(dets[0], "rule")
        self.assertIn("custom", dets)


if __name__ == "__main__":
    unittest.main()
