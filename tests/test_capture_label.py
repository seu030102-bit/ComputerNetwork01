"""capture/label.py, capture/verify.py 검증 (scapy·Mininet 불필요)."""

import csv
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from capture import collect, label, verify  # noqa: E402
from common.records import endpoint, make, write  # noqa: E402

T = 1763357400.0
ATK = endpoint("00:00:00:00:00:04", "10.0.0.4", "s1", 4)
H1 = endpoint("00:00:00:00:00:01", "10.0.0.1", "s1", 1)
FAKE = endpoint("02:aa:bb:cc:dd:01", None, None, None)
HOSTS = [
    {"name": "h1", "role": "client", "mac": H1["mac"], "ip": "10.0.0.1", "sw": "s1", "port": 1},
    {"name": "h4", "role": "attacker", "mac": ATK["mac"], "ip": "10.0.0.4", "sw": "s1", "port": 4},
    {"name": "dhcp", "role": "dhcp_server", "mac": "00:00:00:00:00:fd", "ip": "10.0.0.253",
     "sw": "s1", "port": 6},
]


def lab(attack="arp_spoof", start=T + 10, end=T + 20, attacker=ATK, aid="a01", evasive=False):
    return make("label", ts=end, attack_id=aid, attack=attack, start_ts=start, end_ts=end,
                attacker=attacker, target=None, evasive=evasive, params={})


def host(ep, ts, win=1, **kw):
    return make("feat_host", ts=ts, win=win, host=ep, pkts=kw.pop("pkts", 1), **kw)


def seg(port, ts, win=1, **kw):
    sw = None if port is None else "s1"
    return make("feat_seg", ts=ts, win=win, sw=sw, port=port, pkts=kw.pop("pkts", 1), **kw)


class RunDir:
    """임시 실험 폴더 만들기."""

    def __init__(self, base: Path, name: str, scenario: str, attack: str,
                 labels, feats1, feats5=(), dur=40.0, evasive=False):
        self.path = base / name
        self.path.mkdir(parents=True)
        meta = {"v": 1, "run_id": name, "scenario": scenario, "start_ts": T,
                "end_ts": T + dur, "topology": "", "hosts": HOSTS,
                "dhcp_servers": ["00:00:00:00:00:fd"],
                "notes": f"attack={attack}, evasive={evasive}"}
        (self.path / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
        if labels is not None:
            with open(self.path / "labels.jsonl", "w", encoding="utf-8") as fh:
                for r in labels:
                    write(fh, r)
        for w, feats in ((1, feats1), (5, feats5)):
            if feats is None:
                continue
            with open(self.path / f"features_{w}s.jsonl", "w", encoding="utf-8") as fh:
                for r in feats:
                    write(fh, r)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestLabelRecord(unittest.TestCase):
    known = {h["mac"] for h in HOSTS}

    def test_attacker_window_inside(self):
        r = label.label_record(host(ATK, T + 15), [lab()], self.known)
        self.assertEqual((r["label"], r["overlap"], r["ambiguous"]), ("arp_spoof", 1.0, 0))

    def test_other_host_is_normal(self):
        r = label.label_record(host(H1, T + 15), [lab()], self.known)
        self.assertEqual(r["label"], "normal")

    def test_partial_overlap_5s(self):
        # 창 [T+7, T+12], 공격 T+10부터 → 겹침 2/5 = 0.4 → normal, 경계
        r = label.label_record(host(ATK, T + 12, win=5), [lab()], self.known)
        self.assertEqual((r["label"], r["ambiguous"]), ("normal", 1))
        # 창 [T+17, T+22] → 겹침 3/5 = 0.6 → 공격
        r = label.label_record(host(ATK, T + 22, win=5), [lab()], self.known)
        self.assertEqual((r["label"], r["ambiguous"]), ("arp_spoof", 0))

    def test_outside_is_normal(self):
        r = label.label_record(host(ATK, T + 30), [lab()], self.known)
        self.assertEqual((r["label"], r["overlap"]), ("normal", 0.0))

    def test_fake_mac_host_and_null_segment(self):
        labs = [lab("mac_flood")]
        self.assertEqual(label.label_record(host(FAKE, T + 15), labs, self.known)["label"],
                         "mac_flood")
        self.assertEqual(label.label_record(seg(None, T + 15), labs, self.known)["label"],
                         "mac_flood")
        # 가짜 MAC을 쓰지 않는 공격이면 null 구간은 normal
        self.assertEqual(label.label_record(seg(None, T + 15), [lab()], self.known)["label"],
                         "normal")

    def test_segment_attacker_port(self):
        labs = [lab("syn_flood")]
        self.assertEqual(label.label_record(seg(4, T + 15), labs, self.known)["label"],
                         "syn_flood")
        self.assertEqual(label.label_record(seg(1, T + 15), labs, self.known)["label"],
                         "normal")


class TestBuild(Base):
    def test_csv_written_with_rep(self):
        feats = [host(ATK, T + 15, arp_rep=2), host(H1, T + 15), seg(4, T + 15)]
        a = RunDir(self.tmp, "20261117-140000-arp_spoof", "arp_spoof", "arp_spoof",
                   [lab()], feats, [host(ATK, T + 15, win=5)]).path
        b = RunDir(self.tmp, "20261117-141000-arp_spoof", "arp_spoof", "arp_spoof",
                   [lab()], feats).path
        out = self.tmp / "ds"
        counts = label.build([b, a], out)
        self.assertEqual(counts["host_1s"]["arp_spoof"], 2)
        self.assertEqual(counts["host_1s"]["normal"], 2)
        with open(out / "host_1s.csv", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        reps = {r["run_id"]: r["rep"] for r in rows}
        self.assertEqual(reps, {a.name: "1", b.name: "2"})
        self.assertIn("arp_rep", rows[0])


class TestVerify(Base):
    def good_arp(self, name="r1"):
        feats = [host(H1, T + 5, arp_req=1)]
        feats += [host(ATK, T + 11 + i, arp_rep=2, arp_ip_claims=1, arp_ip_conflicts=1)
                  for i in range(9)]
        return RunDir(self.tmp, name, "arp_spoof", "arp_spoof", [lab()], feats).path

    def test_good_run_passes(self):
        r = verify.verify_run(self.good_arp())
        self.assertEqual(r.status, "통과", r.fails + r.warns)
        self.assertAlmostEqual(r.attack_sec, 10.0)

    def test_no_trace_fails(self):
        d = RunDir(self.tmp, "r", "arp_spoof", "arp_spoof", [lab()], [host(H1, T + 15)]).path
        self.assertIn("흔적이 없음", " ".join(verify.verify_run(d).fails))

    def test_wrong_attacker_fails(self):
        d = RunDir(self.tmp, "r", "arp_spoof", "arp_spoof", [lab(attacker=H1)],
                   [host(H1, T + 15, arp_rep=3)]).path
        self.assertIn("attacker 호스트가 아님", " ".join(verify.verify_run(d).fails))

    def test_attack_type_mismatch_fails(self):
        d = RunDir(self.tmp, "r", "syn_flood", "syn_flood", [lab()], None).path
        self.assertIn("시나리오 syn_flood", " ".join(verify.verify_run(d).fails))

    def test_missing_or_empty_labels_fail(self):
        d = RunDir(self.tmp, "r1", "arp_spoof", "arp_spoof", None, None).path
        self.assertIn("labels.jsonl 없음", " ".join(verify.verify_run(d).fails))
        d = RunDir(self.tmp, "r2", "arp_spoof", "arp_spoof", [], None).path
        self.assertIn("비어 있음", " ".join(verify.verify_run(d).fails))

    def test_out_of_range_and_duplicate(self):
        d = RunDir(self.tmp, "r", "arp_spoof", "arp_spoof",
                   [lab(end=T + 90), lab(aid="a01")], None).path
        msg = " ".join(verify.verify_run(d).fails)
        self.assertIn("실험 시작·끝 밖", msg)
        self.assertIn("중복", msg)

    def test_late_start_and_outside_trace_warn(self):
        feats = [host(ATK, T + 16 + i, arp_rep=2, arp_ip_conflicts=1) for i in range(4)]
        feats.append(host(ATK, T + 35, arp_rep=5))
        d = RunDir(self.tmp, "r", "arp_spoof", "arp_spoof", [lab()], feats).path
        warns = " ".join(verify.verify_run(d).warns)
        self.assertIn("늦게 시작", warns)
        self.assertIn("라벨 구간 밖", warns)

    def test_mac_flood_counts_segment(self):
        feats = [seg(None, T + 11 + i, new_src_macs=30, src_macs=30) for i in range(9)]
        d = RunDir(self.tmp, "r", "mac_flood", "mac_flood", [lab("mac_flood")], feats).path
        self.assertEqual(verify.verify_run(d).status, "통과")

    def test_weak_trace_threshold_depends_on_evasive(self):
        feats = [host(ATK, T + 11 + i, tcp_syn=1) for i in range(9)]
        d = RunDir(self.tmp, "r1", "syn_flood", "syn_flood", [lab("syn_flood")], feats).path
        self.assertIn("약함", " ".join(verify.verify_run(d).warns))
        d = RunDir(self.tmp, "r2", "syn_flood_slow", "syn_flood",
                   [lab("syn_flood", evasive=True)], feats).path
        self.assertNotIn("약함", " ".join(verify.verify_run(d).warns))

    def test_normal_run(self):
        d = RunDir(self.tmp, "n", "normal", "normal", [], [host(H1, T + 5)], dur=600).path
        r = verify.verify_run(d)
        self.assertEqual(r.status, "통과")
        d2 = RunDir(self.tmp, "n2", "normal", "normal", [lab()], None).path
        self.assertIn("정상 시나리오인데", " ".join(verify.verify_run(d2).fails))

    def test_normal_with_conflict_warns(self):
        d = RunDir(self.tmp, "n", "normal", "normal", [],
                   [host(H1, T + 5, arp_rep=1, arp_ip_conflicts=1)]).path
        self.assertIn("ARP 충돌", " ".join(verify.verify_run(d).warns))

    def test_summary_checklist(self):
        rs = [verify.verify_run(self.good_arp("a"))]
        rs.append(verify.verify_run(
            RunDir(self.tmp, "n", "normal", "normal", [], [host(H1, T + 5)], dur=1800).path))
        text, done = verify.summarize(rs, min_reps=1, normal_min=30)
        self.assertFalse(done)  # 다른 공격이 0회
        self.assertIn("✅ 정상 30분 이상", text)
        self.assertIn("❌ 공격별 반복 수집", text)


class TestCollectPlan(unittest.TestCase):
    def test_interleave_and_normal_chunks(self):
        p = collect.plan(["a", "b"], 2, normal_min=25, chunk_min=10, interleave=True)
        self.assertEqual([n for n, _ in p[:4]], ["a", "b", "a", "b"])
        self.assertEqual([d for _, d in p[4:]], [600, 600, 300])

    def test_no_normal(self):
        p = collect.plan(["a"], 3, normal_min=0, chunk_min=10, interleave=False)
        self.assertEqual(p, [("a", None)] * 3)


if __name__ == "__main__":
    unittest.main()
