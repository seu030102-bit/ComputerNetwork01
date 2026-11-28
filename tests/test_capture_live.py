"""capture/follow.py, capture/features.py, capture/live.py(RuleBridge) 검증.

follow·RuleBridge 테스트는 표준 라이브러리만 씁니다(Windows에서도 실행).
FeatureAggregator 테스트는 scapy가 있을 때만 돕니다(WSL/Ubuntu).
"""

import json
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from capture.follow import follow, follow_many  # noqa: E402
from common.records import endpoint, make, validate  # noqa: E402

try:
    import scapy.all  # noqa: F401
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False

T = 1763357400.0
ATK = endpoint("00:00:00:00:00:04", "10.0.0.4", "s1", 4)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestFollow(Base):
    def test_reads_existing_lines(self):
        f = self.tmp / "a.jsonl"
        f.write_text('{"n":1}\n{"n":2}\n', encoding="utf-8")
        got = [r["n"] for r in follow(f, idle_timeout=0.2, poll=0.02)]
        self.assertEqual(got, [1, 2])

    def test_partial_line_waits_for_newline(self):
        f = self.tmp / "a.jsonl"
        f.write_text('{"n":1}\n{"n":', encoding="utf-8")

        def finish():
            time.sleep(0.15)
            with open(f, "a", encoding="utf-8") as fh:
                fh.write('2}\n')
        threading.Thread(target=finish).start()
        got = [r["n"] for r in follow(f, idle_timeout=0.4, poll=0.02)]
        self.assertEqual(got, [1, 2])

    def test_waits_for_missing_file(self):
        f = self.tmp / "later.jsonl"

        def create():
            time.sleep(0.1)
            f.write_text('{"n":7}\n', encoding="utf-8")
        threading.Thread(target=create).start()
        self.assertEqual([r["n"] for r in follow(f, idle_timeout=0.4, poll=0.02)], [7])

    def test_truncate_restarts(self):
        f = self.tmp / "a.jsonl"
        f.write_text('{"n":1}\n{"n":2}\n', encoding="utf-8")
        it = follow(f, idle_timeout=0.4, poll=0.02)
        self.assertEqual([next(it)["n"], next(it)["n"]], [1, 2])
        f.write_text('{"n":3}\n', encoding="utf-8")   # 비우고 새로 씀
        self.assertEqual([r["n"] for r in it], [3])

    def test_new_only_and_bad_json(self):
        f = self.tmp / "a.jsonl"
        f.write_text('{"n":1}\n', encoding="utf-8")
        it = follow(f, from_start=False, idle_timeout=0.3, poll=0.02)

        def append():
            time.sleep(0.05)
            with open(f, "a", encoding="utf-8") as fh:
                fh.write('not json\n{"n":2}\n')
        threading.Thread(target=append).start()
        self.assertEqual([r["n"] for r in it], [2])

    def test_many_files_and_stop(self):
        a, b = self.tmp / "a.jsonl", self.tmp / "b.jsonl"
        a.write_text('{"f":"a"}\n', encoding="utf-8")
        b.write_text('{"f":"b"}\n', encoding="utf-8")
        got = [r["f"] for r in follow_many([a, b], poll=0.02, stop=lambda: True)]
        self.assertEqual(sorted(got), ["a", "b"])


class TestRuleBridge(Base):
    def test_alert_written_to_run_and_inbox(self):
        from capture.live import RuleBridge
        inbox = self.tmp / "sdn" / "inbox.jsonl"
        bridge = RuleBridge(self.tmp, inbox)
        feat = make("feat_host", ts=T, win=1, host=ATK, pkts=3, arp_rep=3,
                    arp_ip_claims=1, arp_ip_conflicts=1)
        before = time.time()
        bridge.feed(feat)
        bridge.feed(make("feat_host", ts=T + 1, win=1, host=ATK, pkts=1))  # 정상 → 경보 없음
        bridge.close()
        alerts = [json.loads(l) for l in open(self.tmp / "alerts_rule.jsonl", encoding="utf-8")]
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual((a["attack"], a["attacker"]["mac"]), ("arp_spoof", ATK["mac"]))
        self.assertGreaterEqual(a["ts"], before)          # 실시간: 판정 시각
        self.assertEqual(a["feature_ts"], T)              # 근거 창은 그대로
        self.assertEqual(validate(a), [])
        self.assertEqual(inbox.read_text(encoding="utf-8").count("\n"), 1)


@unittest.skipUnless(HAVE_SCAPY, "scapy 없음 (WSL/Ubuntu에서 실행)")
class TestAggregator(unittest.TestCase):
    def setUp(self):
        from capture.features import FeatureAggregator, hosts_from_env
        self.agg = FeatureAggregator(*hosts_from_env())

    def pkt(self, ts, src, psrc, pdst, op=2, hwsrc=None):
        from scapy.all import ARP, Ether
        p = Ether(src=src, dst="ff:ff:ff:ff:ff:ff") / ARP(op=op, psrc=psrc, pdst=pdst,
                                                          hwsrc=hwsrc or src)
        p.time = ts
        return p

    def test_conflict_and_windows(self):
        gw = "00:00:00:00:00:fe"
        self.agg.add(self.pkt(T, gw, "10.0.0.254", "10.0.0.254"))           # 진짜 gw 학습
        self.agg.add(self.pkt(T + 1.2, ATK["mac"], "10.0.0.254", "10.0.0.1"))  # 사칭
        out = self.agg.flush(T + 1.5)          # 1초 창 [T, T+1] 만 끝남
        hosts1, _ = out[1]
        self.assertEqual([r["host"]["mac"] for r in hosts1], [gw])
        self.assertEqual(out[5], ([], []))     # 5초 창은 아직
        out = self.agg.flush(None)
        atk = [r for r in out[1][0] if r["host"]["mac"] == ATK["mac"]][0]
        self.assertEqual((atk["arp_ip_conflicts"], atk["host"]["port"]), (1, 4))
        five = [r for r in out[5][0] if r["host"]["mac"] == ATK["mac"]][0]
        self.assertEqual((five["ts"], five["arp_rep"]), (T + 5, 1))

    def test_late_packet_dropped(self):
        self.agg.add(self.pkt(T, ATK["mac"], "10.0.0.4", "10.0.0.1", op=1))
        self.agg.flush(T + 3)                  # 1초 창 0, 1 은 이미 내보냄
        self.agg.add(self.pkt(T + 0.5, ATK["mac"], "10.0.0.4", "10.0.0.1", op=1))
        self.assertEqual(self.agg.late, 1)

    def test_unknown_mac_goes_to_null_segment(self):
        self.agg.add(self.pkt(T, "02:aa:bb:cc:dd:01", "10.0.0.9", "10.0.0.1", op=1))
        segs = self.agg.flush(None)[1][1]
        self.assertEqual([(s["sw"], s["port"], s["new_src_macs"]) for s in segs],
                         [(None, None, 1)])


if __name__ == "__main__":
    unittest.main()
