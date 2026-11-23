"""model/dataset.py 라벨링 검증 (scikit-learn 불필요)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.records import endpoint, make  # noqa: E402
from model import dataset  # noqa: E402

T = 1763357400.0
ATK = endpoint("00:00:00:00:00:04", "10.0.0.4", "s1", 4)
H1 = endpoint("00:00:00:00:00:01", "10.0.0.1", "s1", 1)


def feat(mac_ep, ts, **kw):
    return make("feat_host", ts=ts, win=1, host=mac_ep, **kw)


def lab(attack="arp_spoof", attacker=ATK, start=T + 30, end=T + 60):
    return make("label", ts=end, attack_id="a01", attack=attack, start_ts=start,
                end_ts=end, attacker=attacker, target=None, evasive=False, params={})


class TestLabeling(unittest.TestCase):
    def test_attacker_in_window_is_attack(self):
        self.assertEqual(dataset.label_for(feat(ATK, T + 45), [lab()]), "arp_spoof")

    def test_other_host_in_window_is_normal(self):
        self.assertEqual(dataset.label_for(feat(H1, T + 45), [lab()]), "normal")

    def test_attacker_outside_window_is_normal(self):
        self.assertEqual(dataset.label_for(feat(ATK, T + 10), [lab()]), "normal")

    def test_fake_mac_row_is_flood(self):
        # P2 규칙: meta에 없는 MAC(가짜 MAC) 행은 mac_flood/dhcp_starve 공격
        fake = endpoint("de:ad:be:ef:00:01", None, None, None)
        known = {ATK["mac"], H1["mac"]}
        l = lab(attack="mac_flood")
        self.assertEqual(dataset.label_for(feat(fake, T + 45), [l], known), "mac_flood")
        self.assertEqual(dataset.label_for(feat(H1, T + 45), [l], known), "normal")

    def test_short_attack_inside_window_is_attack(self):
        # 0.3초 스캔이 5초 창 안에 다 들어오면 공격 (P2 label.py와 같은 기준)
        l = lab(attack="port_scan", start=T + 41.0, end=T + 41.3)
        rec = make("feat_host", ts=T + 43, win=5, host=ATK)
        self.assertEqual(dataset.label_for(rec, [l]), "port_scan")

    def test_boundary_window_is_ambiguous(self):
        # 창 [T+29.8, T+30.8] 중 공격과 겹친 0.8초 → 공격; [T+29.2, T+30.2] → 0.2 → 경계
        self.assertEqual(dataset.label_for(feat(ATK, T + 30.8), [lab()]), "arp_spoof")
        info = dataset.label_info(feat(ATK, T + 30.2), [lab()])
        self.assertEqual((info["label"], info["ambiguous"]), ("normal", 1))

    def test_no_labels_all_normal(self):
        self.assertEqual(dataset.label_for(feat(ATK, T + 45), []), "normal")

    def test_evidence(self):
        bg = feat(ATK, T + 45, pkts=3, bytes=210)
        self.assertFalse(dataset.has_evidence(bg, "dhcp_rogue"))
        self.assertTrue(dataset.has_evidence(feat(ATK, T + 45, dhcp_offer=1), "dhcp_rogue"))
        self.assertTrue(dataset.has_evidence(bg, "normal"))
        self.assertTrue(dataset.has_evidence(bg, "mac_flood"))

    def test_feature_vector_length_matches(self):
        rec = feat(ATK, T + 45, arp_ip_conflicts=1)
        vec = [float(rec.get(k, 0) or 0) for k in dataset.FEATURES]
        self.assertEqual(len(vec), len(dataset.FEATURES))
        self.assertEqual(vec[dataset.FEATURES.index("arp_ip_conflicts")], 1.0)


if __name__ == "__main__":
    unittest.main()
