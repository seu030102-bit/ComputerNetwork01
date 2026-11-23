"""rules/detect.py 규칙 판정 검증 (Mininet 불필요, 표준 라이브러리만)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "rules"))

from common.records import endpoint, make, read, write  # noqa: E402
import detect  # noqa: E402

T = 1763357400.0
ATK = endpoint("00:00:00:00:00:04", "10.0.0.4", "s1", 4)
H1 = endpoint("00:00:00:00:00:01", "10.0.0.1", "s1", 1)
DHCP = endpoint("00:00:00:00:00:fd", "10.0.0.253", "s1", 6)
LEGIT = {DHCP["mac"]}


def host(ep=ATK, ts=T, win=1, **kw):
    return make("feat_host", ts=ts, win=win, host=ep, **kw)


def seg(ts=T, win=1, port=4, **kw):
    return make("feat_seg", ts=ts, win=win, sw="s1", port=port, **kw)


def host_attack(rec, legit=LEGIT):
    a = detect._host_alert(rec, legit, detect.Deduper())
    return a and a["attack"]


def seg_attack(rec):
    a = detect._seg_alert(rec, detect.Deduper())
    return a and a["attack"]


class TestHostRules(unittest.TestCase):
    def test_normal_peak_is_quiet(self):
        # w11 정상 구간의 최댓값 근처: 어떤 규칙에도 걸리면 안 됨
        self.assertIsNone(host_attack(host(dst_ports=24, tcp_syn=16, dst_ips=3)))

    def test_arp_conflict(self):
        self.assertEqual(host_attack(host(arp_ip_conflicts=1)), "arp_spoof")

    def test_arp_unsolicited_needs_5s_window(self):
        self.assertIsNone(host_attack(host(win=1, arp_rep_unsolicited=9)))
        self.assertEqual(host_attack(host(win=5, arp_rep_unsolicited=5)), "arp_spoof")

    def test_dhcp_rogue_from_unknown_server(self):
        self.assertEqual(host_attack(host(dhcp_offer=3)), "dhcp_rogue")

    def test_dhcp_offer_from_legit_server_is_quiet(self):
        self.assertIsNone(host_attack(host(ep=DHCP, dhcp_offer=6, dhcp_ack=6)))

    def test_port_scan(self):
        self.assertEqual(host_attack(host(dst_ports=1000, tcp_syn=2000)), "port_scan")

    def test_syn_flood_victim_is_not_scanner(self):
        # SYN flood 중 h1이 RST로 여러 포트에 응답하는 패턴(w11 실측)
        self.assertIsNone(host_attack(host(ep=H1, dst_ports=56, tcp_syn=6)))

    def test_syn_flood(self):
        self.assertEqual(host_attack(host(tcp_syn=30, dst_ports=1)), "syn_flood")

    def test_many_ports_is_scan_not_flood(self):
        self.assertEqual(host_attack(host(tcp_syn=30, dst_ports=100)), "port_scan")


class TestSegRules(unittest.TestCase):
    def test_mac_flood(self):
        self.assertEqual(seg_attack(seg(new_src_macs=20, src_macs=20)), "mac_flood")

    def test_dhcp_starve_by_discover(self):
        self.assertEqual(seg_attack(seg(dhcp_discover=20)), "dhcp_starve")

    def test_dhcp_starve_wins_over_mac_flood(self):
        # 가짜 chaddr DISCOVER는 새 MAC도 늘리므로 고갈로 판정해야 함
        rec = seg(dhcp_discover=27, dhcp_chaddrs=9, new_src_macs=20)
        self.assertEqual(seg_attack(rec), "dhcp_starve")

    def test_seg_rules_use_1s_window_only(self):
        self.assertIsNone(seg_attack(seg(win=5, new_src_macs=50, dhcp_discover=50)))

    def test_seg_alert_has_port_but_no_mac(self):
        a = detect._seg_alert(seg(new_src_macs=20), detect.Deduper())
        self.assertIsNone(a["attacker"]["mac"])
        self.assertEqual(a["attacker"]["port"], 4)


class TestDedup(unittest.TestCase):
    def test_same_attacker_within_10s_once(self):
        d = detect.Deduper()
        first = detect._host_alert(host(ts=T, arp_ip_conflicts=1), LEGIT, d)
        again = detect._host_alert(host(ts=T + 5, arp_ip_conflicts=1), LEGIT, d)
        later = detect._host_alert(host(ts=T + 11, arp_ip_conflicts=1), LEGIT, d)
        self.assertIsNotNone(first)
        self.assertIsNone(again)
        self.assertIsNotNone(later)


class TestDetectRun(unittest.TestCase):
    def test_reads_meta_dhcp_servers(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            (d / "meta.json").write_text(
                json.dumps({"v": 1, "dhcp_servers": [DHCP["mac"]]}), encoding="utf-8")
            with open(d / "features_1s.jsonl", "w", encoding="utf-8") as fh:
                write(fh, host(ep=DHCP, dhcp_offer=5))
                write(fh, host(ts=T + 1, dhcp_offer=5))
            detect.detect(d)
            alerts = list(read(d / "alerts_rule.jsonl"))
        self.assertEqual([a["attack"] for a in alerts], ["dhcp_rogue"])
        self.assertEqual(alerts[0]["attacker"]["mac"], ATK["mac"])


if __name__ == "__main__":
    unittest.main()
