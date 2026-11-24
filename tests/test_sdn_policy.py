"""sdn/policy·apply_alerts 검증 (OS-Ken/Mininet 불필요)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.records import endpoint, make, read  # noqa: E402
from sdn.apply_alerts import load_alerts, record_offline  # noqa: E402
from sdn.policy import (  # noqa: E402
    BlockDeduper, block_spec, dpid_for, make_block_action,
)

T = 1763357400.0
ATK = endpoint("00:00:00:00:00:04", "10.0.0.4", "s1", 4)
SEG = endpoint(None, None, "s1", 4)


def alert(attack="arp_spoof", attacker=ATK, aid="rule-1", ts=T):
    return make("alert", ts=ts, alert_id=aid, detector="rule", source="x",
                attack=attack, score=1.0, attacker=attacker, victim=None,
                feature_ts=ts, win=1, summary="", evidence={})


class TestBlockSpec(unittest.TestCase):
    def test_mac_and_port(self):
        s = block_spec(alert())
        self.assertEqual(s["match"], "mac+port")
        self.assertEqual(s["mac"], ATK["mac"])
        self.assertEqual(s["port"], 4)
        self.assertEqual(s["dpid"], 1)

    def test_port_only_for_mac_flood(self):
        s = block_spec(alert("mac_flood", SEG))
        self.assertEqual(s["match"], "port")
        self.assertIsNone(s["mac"])
        self.assertEqual(s["port"], 4)

    def test_no_target(self):
        empty = endpoint(None, None, None, None)
        self.assertIsNone(block_spec(alert(attacker=empty)))

    def test_dpid_map(self):
        self.assertEqual(dpid_for("s1"), 1)
        self.assertEqual(dpid_for("1"), 1)
        self.assertIsNone(dpid_for("s9"))


class TestActionRecord(unittest.TestCase):
    def test_make_block_action_valid(self):
        a = alert()
        s = block_spec(a)
        act = make_block_action(a, s, ok=True, install_ms=1.5, ts=T + 1)
        self.assertEqual(act["type"], "action")
        self.assertEqual(act["action"], "block")
        self.assertEqual(act["alert_id"], "rule-1")
        self.assertTrue(act["ok"])
        self.assertEqual(act["target"]["mac"], ATK["mac"])

    def test_dedup(self):
        d = BlockDeduper()
        s = block_spec(alert())
        self.assertTrue(d.allow(s, T))
        self.assertFalse(d.allow(s, T + 5))
        self.assertTrue(d.allow(s, T + 11))


class TestApplyOffline(unittest.TestCase):
    def test_record_and_skip_unblockable(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            with open(d / "alerts_rule.jsonl", "w", encoding="utf-8") as fh:
                fh.write(json.dumps(alert(aid="a1"), ensure_ascii=False) + "\n")
                fh.write(json.dumps(
                    alert(aid="a2", attack="mac_flood", attacker=SEG),
                    ensure_ascii=False) + "\n")
                fh.write(json.dumps(
                    alert(aid="a3", attacker=endpoint(None, None, None, None)),
                    ensure_ascii=False) + "\n")
            alerts = load_alerts(d)
            n = record_offline(d, alerts)
            acts = list(read(d / "actions.jsonl"))
        self.assertEqual(n, 2)
        self.assertEqual(len(acts), 2)
        self.assertTrue(all(a["ok"] for a in acts))
        self.assertTrue(all("[offline]" in a["reason"] for a in acts))
        macs = {a["target"]["mac"] for a in acts}
        self.assertIn(ATK["mac"], macs)
        self.assertIn(None, macs)


if __name__ == "__main__":
    unittest.main()
