"""env/scenarios.py 시나리오 정의 검사 (Mininet 불필요)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.records import ATTACKS  # noqa: E402
from env.hosts import by_name  # noqa: E402
from env.scenarios import CORE, SCENARIOS, VARIANTS  # noqa: E402


class TestScenarios(unittest.TestCase):
    def test_names_match_keys(self):
        for key, s in SCENARIOS.items():
            self.assertEqual(key, s.name)

    def test_attack_is_known_label(self):
        for s in SCENARIOS.values():
            self.assertIn(s.attack, ATTACKS, s.name)

    def test_hosts_exist_and_module_file_exists(self):
        for s in SCENARIOS.values():
            by_name(s.attacker)
            if s.target:
                by_name(s.target)
            f = ROOT / (s.module.replace(".", "/") + ".py")
            self.assertTrue(f.exists(), f"{s.name}: {f}")

    def test_target_ip_matches_target_host(self):
        """--target-ip / --victim-ip 가 label의 target 호스트와 같아야 한다."""
        for s in SCENARIOS.values():
            for flag in ("--target-ip", "--victim-ip"):
                if flag in s.args and s.target:
                    ip = s.args[s.args.index(flag) + 1]
                    self.assertEqual(ip, by_name(s.target).ip, f"{s.name} {flag}")

    def test_variants_do_not_shadow_core(self):
        self.assertFalse(set(CORE) & set(VARIANTS))
        self.assertEqual(len(VARIANTS), len(set(VARIANTS)))

    def test_evasive_variants_say_how(self):
        for name in VARIANTS:
            s = SCENARIOS[name]
            if s.evasive:
                self.assertIn("evasion", s.params, name)

    def test_args_are_strings(self):
        for s in SCENARIOS.values():
            self.assertTrue(all(isinstance(a, str) for a in s.args), s.name)


if __name__ == "__main__":
    unittest.main()
