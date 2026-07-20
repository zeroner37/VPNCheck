import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "vpncheck.py"
SPEC = importlib.util.spec_from_file_location("vpncheck", MODULE_PATH)
vpn_check = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules["vpncheck"] = vpn_check
SPEC.loader.exec_module(vpn_check)


class CoreTests(unittest.TestCase):
    def test_parse_ping_english(self):
        text = "Reply from 1.1.1.1: bytes=32 time=42ms TTL=57"
        self.assertEqual(vpn_check.parse_windows_ping(text), 42.0)

    def test_parse_ping_chinese(self):
        text = "来自 1.1.1.1 的回复: 字节=32 时间=18ms TTL=57"
        self.assertEqual(vpn_check.parse_windows_ping(text), 18.0)

    def test_parse_timeout(self):
        self.assertIsNone(vpn_check.parse_windows_ping("Request timed out."))

    def test_metrics(self):
        window = vpn_check.MetricWindow(10)
        for value in (10.0, 14.0, None, 16.0):
            window.add(value)
        result = window.snapshot()
        self.assertAlmostEqual(result["loss"], 25.0)
        self.assertAlmostEqual(result["jitter"], 3.0)
        self.assertAlmostEqual(result["average"], 40 / 3)

    def test_risk_labels(self):
        self.assertEqual(vpn_check.risk_label(0)[0], "低风险")
        self.assertEqual(vpn_check.risk_label(70)[0], "很高风险")

    def test_multi_target_metrics(self):
        window = vpn_check.MultiTargetMetricWindow(10)
        window.add_batch([100.0, 200.0, None, 300.0])
        window.add_batch([110.0, 210.0, 310.0, 410.0])
        result = window.snapshot()
        self.assertAlmostEqual(result["loss"], 12.5)
        self.assertEqual(result["latest"], 260.0)
        self.assertEqual(result["jitter"], 60.0)


if __name__ == "__main__":
    unittest.main()
