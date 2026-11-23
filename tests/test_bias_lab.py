import unittest
import sys
import os

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.bias_audit import audit_statistical_bias, SECP256K1_N
from src.entropy_analysis import calculate_shannon_entropy, calculate_uniqueness_ratio
from src.cve_2013_7372_scanner import filter_cve_targets

class TestBiasLab(unittest.TestCase):
    def test_statistical_bias_audit(self):
        sample_matrix = [
            (0x123456789, 0x987654321, 0xABCDEF),
            (0x23456789A, 0x876543219, 0xBCDEFA),
            (0x3456789AB, 0x765432198, 0xCDEFAB)
        ]
        res = audit_statistical_bias(sample_matrix)
        self.assertEqual(res["count"], 3)
        self.assertGreaterEqual(res["mean"], 0.0)
        self.assertLessEqual(res["mean"], 1.0)
        self.assertIn("variance", res)

    def test_shannon_entropy(self):
        uniform_bytes = bytes(range(256))
        ent = calculate_shannon_entropy(uniform_bytes)
        self.assertLess(abs(ent - 8.0), 0.01)

        constant_bytes = b'\x00' * 100
        ent_const = calculate_shannon_entropy(constant_bytes)
        self.assertEqual(ent_const, 0.0)

    def test_cve_filter(self):
        targets = [
            {"address": "1Test1", "spend_count": 80, "anomaly_ratio": 0.99, "android_bug_window_count": 10},
            {"address": "1Test2", "spend_count": 10, "anomaly_ratio": 0.40, "android_bug_window_count": 0}
        ]
        flagged = filter_cve_targets(targets, min_spend_count=50, min_anomaly_ratio=0.95)
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0]["address"], "1Test1")

if __name__ == "__main__":
    unittest.main()
