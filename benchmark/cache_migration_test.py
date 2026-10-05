import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("cache_migration", Path(__file__).with_name("cache-migration.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LatencyGateTests(unittest.TestCase):
    def test_budget_and_uncertainty(self):
        for deltas, expected in [([-1] * 10, "pass"), ([1] * 10, "fail"),
                                 ([-1, 1] * 5, "inconclusive"), ([0] * 10, "pass")]:
            with self.subTest(expected=expected):
                self.assertEqual(module.classify(deltas, resamples=10_000)["status"], expected)

    def test_invalid_evidence(self):
        for deltas in [[], [0] * 9, [float("nan")] * 10, [float("inf")] * 10]:
            self.assertEqual(module.classify(deltas)["status"], "inconclusive")

    def test_missing_observations_do_not_pass(self):
        self.assertEqual(module.gate([], "idle")["status"], "inconclusive")

    def test_nonfinite_and_zero_latencies_do_not_pass(self):
        for invalid in [None, "bad", float("inf"), float("nan"), 0, -1]:
            records = []
            for repetition in range(10):
                for implementation in ("hashicorp", "adapter"):
                    records.append({"implementation": implementation, "repetition": repetition,
                                    "p95-ns": invalid if implementation == "hashicorp" else 1,
                                    "p99-ns": 1})
            self.assertEqual(module.gate(records, "parallel")["status"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
