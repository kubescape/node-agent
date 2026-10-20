import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest import mock

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


class ParallelSamplingTests(unittest.TestCase):
    """Keep single-CPU runner validation at the documented sample threshold."""

    def test_single_cpu_sample_threshold(self):
        """Reject insufficient samples and accept the minimum and bounded buffer."""
        args = SimpleNamespace(capacity=1000, trials=100, ttl_ms=100,
                               pattern="hits", payload="int", scenario="parallel", cpus=1)
        for samples in (8192, 9999, 10000, 16384):
            with self.subTest(samples=samples), TemporaryDirectory() as directory:
                child = SimpleNamespace(returncode=0, stderr="", stdout=(
                    f"BenchmarkCacheParallel 1048576 100 ns/op 1 B/op 1 allocs/op "
                    f"200 p95-ns 300 p99-ns {samples} samples\n"))
                with mock.patch.object(module.subprocess, "run", return_value=child) as run:
                    if samples < 10000:
                        with self.assertRaisesRegex(RuntimeError, "insufficient latency samples"):
                            module.run_child(Path("cache.test"), args, "adapter", 0, Path(directory))
                    else:
                        result = module.run_child(Path("cache.test"), args, "adapter", 0, Path(directory))
                        self.assertEqual(result["samples"], samples)
                    self.assertIn("-test.cpu=1", run.call_args.args[0])
                    self.assertEqual(run.call_args.kwargs["env"]["GOMAXPROCS"], "1")


if __name__ == "__main__":
    unittest.main()
