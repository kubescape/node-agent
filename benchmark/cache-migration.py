#!/usr/bin/env python3
"""Isolated cache experiments. A failed/inconclusive latency gate exits nonzero.

Each child runs exactly one scenario, one implementation, one CPU setting and
one repetition. Hashicorp's cache is reused across benchmark calibration.
The default experiment targets the first-write-after-inactivity risk first.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import statistics
import subprocess
import sys


# Predeclared upper bound on primary comparisons: steady state has 3 payloads
# * 4 patterns * 3 capacities * 3 CPU settings * 2 percentiles = 216;
# idle has 3 capacities * 3 CPUs * 3 latency metrics * 2 percentiles = 54.
COMPARISONS = 270


def classify(deltas, comparisons=COMPARISONS, resamples=100_000):
    """Bonferroni-adjusted paired bootstrap interval of median relative change."""
    if len(deltas) < 10 or any(not math.isfinite(x) for x in deltas):
        return {"status": "inconclusive", "reason": "need >=10 finite paired observations"}
    rng = random.Random(1014)
    count = len(deltas)
    bootstrap = sorted(
        statistics.median(deltas[rng.randrange(count)] for _ in range(count))
        for _ in range(resamples)
    )
    tail = 0.025 / comparisons
    lower = bootstrap[int(tail * resamples)]
    upper = bootstrap[min(resamples - 1, math.ceil((1 - tail) * resamples) - 1)]
    status = "pass" if upper <= 0 else "fail" if lower > 0 else "inconclusive"
    return {"status": status, "median_change_percent": statistics.median(deltas),
            "lower_percent": lower, "upper_percent": upper, "pairs": count,
            "family_comparisons": comparisons, "family_confidence": 0.95}


def gate(records, scenario):
    rows = {"hashicorp": {}, "adapter": {}}
    for row in records:
        if row["implementation"] in rows:
            rows[row["implementation"]][row["repetition"]] = row
    repetitions = sorted(set(rows["hashicorp"]) & set(rows["adapter"]))
    metrics = ([f"{name}_p{p}_ns" for name in ("write", "reader_call", "reader_response")
                for p in (95, 99)] if scenario == "idle" else ["p95-ns", "p99-ns"])
    decisions = {}
    for metric in metrics:
        deltas = []
        for repetition in repetitions:
            baseline = rows["hashicorp"][repetition].get(metric)
            candidate = rows["adapter"][repetition].get(metric)
            if (not isinstance(baseline, (int, float)) or not isinstance(candidate, (int, float))
                    or not math.isfinite(baseline) or not math.isfinite(candidate)
                    or baseline <= 0 or candidate < 0):
                break
            deltas.append(100 * (candidate / baseline - 1))
        decisions[metric] = classify(deltas) if len(deltas) == len(repetitions) else {
            "status": "inconclusive", "reason": "missing or invalid latency observations"}
    status = ("fail" if any(x["status"] == "fail" for x in decisions.values()) else
              "pass" if all(x["status"] == "pass" for x in decisions.values()) else "inconclusive")
    return {"status": status, "latency_budget_percent": 0, "metrics": decisions}


def run_child(binary, args, implementation, repetition, output):
    env = dict(os.environ, CACHE_BENCH_IMPL=implementation,
               CACHE_BENCH_CAPACITY=str(args.capacity), CACHE_BENCH_TRIALS=str(args.trials),
               CACHE_BENCH_TTL_MS=str(args.ttl_ms), CACHE_BENCH_PATTERN=args.pattern,
               CACHE_BENCH_PAYLOAD=args.payload,
               CACHE_BENCH_LATENCY="0" if args.scenario == "allocations" else "1",
               GOMAXPROCS=str(args.cpus))
    command = [str(binary), "-test.count=1", f"-test.cpu={args.cpus}"]
    if args.scenario == "idle":
        command += ["-test.run=^TestCacheIdleLatency$", "-test.v"]
    else:
        command += ["-test.run=^$", "-test.bench=^BenchmarkCacheParallel$",
                    "-test.benchtime=2s", "-test.benchmem"]
    child = subprocess.run(command, env=env, text=True, capture_output=True)
    raw_path = output / f"{repetition:02d}-{implementation}.txt"
    raw_path.write_text(child.stdout + child.stderr)
    if child.returncode:
        raise RuntimeError(f"{implementation} child failed; see {raw_path}")
    if args.scenario == "idle":
        result = next((json.loads(line.split("=", 1)[1]) for line in child.stdout.splitlines()
                       if line.startswith("CACHE_IDLE_RESULT=")), None)
        if result is None:
            raise RuntimeError(f"missing idle result in {raw_path}")
    else:
        line = next((line for line in child.stdout.splitlines()
                     if line.startswith("BenchmarkCacheParallel")), "")
        result = {unit: float(value) for value, unit in
                  re.findall(r"([\d.eE+-]+)\s+(ns/op|B/op|allocs/op|p95-ns|p99-ns|samples)", line)}
        if args.scenario != "allocations" and result.get("samples", 0) < 10_000:
            raise RuntimeError(f"insufficient latency samples in {raw_path}")
        if not math.isfinite(result.get("ns/op", float("nan"))) or result["ns/op"] <= 0:
            raise RuntimeError(f"invalid operation timing in {raw_path}")
        result["implementation"] = implementation
    result["repetition"] = repetition
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", choices=("idle", "parallel", "allocations"), default="idle")
    parser.add_argument("--capacity", type=int, default=50_000)
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--ttl-ms", type=int, default=100)
    parser.add_argument("--pattern", choices=("hits", "misses", "churn", "expiration"), default="hits")
    parser.add_argument("--payload", choices=("int", "hash", "process"), default="hash")
    parser.add_argument("--implementations", nargs="+", choices=("hashicorp", "adapter", "passive", "active"),
                        default=["hashicorp", "adapter", "passive", "active"])
    parser.add_argument("--repetitions", type=int, default=10)
    args = parser.parse_args()
    if min(args.capacity, args.cpus, args.trials, args.ttl_ms) <= 0 or args.repetitions < 10:
        parser.error("positive dimensions and at least ten repetitions required")
    if not {"hashicorp", "adapter"}.issubset(args.implementations):
        parser.error("both hashicorp and adapter required for the gate")
    if args.scenario == "idle" and args.payload != "hash":
        parser.error("the idle scenario uses representative file-hash payloads; select --payload hash")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary = output / "cache.test"
    root = Path(__file__).resolve().parent.parent
    build_env = dict(os.environ, GOTOOLCHAIN="go1.27.0")
    subprocess.run(["go", "test", "-mod=readonly", "-c", "-o", str(binary), "./internal/ttlcache"],
                   cwd=root, env=build_env, check=True)
    manifest = vars(args).copy()
    manifest["output"] = str(output)
    manifest["baseline_sha"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    manifest["go_version"] = subprocess.check_output(["go", "version"], env=build_env, text=True).strip()
    manifest["working_diff"] = subprocess.check_output(["git", "diff"], cwd=root, text=True)
    manifest["source_snapshot"] = {}
    paths = list((root / "internal/ttlcache").glob("*.go")) + [
        Path(__file__).resolve(), root / "benchmark/cache_migration_test.py", root / "go.mod", root / "go.sum",
        root / "pkg/processtree/process_tree_manager.go", root / "pkg/processtree/process_tree_manager_test.go"]
    for path in paths:
        relative = str(path.relative_to(root))
        target = output / "sources" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        source = path.read_bytes()
        target.write_bytes(source)
        manifest["source_snapshot"][relative] = hashlib.sha256(source).hexdigest()
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2))
    records = []
    total = args.repetitions
    repetition = 0
    while repetition < total:
        order = args.implementations if repetition % 2 == 0 else list(reversed(args.implementations))
        for implementation in order:
            print(f"repetition {repetition + 1}/{total}: {implementation}", flush=True)
            records.append(run_child(binary, args, implementation, repetition, output))
            (output / "observations.json").write_text(json.dumps(records, indent=2))
        repetition += 1
        if repetition == total:
            report = ({"status": "diagnostic", "scenario": "allocations",
                       "note": "uninstrumented B/op and allocs/op; this is not a latency gate"}
                      if args.scenario == "allocations" else gate(records, args.scenario))
            if report["status"] == "inconclusive" and total < 30:
                total = 30
                print("inconclusive: extending paired experiment to 30 repetitions", flush=True)
    (output / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2), flush=True)
    return 0 if report["status"] in ("pass", "diagnostic") else 1


if __name__ == "__main__":
    sys.exit(main())
