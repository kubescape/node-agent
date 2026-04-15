#!/usr/bin/env python3
"""
Compare before/after eBPF dedup benchmark metrics.

Usage: python3 compare-metrics.py [--format text|markdown] <before-dir> <after-dir>

Reads cpu_metrics.csv, memory_metrics.csv, dedup_total.json, and events_total.json
produced by dedup-bench.sh and prints a side-by-side comparison table.
"""

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

SIGNIFICANT_THRESHOLD = 10.0  # percent change that triggers quality gate failure


def load_csv(directory: Path, name: str) -> pd.DataFrame:
    path = directory / name
    if not path.exists():
        print(f"Warning: {path} not found", file=sys.stderr)
        return pd.DataFrame(columns=["Time", "Pod", "Value"])
    return pd.read_csv(path)


def load_json(directory: Path, name: str) -> dict | None:
    path = directory / name
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def compute_resource_stats(df: pd.DataFrame) -> dict:
    """Filter to node-agent pods and compute avg/peak."""
    na = df[df["Pod"].str.contains("node-agent", na=False)]
    if na.empty:
        return {"avg": 0.0, "peak": 0.0}
    return {"avg": na["Value"].mean(), "peak": na["Value"].max()}


def format_delta(before: float, after: float) -> str:
    if before == 0:
        return "N/A"
    pct = (after - before) / before * 100
    sign = "+" if pct >= 0 else ""
    return f"{sign}{pct:.1f}%"


def format_delta_md(before: float, after: float) -> str:
    """Format delta for markdown, bolding significant changes."""
    if before == 0:
        return "N/A"
    pct = (after - before) / before * 100
    sign = "+" if pct >= 0 else ""
    text = f"{sign}{pct:.1f}%"
    if abs(pct) >= SIGNIFICANT_THRESHOLD:
        return f"**{text}**"
    return text


# ---------------------------------------------------------------
#  Text output (original format)
# ---------------------------------------------------------------

def print_resource_table_text(before_dir: Path, after_dir: Path) -> None:
    before_cpu = compute_resource_stats(load_csv(before_dir, "cpu_metrics.csv"))
    after_cpu = compute_resource_stats(load_csv(after_dir, "cpu_metrics.csv"))
    before_mem = compute_resource_stats(load_csv(before_dir, "memory_metrics.csv"))
    after_mem = compute_resource_stats(load_csv(after_dir, "memory_metrics.csv"))

    rows = [
        ("Avg CPU (cores)", before_cpu["avg"], after_cpu["avg"]),
        ("Peak CPU (cores)", before_cpu["peak"], after_cpu["peak"]),
        ("Avg Memory (MiB)", before_mem["avg"], after_mem["avg"]),
        ("Peak Memory (MiB)", before_mem["peak"], after_mem["peak"]),
    ]

    print("  Node-Agent Resource Usage")
    print("  " + "-" * 55)
    print(f"  {'Metric':<22}{'BEFORE':>12}{'AFTER':>12}{'Delta':>12}")
    print("  " + "-" * 55)
    for label, bv, av in rows:
        print(f"  {label:<22}{bv:>12.3f}{av:>12.3f}{format_delta(bv, av):>12}")
    print()


def print_dedup_table_text(after_dir: Path) -> None:
    data = load_json(after_dir, "dedup_total.json")
    if not data or data.get("status") != "success":
        print("  Dedup Effectiveness: no data available\n")
        return

    results = data.get("data", {}).get("result", [])
    if not results:
        print("  Dedup Effectiveness: no data available\n")
        return

    by_type = _aggregate_dedup(results)

    print("  Dedup Effectiveness (AFTER only)")
    print("  " + "-" * 55)
    print(f"  {'Event Type':<16}{'Passed':>10}{'Deduped':>10}{'Ratio':>10}")
    print("  " + "-" * 55)
    for et in sorted(by_type):
        passed = by_type[et]["passed"]
        deduped = by_type[et]["deduplicated"]
        total = passed + deduped
        ratio = f"{deduped / total * 100:.1f}%" if total > 0 else "N/A"
        print(f"  {et:<16}{passed:>10.0f}{deduped:>10.0f}{ratio:>10}")
    print()


def print_event_comparison_text(before_dir: Path, after_dir: Path) -> None:
    before_counters = _extract_counters(load_json(before_dir, "events_total.json"))
    after_counters = _extract_counters(load_json(after_dir, "events_total.json"))
    all_names = sorted(set(before_counters) | set(after_counters))

    if not all_names:
        return

    print("  Event Counters")
    print("  " + "-" * 55)
    print(f"  {'Metric':<35}{'BEFORE':>10}{'AFTER':>10}")
    print("  " + "-" * 55)
    for name in all_names:
        bv = before_counters.get(name, 0.0)
        av = after_counters.get(name, 0.0)
        short = name.replace("node_agent_", "")
        print(f"  {short:<35}{bv:>10.0f}{av:>10.0f}")
    print()


# ---------------------------------------------------------------
#  Markdown output (for PR comments)
# ---------------------------------------------------------------

def print_resource_table_md(before_dir: Path, after_dir: Path) -> None:
    before_cpu = compute_resource_stats(load_csv(before_dir, "cpu_metrics.csv"))
    after_cpu = compute_resource_stats(load_csv(after_dir, "cpu_metrics.csv"))
    before_mem = compute_resource_stats(load_csv(before_dir, "memory_metrics.csv"))
    after_mem = compute_resource_stats(load_csv(after_dir, "memory_metrics.csv"))

    rows = [
        ("Avg CPU (cores)", before_cpu["avg"], after_cpu["avg"]),
        ("Peak CPU (cores)", before_cpu["peak"], after_cpu["peak"]),
        ("Avg Memory (MiB)", before_mem["avg"], after_mem["avg"]),
        ("Peak Memory (MiB)", before_mem["peak"], after_mem["peak"]),
    ]

    print("<details>")
    print("<summary>Node-Agent Resource Usage</summary>")
    print()
    print("| Metric | BEFORE | AFTER | Delta |")
    print("|--------|-------:|------:|------:|")
    for label, bv, av in rows:
        print(f"| {label} | {bv:.3f} | {av:.3f} | {format_delta_md(bv, av)} |")
    print()
    print("</details>")
    print()


def print_dedup_table_md(after_dir: Path) -> None:
    data = load_json(after_dir, "dedup_total.json")
    if not data or data.get("status") != "success":
        print("<details>")
        print("<summary>Dedup Effectiveness</summary>")
        print()
        print("No data available.")
        print()
        print("</details>")
        print()
        return

    results = data.get("data", {}).get("result", [])
    if not results:
        print("<details>")
        print("<summary>Dedup Effectiveness</summary>")
        print()
        print("No data available.")
        print()
        print("</details>")
        print()
        return

    by_type = _aggregate_dedup(results)

    print("<details>")
    print("<summary>Dedup Effectiveness (AFTER only)</summary>")
    print()
    print("| Event Type | Passed | Deduped | Ratio |")
    print("|------------|-------:|--------:|------:|")
    for et in sorted(by_type):
        passed = by_type[et]["passed"]
        deduped = by_type[et]["deduplicated"]
        total = passed + deduped
        ratio = f"{deduped / total * 100:.1f}%" if total > 0 else "N/A"
        print(f"| {et} | {passed:.0f} | {deduped:.0f} | {ratio} |")
    print()
    print("</details>")
    print()


def print_event_comparison_md(before_dir: Path, after_dir: Path) -> None:
    before_counters = _extract_counters(load_json(before_dir, "events_total.json"))
    after_counters = _extract_counters(load_json(after_dir, "events_total.json"))
    all_names = sorted(set(before_counters) | set(after_counters))

    if not all_names:
        return

    print("<details>")
    print("<summary>Event Counters</summary>")
    print()
    print("| Metric | BEFORE | AFTER |")
    print("|--------|-------:|------:|")
    for name in all_names:
        bv = before_counters.get(name, 0.0)
        av = after_counters.get(name, 0.0)
        short = name.replace("node_agent_", "")
        print(f"| {short} | {bv:.0f} | {av:.0f} |")
    print()
    print("</details>")
    print()


# ---------------------------------------------------------------
#  Shared helpers
# ---------------------------------------------------------------

def _aggregate_dedup(results: list) -> dict:
    by_type: dict[str, dict[str, float]] = {}
    for item in results:
        et = item["metric"].get("event_type", "unknown")
        result = item["metric"].get("result", "unknown")
        value = float(item["value"][1]) if len(item.get("value", [])) > 1 else 0.0
        by_type.setdefault(et, {"passed": 0.0, "deduplicated": 0.0})
        by_type[et][result] = value
    return by_type


def _extract_counters(data: dict | None) -> dict[str, float]:
    if not data or data.get("status") != "success":
        return {}
    counters: dict[str, float] = {}
    for item in data.get("data", {}).get("result", []):
        name = item["metric"].get("__name__", "")
        value = float(item["value"][1]) if len(item.get("value", [])) > 1 else 0.0
        counters[name] = counters.get(name, 0.0) + value
    return counters


# ---------------------------------------------------------------
#  Quality gate
# ---------------------------------------------------------------

def check_degradation(before_dir: Path, after_dir: Path, threshold: float) -> list[str]:
    """Return list of failure messages for metrics that degraded beyond threshold."""
    before_cpu = compute_resource_stats(load_csv(before_dir, "cpu_metrics.csv"))
    after_cpu = compute_resource_stats(load_csv(after_dir, "cpu_metrics.csv"))
    before_mem = compute_resource_stats(load_csv(before_dir, "memory_metrics.csv"))
    after_mem = compute_resource_stats(load_csv(after_dir, "memory_metrics.csv"))

    checks = [
        ("Avg CPU", before_cpu["avg"], after_cpu["avg"]),
        ("Peak CPU", before_cpu["peak"], after_cpu["peak"]),
        ("Avg Memory", before_mem["avg"], after_mem["avg"]),
        ("Peak Memory", before_mem["peak"], after_mem["peak"]),
    ]

    failures = []
    for label, before, after in checks:
        if before == 0:
            continue
        pct = (after - before) / before * 100
        if pct > threshold:
            failures.append(f"{label}: +{pct:.1f}% (before={before:.3f}, after={after:.3f}, threshold={threshold}%)")
    return failures


# ---------------------------------------------------------------
#  Main
# ---------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare before/after eBPF dedup benchmark metrics."
    )
    parser.add_argument(
        "--format",
        choices=["text", "markdown"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit with code 1 if any node-agent metric degrades beyond threshold",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=SIGNIFICANT_THRESHOLD,
        help=f"Degradation threshold in percent (default: {SIGNIFICANT_THRESHOLD}%%)",
    )
    parser.add_argument("before_dir", type=Path, help="Directory with before metrics")
    parser.add_argument("after_dir", type=Path, help="Directory with after metrics")
    args = parser.parse_args()

    for d in (args.before_dir, args.after_dir):
        if not d.is_dir():
            print(f"Error: {d} is not a directory", file=sys.stderr)
            sys.exit(1)

    if args.format == "markdown":
        print("## Performance Benchmark Results")
        print()
        print_resource_table_md(args.before_dir, args.after_dir)
        print_dedup_table_md(args.after_dir)
        print_event_comparison_md(args.before_dir, args.after_dir)
    else:
        print()
        print("=" * 61)
        print("  eBPF Dedup Benchmark Results")
        print("=" * 61)
        print()
        print_resource_table_text(args.before_dir, args.after_dir)
        print_dedup_table_text(args.after_dir)
        print_event_comparison_text(args.before_dir, args.after_dir)
        print("=" * 61)
        print()

    if args.check:
        failures = check_degradation(args.before_dir, args.after_dir, args.threshold)
        if failures:
            print("QUALITY GATE FAILED: Performance degradation detected", file=sys.stderr)
            for f in failures:
                print(f"  - {f}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Quality gate passed: no metric degraded beyond {args.threshold}%", file=sys.stderr)


if __name__ == "__main__":
    main()
