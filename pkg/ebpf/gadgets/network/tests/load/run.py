"""Explicit privileged load check; not invoked by the unit-test suite."""

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request


PORT = 32225


def metrics():
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/metrics", timeout=3) as response:
        return response.read().decode()


def value(text, name):
    match = re.search(rf"^{name} ([0-9.e+\-]+)$", text, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"missing metric: {name}")
    return float(match[1])


def measure(image, label, rate, sender, output_dir, cpu):
    log_path = output_dir / f"{label}-{rate}.log"
    command = [
        "sudo", "-n", "timeout", "-s", "INT", "-k", "5", "60",
        "ig", "-v", "run", image, "--verify-image=false", "--host", "-o", "none",
        "--otel-metrics-listen", f"--otel-metrics-listen-address=127.0.0.1:{PORT}",
        "--otel-metrics-export-internals",
    ]
    with log_path.open("w") as log:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log)
        try:
            for _ in range(120):
                if process.poll() is not None:
                    raise RuntimeError(f"gadget exited; see {log_path}")
                if "msg=running..." in log_path.read_text():
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError(f"gadget not ready; see {log_path}")
            before = metrics()
            sent = json.loads(subprocess.check_output(
                ["sudo", "-n", str(sender), "15", str(rate), str(cpu)], text=True,
            ))
            if process.poll() is not None:
                raise RuntimeError(f"gadget exited during load; see {log_path}")
            time.sleep(1)  # Let the perf reader drain before the final snapshot.
            after = metrics()
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                # The scoped timeout command also bounds the ig child lifetime.
                process.terminate()
                process.wait(timeout=45)
    log_text = log_path.read_text()
    if "Error:" in log_text or "level=error" in log_text or "level=fatal" in log_text:
        raise RuntimeError(f"gadget reported an error; see {log_path}")
    return {
        "variant": label, "image": image, "target_packets_per_second": rate,
        "cpu": cpu, **sent,
        "ig_cpu_seconds": value(after, "process_cpu_seconds_total")
            - value(before, "process_cpu_seconds_total"),
        "ig_alloc_bytes": value(after, "go_memstats_alloc_bytes_total")
            - value(before, "go_memstats_alloc_bytes_total"),
        "lost_samples": sum(map(int, re.findall(r"lost (\d+) samples", log_text))),
    }


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: run.py BASELINE_IMAGE PATH512_IMAGE PATH256_IMAGE")
    output_dir = Path(tempfile.mkdtemp(prefix="network-load-results-"))
    print(f"Results: {output_dir}", flush=True)
    cpu = min(os.sched_getaffinity(0))
    results = []
    with tempfile.TemporaryDirectory(prefix="network-load-build-") as build_dir:
        sender = Path(build_dir) / "sender"
        subprocess.run([
            "cc", "-O2", "-Wall", str(Path(__file__).with_name("udp_sender.c")),
            "-o", str(sender),
        ], check=True)
        for label, image in zip(["baseline", "512", "256"], sys.argv[1:]):
            for rate in [20000, 100000]:
                row = measure(image, label, rate, sender, output_dir, cpu)
                results.append(row)
                print(json.dumps(row), flush=True)
                (output_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                time.sleep(1)


if __name__ == "__main__":
    main()
