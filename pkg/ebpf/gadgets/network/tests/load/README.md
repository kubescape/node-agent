# Network executable-path payload budget and load check

The executable-path buffer is **256 bytes**, including the terminating NUL.
Longer paths are truncated to 255 bytes. This halves the added payload compared
with the initial 512-byte design without changing the shared IG perf-reader size.

## Fixed ring capacity

BTF sizes from the built gadgets, with IG's 64-page per-CPU perf reader and
4096-byte host pages:

| Variant | Event bytes | Approximate perf-record bytes | Maximum records in 256 KiB |
| --- | ---: | ---: | ---: |
| Original (no executable path) | 128 | 144 | 1,820 |
| 512-byte path | 640 | 656 | 399 |
| 256-byte path (selected) | 384 | 400 | 655 |

Record estimates include the perf header, raw-size prefix and eight-byte alignment;
actual usable capacity also depends on other records and producer/consumer timing.
The selected design fits about 64% more records than the 512-byte version, while
still increasing the original event size threefold. Every event pays this fixed
cost, even if its path is empty; downstream event copies also carry the added bytes.

## Measured mixed IPv4/IPv6 UDP load

2026-10-16: AMD Ryzen 9 7900, 24 logical CPUs, x86_64 Linux
7.1.13+parrot7-amd64, IG v0.48.1, pinned v0.48.1 gadget builder. Both architectures
compiled; these load measurements and verifier loads ran on amd64 only.

`udp_sender.c` pins itself to CPU 0 and alternates successful UDP sends to
127.0.0.1:999 and [::1]:999, in batches of 100. Each rate runs for 15 seconds.
Bound receiver sockets avoid ICMP responses; receiver delivery/UDP queue drops
are not the metric being tested. There were zero send syscall errors.

`run.py` waits for the gadget's `running...` debug message before starting the
measurement, then allows one second for draining. CPU seconds and allocated MiB
are deltas from the IG process's Prometheus metrics. Lost samples are summed from
the perf-reader warnings. `--host -o none` avoids JSON/output costs, but includes
background host traffic. Counts below are perf samples, not a percentage of sends.

| Variant | Target packets/s | Successful sends | IG CPU seconds | IG allocated MiB | Lost samples |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 20,000 | 300,000 | 2.07 | 533.6 | 0 |
| baseline | 100,000 | 1,500,000 | 8.11 | 2657.9 | 0 |
| 512 | 20,000 | 300,000 | 2.18 | 534.1 | 0 |
| 512 | 100,000 | 1,500,000 | 8.03 | 2657.9 | 462 |
| 256 | 20,000 | 300,000 | 2.15 | 534.0 | 0 |
| 256 | 100,000 | 1,500,000 | 8.05 | 2658.4 | 227 |

This is a single-run local stress comparison, not an acceptance SLO. At 20k
packets/s all variants reported zero loss. At 100k packets/s both path-carrying
variants dropped samples, so the added payload is not free and 256 bytes does not
make drops impossible. CPU and allocation differences are noisy; these measurements
exclude the node agent's downstream queues, event DeepCopy, rule evaluation and
exporters. They do not establish full-agent overhead, native arm64 verifier
compatibility, or an older-kernel/production-cluster throughput ceiling.

## Reproduce

Prerequisites: Linux, Python 3, `cc`, IG v0.48.1, container builder access,
noninteractive sudo for the explicitly invoked workload, a free TCP port 32225 for
metrics and free local UDP port 999. The script is manual and never runs in `go test`.
It creates only its own test processes and temporary files; gadget processes have
a 60-second timeout. It prints its result directory and writes raw logs/results there.

From the repository root:

```sh
network_load_dir=$(mktemp -d)
mkdir "$network_load_dir/baseline" "$network_load_dir/path512"
git archive 493f1011 pkg/ebpf/gadgets/network | tar -x -C "$network_load_dir/baseline"
git archive 118caafe pkg/ebpf/gadgets/network | tar -x -C "$network_load_dir/path512"
sudo ig image build -t network:load-baseline "$network_load_dir/baseline/pkg/ebpf/gadgets/network"
sudo ig image build -t network:load-512 "$network_load_dir/path512/pkg/ebpf/gadgets/network"
sudo ig image build -t network:load-256 pkg/ebpf/gadgets/network
python3 pkg/ebpf/gadgets/network/tests/load/run.py network:load-baseline network:load-512 network:load-256
```

The baseline already includes IPv6 support, so the comparison isolates the path
payload with both current traffic classes present. Keep the images unchanged when
comparing rates; use the same reader configuration and builder for every variant.
