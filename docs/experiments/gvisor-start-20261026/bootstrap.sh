#!/bin/sh
# Exact installation inputs for the disposable Ubuntu ARM64 trial VM.
# This changes the VM's packages and /usr/local/bin; do not run on a shared node.
set -eu
test "$(uname -m)" = aarch64
test "$(id -u)" = 0
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  ca-certificates curl bzip2 containerd runc busybox-static python3 jq bpftrace tcpdump
install -d -m 0700 /home/ubuntu/gvisor-trial /run/kubescape
cd /home/ubuntu/gvisor-trial
curl -fL --max-time 300 -o gvisor-aarch64.tar.bz2 \
  https://github.com/google/gvisor/releases/download/release-20261019.0/gvisor-aarch64.tar.bz2
printf '%s  %s\n' \
  5790f89dc94b091b5aa0f0b6596aa4391606b3fe5f069e68f440576f3388abd8 \
  gvisor-aarch64.tar.bz2 | sha256sum -c -
tar -xjf gvisor-aarch64.tar.bz2 -C /usr/local/bin
systemctl start containerd
ctr namespaces create gvisor-trial
mkdir -p /opt/gvisor-trial/rootfs/bin /opt/gvisor-trial/rootfs/tmp \
  /opt/gvisor-trial/rootfs/proc /opt/gvisor-trial/rootfs/dev
cp /usr/bin/busybox /opt/gvisor-trial/rootfs/bin/busybox
ln -s busybox /opt/gvisor-trial/rootfs/bin/sh
ln -s busybox /opt/gvisor-trial/rootfs/bin/sleep
cat > pod-init.json <<'JSON'
{"trace_session":{"name":"Default","points":[{"name":"container/start"}],"sinks":[{"name":"remote","config":{"endpoint":"/run/kubescape/gvisor-events.sock"}}]}}
JSON
cat > runsc.toml <<'TOML'
[runsc_config]
platform = "systrap"
pod-init-config = "/home/ubuntu/gvisor-trial/pod-init.json"
TOML
