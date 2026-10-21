#!/usr/bin/env bash
# Only for a fresh, disposable GitHub-hosted Ubuntu VM. Never run on a workstation.
# Sources: minikube v1.38.1 none driver and its CNI/crictl release dependencies:
# https://minikube.sigs.k8s.io/docs/drivers/none/
# https://github.com/kubernetes/minikube/releases/tag/v1.38.1
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo "Native cluster setup requires a disposable GitHub-hosted Actions runner." >&2
  exit 1
fi
# shellcheck source=/dev/null
source /etc/os-release
if [[ "$ID" != ubuntu || "$VERSION_ID" != 22.04 || "$(uname -m)" != x86_64 ]]; then
  echo "Native cluster setup requires Ubuntu 22.04 amd64." >&2
  exit 1
fi
: "${RUNNER_TEMP:?}" "${GITHUB_ENV:?}"
if [[ "${1:-}" != --bounded ]]; then
  exec timeout --kill-after=15s 20m bash "$0" --bounded
fi

# Refuse to replace an existing cluster, even on a hosted runner.
if sudo test -e /etc/kubernetes/admin.conf || sudo test -d /var/lib/minikube; then
  echo "Existing Kubernetes/minikube state found; refusing native setup." >&2
  exit 1
fi
command -v containerd >/dev/null
command -v docker >/dev/null
timeout 15s sudo systemctl is-active containerd
timeout 15s docker info >/dev/null

work=$(mktemp -d "${RUNNER_TEMP}/native-component-cluster.XXXXXX")
cleanup() {
  result=$?
  if [[ "$result" != 0 ]]; then
    echo "Native cluster setup failed; recent runtime/kubelet diagnostics:" >&2
    timeout --kill-after=1s 10s sudo journalctl -u containerd -u kubelet \
      --no-pager -n 80 >&2 || true
    timeout --kill-after=1s 10s sudo /usr/local/bin/minikube status >&2 || true
  fi
  if [[ -n "${fixture_id:-}" ]]; then
    timeout --kill-after=1s 10s docker rm --force "$fixture_id" >/dev/null 2>&1 || true
  fi
  if [[ -n "${smoke_created:-}" ]]; then
    timeout --kill-after=1s 10s kubectl --request-timeout=8s delete pod component-runtime-smoke \
      --namespace=default --wait=false >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM
download() {
  curl --fail --location --silent --show-error --connect-timeout 10 --max-time 120 \
    "$1" -o "$work/$2"
  printf '%s  %s\n' "$3" "$work/$2" | sha256sum --check
}

timeout --kill-after=10s 4m sudo apt-get update
timeout --kill-after=10s 4m sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
  conntrack socat iptables jq
download https://github.com/kubernetes/minikube/releases/download/v1.38.1/minikube-linux-amd64 \
  minikube 099477eaf248bcb5bcea8ce78a2898e93ac01461c35189da1848c3de82ecd22e
download https://github.com/containernetworking/plugins/releases/download/v1.8.0/cni-plugins-linux-amd64-v1.8.0.tgz \
  cni.tgz ab3bda535f9d90766cccc90d3dddb5482003dd744d7f22bcf98186bf8eea8be6
download https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.35.0/crictl-v1.35.0-linux-amd64.tar.gz \
  crictl.tgz 2e141e5b22cb189c40365a11807d69b76b9b3caced89fac2f4ec879408ce2177
curl --fail --location --silent --show-error --connect-timeout 10 --max-time 120 \
  https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubectl.sha256 -o "$work/kubectl.sha256"
download https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubectl \
  kubectl "$(cat "$work/kubectl.sha256")"
sudo install -m 0755 "$work/minikube" "$work/kubectl" /usr/local/bin/
sudo mkdir -p /opt/cni/bin
sudo tar -xzf "$work/cni.tgz" -C /opt/cni/bin
sudo tar -xzf "$work/crictl.tgz" -C /usr/local/bin crictl

# The hosted runner's Docker package may disable CRI. Use the installed runtime's
# own default config, retaining its version and Docker's separate moby namespace.
containerd config default > "$work/containerd.toml"
sudo install -m 0644 "$work/containerd.toml" /etc/containerd/config.toml
sudo modprobe br_netfilter
sudo sysctl -w net.ipv4.ip_forward=1 net.bridge.bridge-nf-call-iptables=1
sudo swapoff -a
timeout --kill-after=5s 30s sudo systemctl restart containerd

# The none driver keeps other runtimes enabled. Minikube configures systemd
# cgroups and bridge CNI; do not use the nested Docker driver here.
timeout --kill-after=15s 10m sudo /usr/local/bin/minikube start \
  --driver=none --container-runtime=containerd --kubernetes-version=v1.35.0 \
  --cri-socket=/run/containerd/containerd.sock --force-systemd \
  --wait=all --wait-timeout=5m
export KUBECONFIG="$work/kubeconfig"
# Keep the flattened file owned by the runner, not root.
# shellcheck disable=SC2024
sudo /usr/local/bin/kubectl --kubeconfig=/root/.kube/config config view --raw --flatten > "$KUBECONFIG"
chmod 0600 "$KUBECONFIG"
printf 'KUBECONFIG=%s\n' "$KUBECONFIG" >> "$GITHUB_ENV"
timeout --kill-after=1s 15s docker info >/dev/null
timeout --kill-after=1s 15s sudo crictl --runtime-endpoint=unix:///run/containerd/containerd.sock info > "$work/cri-info.json"
jq -e '.status.conditions | any(.type == "RuntimeReady" and .status == true)' "$work/cri-info.json"
timeout --kill-after=1s 60s kubectl --request-timeout=55s wait --for=condition=Ready nodes --all --timeout=50s

# Prove hostPID pods and the CRI-reported init PID use this VM's kernel PID
# domain, which is essential for matching eBPF process IDs to runtime metadata.
timeout --kill-after=1s 15s kubectl --request-timeout=12s create -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: component-runtime-smoke
  namespace: default
spec:
  hostPID: true
  restartPolicy: Never
  containers:
    - name: smoke
      image: busybox:1.36.1
      command: ["sleep", "600"]
YAML
smoke_created=true
timeout --kill-after=1s 90s kubectl --request-timeout=85s wait \
  --for=condition=Ready pod/component-runtime-smoke --timeout=80s
container_id=$(timeout 10s kubectl --request-timeout=8s get pod component-runtime-smoke \
  -o jsonpath='{.status.containerStatuses[0].containerID}')
container_id=${container_id#containerd://}
[[ "$container_id" =~ ^[a-f0-9]{64}$ ]]
pid=$(timeout 10s sudo crictl --runtime-endpoint=unix:///run/containerd/containerd.sock \
  inspect "$container_id" | jq -er '.info.pid')
[[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]]
host_pidns=$(readlink /proc/self/ns/pid)
runtime_pidns=$(sudo readlink "/proc/$pid/ns/pid")
pod_pidns=$(timeout 10s kubectl --request-timeout=8s exec component-runtime-smoke -- readlink /proc/self/ns/pid)
[[ "$host_pidns" == "$runtime_pidns" && "$host_pidns" == "$pod_pidns" ]]
sudo awk '/^NSpid:/ { if (NF != 2) exit 1; found=1 } END { if (!found) exit 1 }' "/proc/$pid/status"
[[ "$(sudo cat "/proc/$pid/comm")" == sleep ]]
printf 'Native PID smoke passed: container=%s kernelPID=%s namespace=%s\n' "$container_id" "$pid" "$host_pidns"

# Keep the endpoints outside Kubernetes inventory, just like Test01. Validate
# routing from the pod network (hostPID above does not enable hostNetwork).
timeout 15s docker network create --driver bridge \
  --label component-test=native-cluster \
  --opt com.docker.network.bridge.name=ct-fixture0 component-fixtures
timeout --kill-after=1s 90s docker pull nginx:1.25.5
fixture_id=$(timeout --kill-after=1s 15s docker create --network component-fixtures \
  --label component-test=native-cluster nginx:1.25.5)
[[ "$fixture_id" =~ ^[a-f0-9]{64}$ ]]
timeout --kill-after=1s 15s docker start "$fixture_id"
fixture_ip=$(timeout 10s docker inspect --format \
  '{{with index .NetworkSettings.Networks "component-fixtures"}}{{.IPAddress}}{{end}}' "$fixture_id")
[[ "$fixture_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
for attempt in {1..10}; do
  if curl --noproxy '*' --fail --silent --show-error --max-time 2 "http://$fixture_ip/" >/dev/null; then
    break
  fi
  [[ "$attempt" != 10 ]]
  sleep 1
done
probe_fixture() {
  timeout --kill-after=1s 10s kubectl --request-timeout=8s exec component-runtime-smoke -- \
    wget -T 5 -q -O /dev/null "http://$fixture_ip/"
}
if ! probe_fixture; then
  # Docker can reject traffic between its bridge and the CNI bridge. Permit
  # only this CNI subnet/interface to this fixture subnet/interface and replies.
  cni_bridge=$(sudo jq -er '.plugins[] | select(.type == "bridge") | .bridge' /etc/cni/net.d/1-k8s.conflist)
  cni_subnet=$(sudo jq -er '.plugins[] | select(.type == "bridge") | .ipam.subnet' /etc/cni/net.d/1-k8s.conflist)
  fixture_subnet=$(timeout 10s docker network inspect --format '{{(index .IPAM.Config 0).Subnet}}' component-fixtures)
  timeout 10s sudo iptables -w 5 -I DOCKER-USER 1 \
    -i "$cni_bridge" -o ct-fixture0 -s "$cni_subnet" -d "$fixture_subnet" -j ACCEPT
  timeout 10s sudo iptables -w 5 -I DOCKER-USER 1 \
    -i ct-fixture0 -o "$cni_bridge" -s "$fixture_subnet" -d "$cni_subnet" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  probe_fixture
fi
printf 'COMPONENT_DOCKER_NETWORK=component-fixtures\n' >> "$GITHUB_ENV"
echo "Native pod-to-external-fixture HTTP smoke passed."
