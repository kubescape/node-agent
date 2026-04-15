#!/usr/bin/env bash
set -euo pipefail

# =============================================================
#  eBPF Dedup Benchmark — Kind Cluster Performance Test
#
#  Usage: ./dedup-bench.sh <before-image> <after-image>
#  Example: ./dedup-bench.sh quay.io/kubescape/node-agent:baseline quay.io/kubescape/node-agent:dedup
#
#  Environment variable alternatives (for CI):
#    BEFORE_IMAGE=quay.io/kubescape/node-agent:v1 \
#    AFTER_IMAGE=quay.io/kubescape/node-agent:v2 \
#    ./dedup-bench.sh
#
#  For private (armo) chart:
#  HELM_MODE=armo ARMO_ACCOUNT=... ARMO_ACCESS_KEY=... \
#  ARMO_IMAGE_PULL_SECRET=... ARMO_SERVER=api-dev.armosec.io \
#  ./dedup-bench.sh quay.io/armosec/node-agent:v0.0.240 quay.io/armosec/node-agent:test
#
#  Estimated runtime: ~35 minutes
# =============================================================

CLUSTER_NAME="dedup-bench"
KUBESCAPE_NS="kubescape"
MONITORING_NS="monitoring"
HELM_MODE="${HELM_MODE:-kubescape}"  # "kubescape" (default) or "armo" (private chart)
LOAD_DURATION=600          # 10 minutes
WARMUP_SECONDS=120         # 2 minutes
METRICS_DURATION=10        # minutes (matches LOAD_DURATION, excludes warmup)
PROM_LOCAL_PORT=9090
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOAD_SIM_IMAGE="quay.io/armosec/load-simulator:v2"
OUTPUT_BASE="${OUTPUT_DIR:-${SCRIPT_DIR}/dedup-bench-output}"

PORT_FORWARD_PID=""

# ---------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------

log() { echo "==> [$(date +%H:%M:%S)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

split_image() {
    # Split image into repo and tag. Default tag to "latest".
    local image="$1"
    if [[ "$image" == *:* ]]; then
        echo "${image%:*}" "${image##*:}"
    else
        echo "$image" "latest"
    fi
}

# ---------------------------------------------------------------
#  check_prerequisites
# ---------------------------------------------------------------
check_prerequisites() {
    log "Checking prerequisites..."
    local missing=()
    for cmd in kind helm kubectl docker python3; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    [[ ${#missing[@]} -eq 0 ]] || die "Missing required tools: ${missing[*]}"

    # Set up Python venv with deps
    local venv_dir="${SCRIPT_DIR}/.venv"
    if [[ ! -d "$venv_dir" ]]; then
        log "Creating Python venv and installing dependencies..."
        python3 -m venv "$venv_dir"
        "$venv_dir/bin/pip" install -r "$SCRIPT_DIR/requirements.txt"
    fi
    # Use the venv python for the rest of the script
    export PATH="${venv_dir}/bin:${PATH}"

    local cpus
    cpus=$(nproc)
    if (( cpus < 8 )); then
        echo "WARNING: Host has $cpus CPUs (recommended >= 8). Results may be noisy."
    fi

    local mem_gb
    mem_gb=$(free -g | awk '/^Mem:/{print $2}')
    if (( mem_gb < 16 )); then
        echo "WARNING: Host has ${mem_gb}GB RAM (recommended >= 16). Results may be noisy."
    fi
}

# ---------------------------------------------------------------
#  create_kind_cluster (idempotent)
# ---------------------------------------------------------------
create_kind_cluster() {
    log "Creating kind cluster '$CLUSTER_NAME'..."
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true

    local tmpfile
    tmpfile=$(mktemp /tmp/kind-config-XXXX.yaml)
    cat > "$tmpfile" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        system-reserved: cpu=500m,memory=512Mi
- role: worker
EOF
    kind create cluster --name "$CLUSTER_NAME" --wait 5m --config "$tmpfile"
    rm -f "$tmpfile"
    log "Kind cluster ready."
}

# ---------------------------------------------------------------
#  install_prometheus
# ---------------------------------------------------------------
install_prometheus() {
    log "Installing Prometheus..."
    helm repo add --force-update prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo update
    helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
        --namespace "$MONITORING_NS" --create-namespace --wait --timeout 5m \
        --set grafana.enabled=false \
        --set alertmanager.enabled=false \
        --set prometheus.prometheusSpec.scrapeInterval=10s \
        --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false \
        --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false

    kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=prometheus \
        -n "$MONITORING_NS" --timeout=300s
    log "Prometheus ready."
}

# ---------------------------------------------------------------
#  install_kubescape / swap_image
# ---------------------------------------------------------------
_helm_install_kubescape() {
    local repo="$1" tag="$2"

    if [[ "$HELM_MODE" == "armo" ]]; then
        _helm_install_armo "$repo" "$tag"
    else
        _helm_install_kubescape_oss "$repo" "$tag"
    fi
}

_helm_install_kubescape_oss() {
    local repo="$1" tag="$2"
    helm repo add --force-update kubescape https://kubescape.github.io/helm-charts
    helm repo update
    helm upgrade --install kubescape kubescape/kubescape-operator \
        -n "$KUBESCAPE_NS" --create-namespace --wait --timeout 5m \
        --set clusterName="kind-${CLUSTER_NAME}" \
        --set capabilities.runtimeDetection=enable \
        --set capabilities.runtimeObservability=enable \
        --set capabilities.malwareDetection=disable \
        --set capabilities.prometheusExporter=enable \
        --set nodeAgent.config.prometheusExporter=enable \
        --set nodeAgent.serviceMonitor.enabled=true \
        --set nodeAgent.config.stdoutExporter=true \
        --set nodeAgent.config.httpExporterConfig=null \
        --set alertCRD.scopeClustered=true \
        --set nodeAgent.image.repository="$repo" \
        --set nodeAgent.image.tag="$tag" \
        --set nodeAgent.image.pullPolicy=IfNotPresent
}

_helm_install_armo() {
    local repo="$1" tag="$2"

    # Validate required env vars for armo mode
    : "${ARMO_ACCOUNT:?ARMO_ACCOUNT required for HELM_MODE=armo}"
    : "${ARMO_ACCESS_KEY:?ARMO_ACCESS_KEY required for HELM_MODE=armo}"
    : "${ARMO_IMAGE_PULL_SECRET:?ARMO_IMAGE_PULL_SECRET required for HELM_MODE=armo}"
    : "${ARMO_SERVER:?ARMO_SERVER required for HELM_MODE=armo}"

    helm repo add --force-update armosec https://armosec.github.io/helm-charts/
    helm repo update
    # Use IfNotPresent only when the image is pre-loaded into kind; otherwise Always
    local pull_policy="Always"
    if docker image inspect "${repo}:${tag}" &>/dev/null; then
        pull_policy="IfNotPresent"
    fi

    helm upgrade --install kubescape armosec/armosec-kubescape-operator \
        -n "$KUBESCAPE_NS" --create-namespace --wait --timeout 10m \
        --set kubescape-operator.account="${ARMO_ACCOUNT}" \
        --set kubescape-operator.accessKey="${ARMO_ACCESS_KEY}" \
        --set kubescape-operator.imagePullSecret.password="${ARMO_IMAGE_PULL_SECRET}" \
        --set kubescape-operator.server="${ARMO_SERVER}" \
        --set kubescape-operator.clusterName="kind-${CLUSTER_NAME}" \
        --set kubescape-operator.capabilities.runtimeDetection=enable \
        --set kubescape-operator.capabilities.runtimeObservability=enable \
        --set kubescape-operator.capabilities.malwareDetection=disable \
        --set kubescape-operator.capabilities.prometheusExporter=enable \
        --set kubescape-operator.nodeAgent.config.prometheusExporter=enable \
        --set kubescape-operator.nodeAgent.serviceMonitor.enabled=true \
        --set kubescape-operator.nodeAgent.config.stdoutExporter=true \
        --set kubescape-operator.nodeAgent.config.httpExporterConfig=null \
        --set kubescape-operator.alertCRD.scopeClustered=true \
        --set kubescape-operator.nodeAgent.image.repository="$repo" \
        --set kubescape-operator.nodeAgent.image.tag="$tag" \
        --set kubescape-operator.nodeAgent.image.pullPolicy="$pull_policy"
}

install_kubescape() {
    log "Installing Kubescape with node-agent $1:$2..."
    _helm_install_kubescape "$1" "$2"
    if ! kubectl wait --for=condition=Ready pod -l app.kubernetes.io/component=node-agent \
        -n "$KUBESCAPE_NS" --timeout=600s; then
        log "ERROR: node-agent pod did not become ready. Diagnostics:"
        kubectl get pods -n "$KUBESCAPE_NS" -o wide
        kubectl describe pod -l app.kubernetes.io/component=node-agent -n "$KUBESCAPE_NS" | tail -60
        kubectl logs -l app.kubernetes.io/component=node-agent -n "$KUBESCAPE_NS" --tail=40 2>/dev/null || true
        die "node-agent pod failed to become ready"
    fi
    log "Kubescape ready."
}

swap_image() {
    log "Swapping node-agent image to $1:$2..."
    _helm_install_kubescape "$1" "$2"
    kubectl rollout status daemonset/node-agent -n "$KUBESCAPE_NS" --timeout=600s
    log "Node-agent rollout complete."
}

# ---------------------------------------------------------------
#  load_image — preload into kind if available locally
# ---------------------------------------------------------------
load_image() {
    local image="$1"
    if docker image inspect "$image" &>/dev/null; then
        log "Loading $image into kind cluster..."
        kind load docker-image "$image" --name "$CLUSTER_NAME"
    else
        log "Image $image not found locally, assuming registry-pullable."
    fi
}

# ---------------------------------------------------------------
#  deploy / remove load simulator
# ---------------------------------------------------------------
deploy_load_simulator() {
    log "Deploying load simulator..."
    kubectl create namespace load-simulator --dry-run=client -o yaml | kubectl apply -f -

    cat <<'EOF' > /tmp/load-sim-config.yaml
cpuLoadMs: 500
numberParallelCPUs: 2
dnsRate: 2
execRate: 10
hardlinkRate: 10
httpRate: 100
networkRate: 10
openRate: 1000
symlinkRate: 10
EOF
    kubectl create configmap config --from-file=config.yaml=/tmp/load-sim-config.yaml \
        -n load-simulator --dry-run=client -o yaml | kubectl apply -f -

    kubectl apply -f "$SCRIPT_DIR/load-simulator/daemonset.yaml" -n load-simulator
    kubectl wait --for=condition=ready pod -l app=load-simulator \
        -n load-simulator --timeout=300s
    log "Load simulator running."
}

remove_load_simulator() {
    log "Removing load simulator..."
    kubectl delete namespace load-simulator --wait=true --timeout=120s 2>/dev/null || true
}

# ---------------------------------------------------------------
#  port-forward helpers
# ---------------------------------------------------------------
start_port_forward() {
    log "Starting Prometheus port-forward on :$PROM_LOCAL_PORT..."
    kubectl port-forward svc/prometheus-kube-prometheus-prometheus \
        "$PROM_LOCAL_PORT":9090 -n "$MONITORING_NS" &
    PORT_FORWARD_PID=$!

    # Wait for readiness
    local retries=30
    while (( retries > 0 )); do
        if curl -sf "http://localhost:$PROM_LOCAL_PORT/-/ready" &>/dev/null; then
            log "Prometheus port-forward ready."
            return 0
        fi
        sleep 1
        (( retries-- ))
    done
    die "Prometheus port-forward failed to become ready."
}

stop_port_forward() {
    if [[ -n "$PORT_FORWARD_PID" ]]; then
        kill "$PORT_FORWARD_PID" 2>/dev/null || true
        wait "$PORT_FORWARD_PID" 2>/dev/null || true
        PORT_FORWARD_PID=""
        log "Port-forward stopped."
    fi
}

# ---------------------------------------------------------------
#  collect_metrics
# ---------------------------------------------------------------
collect_metrics() {
    local output_dir="$1"
    mkdir -p "$output_dir"

    log "Collecting Prometheus metrics into $output_dir..."

    # Collect CPU/memory via existing PrometheusMetricsCollector
    OUTPUT_DIR="$output_dir" DURATION_TIME="$METRICS_DURATION" python3 -c "
import sys; sys.path.insert(0, '${SCRIPT_DIR}')
from get_data_from_prometheus import PrometheusMetricsCollector, PrometheusConfig
config = PrometheusConfig()
config.url = 'http://localhost:${PROM_LOCAL_PORT}'
config.rate_window = '1m'
collector = PrometheusMetricsCollector(config=config)
collector.run()
"

    # Collect dedup-specific and event counter metrics
    python3 -c "
import requests, json, os
from datetime import datetime, timedelta, timezone

url = 'http://localhost:${PROM_LOCAL_PORT}'
end = datetime.now(timezone.utc)
start = end - timedelta(minutes=${METRICS_DURATION})
queries = {
    'dedup_total': 'sum by (event_type, result) (increase(node_agent_dedup_events_total[${METRICS_DURATION}m]))',
    'events_total': '{__name__=~\"node_agent_(exec|open|dns|network|syscall|capability)_counter\"}',
    'rule_total': 'sum by (rule_id) (increase(node_agent_rule_counter[${METRICS_DURATION}m]))',
}
output_dir = '${output_dir}'
os.makedirs(output_dir, exist_ok=True)
for name, query in queries.items():
    try:
        resp = requests.get(f'{url}/api/v1/query', params={'query': query, 'time': end.isoformat()}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if data.get('status') != 'success':
            print(f'Warning: {name}: Prometheus returned status={data.get("status")}')
        with open(os.path.join(output_dir, f'{name}.json'), 'w') as f:
            json.dump(data, f, indent=2)
        print(f'Collected {name}')
    except Exception as e:
        print(f'Warning: {name}: {e}')
"

    log "Metrics collection complete."
}

# ---------------------------------------------------------------
#  cleanup (trap EXIT)
# ---------------------------------------------------------------
cleanup() {
    log "Cleaning up..."
    stop_port_forward
    remove_load_simulator
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    log "Done."
}

# ---------------------------------------------------------------
#  Main
# ---------------------------------------------------------------
main() {
    # Support both positional args and environment variables
    local before_image="${1:-${BEFORE_IMAGE:-}}"
    local after_image="${2:-${AFTER_IMAGE:-}}"

    if [[ -z "$before_image" || -z "$after_image" ]]; then
        echo "Usage: $0 <before-image> <after-image>"
        echo "  or:  BEFORE_IMAGE=... AFTER_IMAGE=... $0"
        echo ""
        echo "  e.g. $0 quay.io/kubescape/node-agent:baseline quay.io/kubescape/node-agent:dedup"
        exit 1
    fi

    local before_repo before_tag after_repo after_tag

    read -r before_repo before_tag <<< "$(split_image "$before_image")"
    read -r after_repo after_tag <<< "$(split_image "$after_image")"

    trap cleanup EXIT

    check_prerequisites

    rm -rf "$OUTPUT_BASE"
    mkdir -p "$OUTPUT_BASE/before" "$OUTPUT_BASE/after"

    # --- Cluster & infrastructure ---
    create_kind_cluster

    # Pre-pull load simulator image and load into kind to avoid pull timeouts
    if ! docker image inspect "$LOAD_SIM_IMAGE" &>/dev/null; then
        log "Pulling load simulator image..."
        docker pull "$LOAD_SIM_IMAGE"
    fi
    load_image "$LOAD_SIM_IMAGE"

    install_prometheus

    # --- BEFORE run ---
    log "===== BEFORE run: $before_image ====="
    load_image "$before_image"
    install_kubescape "$before_repo" "$before_tag"
    deploy_load_simulator

    log "Warming up (${WARMUP_SECONDS}s)..."
    sleep "$WARMUP_SECONDS"

    log "Load running for ${LOAD_DURATION}s..."
    sleep "$LOAD_DURATION"

    start_port_forward
    collect_metrics "$OUTPUT_BASE/before"
    stop_port_forward
    remove_load_simulator

    # --- AFTER run ---
    log "===== AFTER run: $after_image ====="
    load_image "$after_image"
    swap_image "$after_repo" "$after_tag"
    deploy_load_simulator

    log "Warming up (${WARMUP_SECONDS}s)..."
    sleep "$WARMUP_SECONDS"

    log "Load running for ${LOAD_DURATION}s..."
    sleep "$LOAD_DURATION"

    start_port_forward
    collect_metrics "$OUTPUT_BASE/after"
    stop_port_forward

    # --- Compare ---
    log "===== Comparison ====="
    python3 "$SCRIPT_DIR/compare-metrics.py" "$OUTPUT_BASE/before" "$OUTPUT_BASE/after"

    log "Results saved in $OUTPUT_BASE/"
    # cleanup via trap EXIT
}

main "$@"
