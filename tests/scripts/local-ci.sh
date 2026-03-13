#!/usr/bin/env bash
# local-ci.sh — exact local mirror of .github/workflows/component-tests.yaml
#
# Usage:
#   ./tests/scripts/local-ci.sh                          # full run: cluster setup + deploy + all tests
#   ./tests/scripts/local-ci.sh --deploy-only             # stop after helm install (skip tests)
#   ./tests/scripts/local-ci.sh --test-only Test_27       # skip setup, just run one test
#   ./tests/scripts/local-ci.sh Test_27                   # full run, single test
#   ./tests/scripts/local-ci.sh Test_01 Test_27           # full run, multiple tests
#
# Differences from CI:
#   - Uses ~/go/bin/kind (v0.31.0) instead of downloading kind
#   - Uses existing kubectl instead of downloading it
#   - Builds Docker images locally + kind load instead of pulling from ghcr.io
#   - Storage is built from ../storage (local replace for go.mod)
#   - Node-agent privileged=true for Kind clusters
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STORAGE_ROOT="$(cd "$REPO_ROOT/../storage" && pwd)"
KIND="${HOME}/go/bin/kind"
KIND_CLUSTER="integration-test"
NAMESPACE="kubescape"
TAG="local-test"

cd "$REPO_ROOT"

# ── parse args ────────────────────────────────────────────────────────────────
DEPLOY_ONLY=false
TEST_ONLY=false
TESTS=()

for arg in "$@"; do
  case "$arg" in
    --deploy-only) DEPLOY_ONLY=true ;;
    --test-only)   TEST_ONLY=true ;;
    Test_*)        TESTS+=("$arg") ;;
  esac
done

log() { echo "[$(date +%H:%M:%S)] $*"; }

# ── step 1: kind cluster ─────────────────────────────────────────────────────
# CI: curl kind, ./kind create cluster, download kubectl
setup_cluster() {
  if $KIND get clusters 2>/dev/null | grep -q "^${KIND_CLUSTER}$"; then
    log "Kind cluster '${KIND_CLUSTER}' already exists, reusing"
  else
    log "Creating Kind cluster '${KIND_CLUSTER}'"
    $KIND create cluster --name "$KIND_CLUSTER"
  fi
  kubectl cluster-info --context "kind-${KIND_CLUSTER}" >/dev/null 2>&1 \
    || { log "ERROR: cluster unreachable"; exit 1; }
}

# ── step 2: install prometheus ────────────────────────────────────────────────
# CI: helm repo add + helm upgrade --install prometheus
install_prometheus() {
  if kubectl get ns monitoring >/dev/null 2>&1 && \
     kubectl get pods -n monitoring -l app.kubernetes.io/name=prometheus -o name 2>/dev/null | grep -q .; then
    log "Prometheus already installed, skipping"
  else
    log "Installing Prometheus"
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 2>/dev/null || true
    helm repo update
    helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
      --set grafana.enabled=false \
      --namespace monitoring --create-namespace \
      --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false,prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
      --set prometheus.prometheusSpec.maximumStartupDurationSeconds=300 \
      --wait --timeout 5m
  fi
  kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=prometheus -n monitoring --timeout=300s
}

# ── step 3: build + load images ──────────────────────────────────────────────
# CI: pulls from ghcr.io. Locally: docker build + kind load.
build_and_load_images() {
  log "Checking disk space"
  df -h / | tail -1

  # Storage
  log "Building storage image from ${STORAGE_ROOT}"
  docker build -f "${STORAGE_ROOT}/build/Dockerfile" \
    -t "ghcr.io/k8sstormcenter/storage:${TAG}" \
    "${STORAGE_ROOT}"

  # Node-agent: add local storage replace, vendor, build
  log "Setting up node-agent go.mod with local storage replace"
  go mod edit -replace "github.com/kubescape/storage=${STORAGE_ROOT}"
  go mod tidy
  go mod vendor

  log "Building node-agent image"
  docker build -f build/Dockerfile \
    -t "ghcr.io/k8sstormcenter/node-agent:${TAG}" \
    --build-arg image_version="${TAG}" .

  # Clean up Docker build cache
  docker builder prune --filter until=1h -f >/dev/null 2>&1 || true
  docker image prune -f >/dev/null 2>&1 || true

  # Drop the local replace (not committed)
  go mod edit -dropreplace "github.com/kubescape/storage"

  log "Loading images into Kind"
  $KIND load docker-image "ghcr.io/k8sstormcenter/storage:${TAG}" --name "$KIND_CLUSTER"
  $KIND load docker-image "ghcr.io/k8sstormcenter/node-agent:${TAG}" --name "$KIND_CLUSTER"

  log "Checking disk space after build"
  df -h / | tail -1
}

# ── step 4: helm install kubescape ────────────────────────────────────────────
# CI: helm upgrade --install kubescape ./tests/chart --set ...
install_kubescape() {
  log "Installing kubescape chart (storage=${TAG}, node-agent=${TAG})"
  helm upgrade --install kubescape ./tests/chart \
    --set clusterName="$(kubectl config current-context)" \
    --set nodeAgent.image.tag="${TAG}" \
    --set nodeAgent.image.repository=ghcr.io/k8sstormcenter/node-agent \
    --set nodeAgent.image.pullPolicy=Never \
    --set storage.image.tag="${TAG}" \
    --set storage.image.pullPolicy=Never \
    --set nodeAgent.privileged=true \
    -n "$NAMESPACE" --create-namespace --wait --timeout 5m \
    --disable-openapi-validation

  kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=node-agent -n "$NAMESPACE" --timeout=300s
  kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=storage -n "$NAMESPACE" --timeout=300s
  sleep 5
}

# ── step 5: port forwarding ──────────────────────────────────────────────────
# CI: ./tests/scripts/port-forward.sh
start_port_forwards() {
  log "Setting up port forwarding"
  # Kill stale port-forwards
  pkill -f 'kubectl port-forward.*alertmanager-operated' 2>/dev/null || true
  pkill -f 'kubectl port-forward.*prometheus-kube-prometheus' 2>/dev/null || true
  sleep 1
  "${SCRIPT_DIR}/port-forward.sh"
}

# ── step 6: run tests ────────────────────────────────────────────────────────
# CI: cd tests && go test -v ./... -run ${{ matrix.test }} --timeout=20m --tags=component
run_tests() {
  local test_pattern="${1:-}"

  # CI: Update storage dependency (go mod edit -replace ...)
  # Locally: same replace so test code compiles against fork storage
  log "Applying storage replace for test compilation"
  go mod edit -replace "github.com/kubescape/storage=${STORAGE_ROOT}"
  go mod tidy
  go mod vendor

  if [[ -n "$test_pattern" ]]; then
    log "Running test: ${test_pattern}"
    cd tests && CGO_ENABLED=0 go test -v ./... -run "${test_pattern}" --timeout=20m --tags=component; cd ..
  else
    log "Running all component tests"
    cd tests && CGO_ENABLED=0 go test -v ./... --timeout=20m --tags=component; cd ..
  fi
}

# ── step 7: collect logs ─────────────────────────────────────────────────────
# CI: kubectl logs ... node-agent + storage
print_logs() {
  log "=== Node agent logs ==="
  kubectl logs "$(kubectl get pods -n "$NAMESPACE" -o name | grep node-agent)" -n "$NAMESPACE" -c node-agent --tail=100 2>/dev/null || true
  echo "-----------------------------------------"
  log "=== Storage logs ==="
  kubectl logs "$(kubectl get pods -n "$NAMESPACE" -o name | grep storage)" -n "$NAMESPACE" --tail=50 2>/dev/null || true
}

# ── main ──────────────────────────────────────────────────────────────────────
if $TEST_ONLY; then
  # Just run the test(s), assume cluster + deploy are already done
  start_port_forwards
  if [[ ${#TESTS[@]} -gt 0 ]]; then
    for t in "${TESTS[@]}"; do run_tests "$t"; done
  else
    run_tests ""
  fi
  print_logs
  exit 0
fi

setup_cluster
install_prometheus
build_and_load_images
install_kubescape

if $DEPLOY_ONLY; then
  log "Deploy complete. Pods:"
  kubectl get pods -n "$NAMESPACE" -o wide
  exit 0
fi

start_port_forwards

# Run specified tests or all
set +e
if [[ ${#TESTS[@]} -gt 0 ]]; then
  for t in "${TESTS[@]}"; do run_tests "$t"; done
else
  run_tests ""
fi
TEST_EXIT=$?
set -e

print_logs

if [[ "$TEST_EXIT" -eq 0 ]]; then
  log "All tests passed"
else
  log "Tests finished with exit code ${TEST_EXIT}"
fi
exit $TEST_EXIT
