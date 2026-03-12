#!/usr/bin/env bash
#
# run-test-28.sh — Manual execution of Test_28_UserDefinedNetworkNeighborhood
#
# Exercises user-defined NetworkNeighborhood + ApplicationProfile labels.
# Covers: both labels, NN-only, and AP-only scenarios.
#
# Usage:
#   ./run-test-28.sh                  # run all subtests
#   ./run-test-28.sh both             # only the "both labels" scenario
#   ./run-test-28.sh nn-only          # only NN label (AP auto-learns)
#   ./run-test-28.sh profile-only     # only AP label (NN auto-learns)
#
# Requires: kubectl, curl, jq configured against a cluster with node-agent.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERTMANAGER_URL="${ALERTMANAGER_URL:-http://localhost:9093}"
SCENARIO="${1:-all}"

# Ensure alertmanager port-forward is active.
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm upgrade --install prometheus prometheus-community/kube-prometheus-stack --set grafana.enabled=false --namespace monitoring --create-namespace --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false,prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false --set prometheus.prometheusSpec.maximumStartupDurationSeconds=300 --wait --timeout 5m
# Check that the prometheus pod is running
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=prometheus -n monitoring --timeout=300s
if ! curl -s --max-time 2 "$ALERTMANAGER_URL/api/v2/alerts" >/dev/null 2>&1; then
  echo "Alertmanager not reachable at $ALERTMANAGER_URL — starting port-forward..."
  kubectl port-forward svc/alertmanager-operated 9093:9093 -n monitoring &
  ALERT_PF_PID=$!
  sleep 3
  if ! curl -s --max-time 2 "$ALERTMANAGER_URL/api/v2/alerts" >/dev/null 2>&1; then
    echo "ERROR: alertmanager still not reachable after port-forward (pid=$ALERT_PF_PID)"
    kill "$ALERT_PF_PID" 2>/dev/null || true
    exit 1
  fi
  echo "Alertmanager port-forward active (pid=$ALERT_PF_PID)"
  trap 'kill $ALERT_PF_PID 2>/dev/null || true' EXIT
fi

PASS=0; FAIL=0

pass()  { PASS=$((PASS+1)); echo "  PASS: $1"; }
fail()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

get_alerts() {
  local ns="$1" rule="$2" container="$3"
  curl -s "$ALERTMANAGER_URL/api/v2/alerts" | \
    jq -r "[.[] | select(
      .labels.alertname==\"KubescapeRuleViolated\" and
      .labels.namespace==\"$ns\" and
      .labels.rule_name==\"$rule\" and
      .labels.container_name==\"$container\")] | length"
}

wait_for_pod() {
  local ns="$1"
  kubectl rollout status deployment/curl-fusioncore-deployment -n "$ns" --timeout=120s
}

get_pod() {
  local ns="$1"
  kubectl get pods -n "$ns" -l app=curl-fusioncore \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# ---------------------------------------------------------------
# Create user-defined ApplicationProfile in a namespace.
# ---------------------------------------------------------------
create_profile() {
  local ns="$1" name="$2"
  cat <<EOF | kubectl apply -f -
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata:
  name: "$name"
  namespace: "$ns"
spec:
  architectures: ["amd64"]
  containers:
  - name: curl
    execs:
    - path: /bin/cat
      args: ["/bin/cat"]
    - path: /usr/bin/curl
      args: ["/usr/bin/curl"]
    opens:
    - path: /etc/hosts
      flags: ["O_RDONLY"]
    - path: /etc/ld.so.cache
      flags: ["O_RDONLY","O_CLOEXEC"]
EOF
}

# ---------------------------------------------------------------
# Create user-defined NetworkNeighborhood in a namespace.
# No "kubescape.io/managed-by: User" — the pod label is the sole link.
# ---------------------------------------------------------------
create_network() {
  local ns="$1" name="$2"
  cat <<EOF | kubectl apply -f -
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: NetworkNeighborhood
metadata:
  name: "$name"
  namespace: "$ns"
spec:
  matchLabels:
    app: curl-fusioncore
  containers:
  - name: curl
    ingress: []
    egress:
    - identifier: fusioncore-ai
      type: external
      dnsNames: ["fusioncore.ai."]
      ipAddress: "162.0.217.171"
      ports:
      - name: TCP-80
        protocol: TCP
        port: 80
      - name: TCP-443
        protocol: TCP
        port: 443
      - name: UDP-53
        protocol: UDP
        port: 53
    - identifier: cluster-dns
      type: internal
      dnsNames: ["kubernetes.default.svc.cluster.local."]
      ports:
      - name: UDP-53
        protocol: UDP
        port: 53
EOF
}

# ---------------------------------------------------------------
# Verify the auto-learned NetworkNeighborhood contains expected DNS.
# The auto-learned NN name starts with "replicaset-".
# ---------------------------------------------------------------
verify_learned_nn() {
  local ns="$1" expected_dns="$2"
  echo "  Verifying auto-learned NetworkNeighborhood contains ${expected_dns}..."

  local nn_json
  nn_json=$(kubectl get networkneighborhoods -n "$ns" -o json 2>/dev/null | \
    jq '[.items[] | select(.metadata.name | startswith("replicaset-"))] | .[0]' 2>/dev/null)

  if [ -z "$nn_json" ] || [ "$nn_json" = "null" ]; then
    fail "no auto-learned NetworkNeighborhood found in ns $ns"
    return
  fi

  local nn_name
  nn_name=$(echo "$nn_json" | jq -r '.metadata.name')

  # DNS names in the NN have a trailing dot (e.g. "fusioncore.ai.")
  if echo "$nn_json" | jq -e \
    ".spec.containers[]?.egress[]?.dnsNames[]? | select(startswith(\"${expected_dns}\"))" \
    >/dev/null 2>&1; then
    pass "learned NN ($nn_name) contains ${expected_dns}"
  else
    local actual
    actual=$(echo "$nn_json" | jq -r \
      '[.spec.containers[]?.egress[]?.dnsNames[]?] | join(", ")' 2>/dev/null)
    fail "learned NN ($nn_name) missing ${expected_dns} (has: ${actual:-empty})"
  fi
}

# ---------------------------------------------------------------
# Wait for the auto-learned NetworkNeighborhood to complete.
# ---------------------------------------------------------------
wait_for_learned_nn() {
  local ns="$1"
  echo "  Waiting for auto-learned NetworkNeighborhood to complete..."
  local status=""
  for i in $(seq 1 80); do
    status=$(kubectl get networkneighborhoods -n "$ns" -o json 2>/dev/null | \
      jq -r '.items[] | select(.metadata.name | startswith("replicaset-")) | .metadata.annotations["kubescape.io/status"]' \
      2>/dev/null | head -1 || true)
    [ "$status" = "completed" ] && break
    sleep 10
  done
  if [ "$status" = "completed" ]; then
    echo "  Auto-learned NN completed"
  else
    echo "  WARNING: auto-learned NN status=${status:-not found}"
  fi
}

# =================================================================
# Scenario: BOTH user-defined AP + NN
# =================================================================
run_both() {
  local NS="t28-both-$(head -c4 /dev/urandom | xxd -p)"
  echo ""
  echo "=== Scenario: BOTH user-defined AP + NN  (ns=$NS) ==="

  kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
  create_profile "$NS" fusioncore-profile
  create_network "$NS" fusioncore-network
  kubectl apply -n "$NS" -f "$SCRIPT_DIR/curl-both-user-defined-deployment.yaml"
  wait_for_pod "$NS"
  local POD; POD=$(get_pod "$NS")
  echo "Pod: $POD — sleeping 30s for node-agent to pick up resources..."
  sleep 30

  # --- a. Allowed activity → no alerts ---
  echo "  (a) Allowed exec + allowed DNS..."
  kubectl exec -n "$NS" "$POD" -c curl -- cat /etc/hosts >/dev/null 2>&1 || true
  kubectl exec -n "$NS" "$POD" -c curl -- \
    curl -sm2 http://fusioncore.ai >/dev/null 2>&1 || true
  sleep 30

  local EXEC_ALERTS; EXEC_ALERTS=$(get_alerts "$NS" "Unexpected process launched" curl)
  local DNS_ALERTS;  DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" curl)
  [ "$EXEC_ALERTS" -eq 0 ] && pass "no R0001 for allowed exec" || fail "R0001 fired ($EXEC_ALERTS) for allowed exec"
  [ "$DNS_ALERTS" -eq 0 ]  && pass "no R0005 for allowed DNS"  || fail "R0005 fired ($DNS_ALERTS) for allowed DNS"

  # --- b. Unknown exec → R0001 ---
  echo "  (b) Unknown exec (ls)..."
  kubectl exec -n "$NS" "$POD" -c curl -- ls / >/dev/null 2>&1 || true
  sleep 30

  EXEC_ALERTS=$(get_alerts "$NS" "Unexpected process launched" curl)
  [ "$EXEC_ALERTS" -gt 0 ] && pass "R0001 fired for unknown exec" || fail "no R0001 for unknown exec"

  # --- c. Unknown DNS → R0005 ---
  echo "  (c) Unknown DNS (evil.example.com)..."
  kubectl exec -n "$NS" "$POD" -c curl -- \
    curl -sm2 http://evil.example.com >/dev/null 2>&1 || true
  sleep 30

  DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" curl)
  [ "$DNS_ALERTS" -gt 0 ] && pass "R0005 fired for unknown DNS" || fail "no R0005 for unknown DNS"

  echo "  Cleanup: kubectl delete namespace $NS"
}

# =================================================================
# Scenario: NN-only (AP auto-learns)
# =================================================================
run_nn_only() {
  local NS="t28-nn-$(head -c4 /dev/urandom | xxd -p)"
  echo ""
  echo "=== Scenario: NN-only (AP auto-learns)  (ns=$NS) ==="

  kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
  create_network "$NS" fusioncore-network
  kubectl apply -n "$NS" -f "$SCRIPT_DIR/curl-user-network-deployment.yaml"
  wait_for_pod "$NS"
  local POD; POD=$(get_pod "$NS")
  echo "Pod: $POD"

  # Generate traffic during learning phase so the auto-learned NN captures it.
  echo "  Generating fusioncore.ai traffic during learning phase..."
  kubectl exec -n "$NS" "$POD" -c curl -- curl -sm5 http://fusioncore.ai >/dev/null 2>&1 || true

  echo "  Waiting for ApplicationProfile to complete (auto-learn)..."
  for i in $(seq 1 80); do
    AP_STATUS=$(kubectl get applicationprofiles -n "$NS" \
      -o jsonpath='{.items[0].metadata.annotations.kubescape\.io/status}' 2>/dev/null || true)
    [ "$AP_STATUS" = "completed" ] && break
    sleep 10
  done
  [ "$AP_STATUS" = "completed" ] && echo "  AP completed" || echo "  WARNING: AP status=$AP_STATUS"

  # Wait for auto-learned NN and verify it captured fusioncore.ai.
  wait_for_learned_nn "$NS"
  verify_learned_nn "$NS" "fusioncore.ai"

  # --- d. Allowed DNS → no R0005 ---
  echo "  (d) Allowed DNS (fusioncore.ai)..."
  kubectl exec -n "$NS" "$POD" -c curl -- \
    curl -sm2 http://fusioncore.ai >/dev/null 2>&1 || true
  sleep 30

  local DNS_ALERTS; DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" curl)
  [ "$DNS_ALERTS" -eq 0 ] && pass "no R0005 for allowed DNS (NN-only)" || fail "R0005 fired ($DNS_ALERTS) for allowed DNS (NN-only)"

  # --- e. Unknown DNS → R0005 ---
  echo "  (e) Unknown DNS (evil.example.com)..."
  kubectl exec -n "$NS" "$POD" -c curl -- \
    curl -sm2 http://evil.example.com >/dev/null 2>&1 || true
  sleep 30

  DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" curl)
  [ "$DNS_ALERTS" -gt 0 ] && pass "R0005 fired for unknown DNS (NN-only)" || fail "no R0005 for unknown DNS (NN-only)"

  echo "  Cleanup: kubectl delete namespace $NS"
}

# =================================================================
# Scenario: AP-only (NN auto-learns)
# =================================================================
run_profile_only() {
  local NS="t28-ap-$(head -c4 /dev/urandom | xxd -p)"
  echo ""
  echo "=== Scenario: AP-only (NN auto-learns)  (ns=$NS) ==="

  kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
  create_profile "$NS" curl-regex-profile
  kubectl apply -n "$NS" -f "$SCRIPT_DIR/curl-user-profile-deployment.yaml"

  echo "  Waiting for deployment..."
  kubectl rollout status deployment/curl-deployment -n "$NS" --timeout=120s
  local POD; POD=$(kubectl get pods -n "$NS" -l app=curl \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  echo "  Pod: $POD"

  # Generate traffic during learning phase so the auto-learned NN captures it.
  echo "  Generating fusioncore.ai traffic during learning phase..."
  kubectl exec -n "$NS" "$POD" -c curl -- curl -sm5 http://fusioncore.ai >/dev/null 2>&1 || true

  echo "  Waiting for NetworkNeighborhood to complete (auto-learn)..."
  for i in $(seq 1 80); do
    NN_STATUS=$(kubectl get networkneighborhoods -n "$NS" \
      -o jsonpath='{.items[0].metadata.annotations.kubescape\.io/status}' 2>/dev/null || true)
    [ "$NN_STATUS" = "completed" ] && break
    sleep 10
  done
  [ "$NN_STATUS" = "completed" ] && echo "  NN completed" || echo "  WARNING: NN status=$NN_STATUS"

  # Verify the auto-learned NN captured the fusioncore.ai traffic.
  verify_learned_nn "$NS" "fusioncore.ai"

  # --- f. Unknown DNS → R0005 (NN was auto-learned, evil.example.com not in it) ---
  echo "  (f) Unknown DNS (evil.example.com)..."
  kubectl exec -n "$NS" "$POD" -c curl -- \
    curl -sm2 http://evil.example.com >/dev/null 2>&1 || true
  sleep 30

  local DNS_ALERTS; DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" curl)
  [ "$DNS_ALERTS" -gt 0 ] && pass "R0005 fired for unknown DNS (AP-only)" || fail "no R0005 for unknown DNS (AP-only)"

  echo "  Cleanup: kubectl delete namespace $NS"
}

# =================================================================
# Main
# =================================================================
echo "=== Test 28: User-Defined Network Neighborhood ==="
echo "Alertmanager: $ALERTMANAGER_URL"

case "$SCENARIO" in
  both)         run_both ;;
  nn-only)      run_nn_only ;;
  profile-only) run_profile_only ;;
  all)
    run_both
    run_nn_only
    run_profile_only
    ;;
  *)
    echo "Unknown scenario: $SCENARIO"
    echo "Usage: $0 [all|both|nn-only|profile-only]"
    exit 1
    ;;
esac

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
