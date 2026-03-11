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
  kubectl rollout status deployment/nginx-fusioncore-deployment -n "$ns" --timeout=120s
}

get_pod() {
  local ns="$1"
  kubectl get pods -n "$ns" -l app=nginx-fusioncore \
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
  - name: nginx
    execs:
    - path: /bin/cat
      args: ["/bin/cat"]
    - path: /usr/bin/wget
      args: ["/usr/bin/wget"]
    opens:
    - path: /etc/nginx/nginx.conf
      flags: ["O_RDONLY"]
    - path: /etc/ld.so.cache
      flags: ["O_RDONLY","O_CLOEXEC"]
EOF
}

# ---------------------------------------------------------------
# Create user-defined NetworkNeighborhood in a namespace.
# ---------------------------------------------------------------
create_network() {
  local ns="$1" name="$2"
  cat <<EOF | kubectl apply -f -
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: NetworkNeighborhood
metadata:
  name: "$name"
  namespace: "$ns"
  annotations:
    kubescape.io/status: completed
    kubescape.io/completion: complete
spec:
  matchLabels:
    app: nginx-fusioncore
  containers:
  - name: nginx
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
  kubectl apply -n "$NS" -f "$SCRIPT_DIR/nginx-both-user-defined-deployment.yaml"
  wait_for_pod "$NS"
  local POD; POD=$(get_pod "$NS")
  echo "Pod: $POD — sleeping 30s for node-agent to pick up resources..."
  sleep 30

  # --- a. Allowed activity → no alerts ---
  echo "  (a) Allowed exec + allowed DNS..."
  kubectl exec -n "$NS" "$POD" -c nginx -- cat /etc/nginx/nginx.conf >/dev/null 2>&1 || true
  kubectl exec -n "$NS" "$POD" -c nginx -- \
    wget --spider -T 2 -t 1 http://fusioncore.ai 2>/dev/null || true
  sleep 30

  local EXEC_ALERTS; EXEC_ALERTS=$(get_alerts "$NS" "Unexpected process launched" nginx)
  local DNS_ALERTS;  DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" nginx)
  [ "$EXEC_ALERTS" -eq 0 ] && pass "no R0001 for allowed exec" || fail "R0001 fired ($EXEC_ALERTS) for allowed exec"
  [ "$DNS_ALERTS" -eq 0 ]  && pass "no R0005 for allowed DNS"  || fail "R0005 fired ($DNS_ALERTS) for allowed DNS"

  # --- b. Unknown exec → R0001 ---
  echo "  (b) Unknown exec (ls)..."
  kubectl exec -n "$NS" "$POD" -c nginx -- ls / >/dev/null 2>&1 || true
  sleep 30

  EXEC_ALERTS=$(get_alerts "$NS" "Unexpected process launched" nginx)
  [ "$EXEC_ALERTS" -gt 0 ] && pass "R0001 fired for unknown exec" || fail "no R0001 for unknown exec"

  # --- c. Unknown DNS → R0005 ---
  echo "  (c) Unknown DNS (evil.example.com)..."
  kubectl exec -n "$NS" "$POD" -c nginx -- \
    wget --spider -T 2 -t 1 http://evil.example.com 2>/dev/null || true
  sleep 30

  DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" nginx)
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
  kubectl apply -n "$NS" -f "$SCRIPT_DIR/nginx-user-network-deployment.yaml"
  wait_for_pod "$NS"
  local POD; POD=$(get_pod "$NS")
  echo "Pod: $POD"

  echo "  Waiting for ApplicationProfile to complete (auto-learn)..."
  for i in $(seq 1 80); do
    AP_STATUS=$(kubectl get applicationprofiles -n "$NS" \
      -o jsonpath='{.items[0].metadata.annotations.kubescape\.io/status}' 2>/dev/null || true)
    [ "$AP_STATUS" = "completed" ] && break
    sleep 10
  done
  [ "$AP_STATUS" = "completed" ] && echo "  AP completed" || echo "  WARNING: AP status=$AP_STATUS"
  sleep 10

  # --- d. Allowed DNS → no R0005 ---
  echo "  (d) Allowed DNS (fusioncore.ai)..."
  kubectl exec -n "$NS" "$POD" -c nginx -- \
    wget --spider -T 2 -t 1 http://fusioncore.ai 2>/dev/null || true
  sleep 30

  local DNS_ALERTS; DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" nginx)
  [ "$DNS_ALERTS" -eq 0 ] && pass "no R0005 for allowed DNS (NN-only)" || fail "R0005 fired ($DNS_ALERTS) for allowed DNS (NN-only)"

  # --- e. Unknown DNS → R0005 ---
  echo "  (e) Unknown DNS (evil.example.com)..."
  kubectl exec -n "$NS" "$POD" -c nginx -- \
    wget --spider -T 2 -t 1 http://evil.example.com 2>/dev/null || true
  sleep 30

  DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" nginx)
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
  create_profile "$NS" nginx-regex-profile
  kubectl apply -n "$NS" -f "$SCRIPT_DIR/nginx-user-profile-deployment.yaml"

  echo "  Waiting for deployment..."
  kubectl rollout status deployment/nginx-deployment -n "$NS" --timeout=120s
  local POD; POD=$(kubectl get pods -n "$NS" -l app=nginx \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  echo "  Pod: $POD"

  echo "  Waiting for NetworkNeighborhood to complete (auto-learn)..."
  for i in $(seq 1 80); do
    NN_STATUS=$(kubectl get networkneighborhoods -n "$NS" \
      -o jsonpath='{.items[0].metadata.annotations.kubescape\.io/status}' 2>/dev/null || true)
    [ "$NN_STATUS" = "completed" ] && break
    sleep 10
  done
  [ "$NN_STATUS" = "completed" ] && echo "  NN completed" || echo "  WARNING: NN status=$NN_STATUS"
  sleep 10

  # --- f. Unknown DNS → R0005 (NN was auto-learned, evil.example.com not in it) ---
  echo "  (f) Unknown DNS (evil.example.com)..."
  kubectl exec -n "$NS" "$POD" -c nginx -- \
    wget --spider -T 2 -t 1 http://evil.example.com 2>/dev/null || true
  sleep 30

  local DNS_ALERTS; DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" nginx)
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
