#!/usr/bin/env bash
#
# run-test-28.sh — Manual execution of Test_28_UserDefinedNetworkNeighborhood
#
# Applies user-defined NN, deploys curl, waits for AP to auto-learn,
# triggers allowed + unknown traffic, checks for alerts.
#
# Usage:
#   ./run-test-28.sh           # run the test
#   ./run-test-28.sh learn     # learn NN from scratch (debug)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERTMANAGER_URL="${ALERTMANAGER_URL:-http://localhost:9093}"
SCENARIO="${1:-test}"

# Ensure alertmanager port-forward is active.
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
  trap 'kill $ALERT_PF_PID 2>/dev/null || true' EXIT
fi

get_all_alerts() {
  local ns="$1"
  curl -s "$ALERTMANAGER_URL/api/v2/alerts" | \
    jq "[.[] | select(.labels.namespace==\"$ns\")]"
}

wait_for_pod() {
  local ns="$1"
  kubectl rollout status deployment/curl-fusioncore-deployment -n "$ns" --timeout=120s
}

get_pod() {
  local ns="$1"
  kubectl get pods -n "$ns" -l app=curl-fusioncore-28-1 \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# =================================================================
# Main test: apply NN manifest, deploy curl, trigger traffic, check alerts
# =================================================================
run_test() {
  local NS="t28-$(head -c4 /dev/urandom | xxd -p)"
  local NET="fusioncore-network-$NS"
  echo ""
  echo "=== Test 28: User-Defined NN  (ns=$NS, net=$NET) ==="

  kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

  # 1. Apply NN manifest with unique name
  sed -e "s/{{NAMESPACE}}/$NS/g" \
      -e "s/fusioncore-network/$NET/g" \
      "$SCRIPT_DIR/known-network-neighborhood.yaml" | kubectl apply -f -
  echo "  NN $NET created"

  # 2. Deploy curl with user-defined-network label
  sed "s/{{NETWORK_NAME}}/$NET/g" \
      "$SCRIPT_DIR/curl-user-network-deployment.yaml" | kubectl apply -n "$NS" -f -
  wait_for_pod "$NS"
  local POD; POD=$(get_pod "$NS")
  echo "  Pod: $POD"

  # 3. Wait for AP to auto-learn
  echo "  Waiting for AP to complete..."
  for i in $(seq 1 80); do
    AP_STATUS=$(kubectl get applicationprofiles -n "$NS" \
      -o jsonpath='{.items[0].metadata.annotations.kubescape\.io/status}' 2>/dev/null || true)
    [ "$AP_STATUS" = "completed" ] && break
    sleep 10
  done
  echo "  AP status: $AP_STATUS"

  # 4. Trigger traffic
  echo "  Triggering traffic..."
  echo "    nslookup fusioncore.ai (allowed)"
  kubectl exec -n "$NS" "$POD" -c curl -- nslookup fusioncore.ai 2>&1 || true
  echo "    curl fusioncore.ai (allowed)"
  kubectl exec -n "$NS" "$POD" -c curl -- curl -sm2 http://fusioncore.ai >/dev/null 2>&1 || true
  echo "    nslookup evil.example.com (unknown)"
  kubectl exec -n "$NS" "$POD" -c curl -- nslookup evil.example.com 2>&1 || true
  echo "    curl evil.example.com (unknown)"
  kubectl exec -n "$NS" "$POD" -c curl -- curl -sm2 http://evil.example.com >/dev/null 2>&1 || true

  echo "  Waiting 30s for alerts..."
  sleep 30

  # 5. Check alerts
  echo ""
  echo "  === All alerts in namespace $NS ==="
  ALERTS=$(get_all_alerts "$NS")
  ALERT_COUNT=$(echo "$ALERTS" | jq 'length')
  echo "$ALERTS" | jq -r '.[] | "  [\(.labels.rule_name)] container=\(.labels.container_name // "n/a")"'
  echo "  Total: $ALERT_COUNT"
  echo "  ======================================"

  if [ "$ALERT_COUNT" -eq 0 ]; then
    echo "  FAIL: expected at least one alert (R0005 for evil.example.com), got ZERO"
    echo "  Namespace $NS left for inspection"
    exit 1
  else
    echo "  PASS: got $ALERT_COUNT alert(s)"
    echo "  Cleanup: kubectl delete namespace $NS"
  fi
}

# =================================================================
# Learn scenario: no user-defined labels, learn NN from scratch
# =================================================================
run_learn() {
  local NS="t28-learn-$(head -c4 /dev/urandom | xxd -p)"
  echo ""
  echo "=== LEARN NN from scratch (ns=$NS) ==="

  kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
  kubectl apply -n "$NS" -f "$SCRIPT_DIR/curl-plain-deployment.yaml"
  wait_for_pod "$NS"
  local POD; POD=$(kubectl get pods -n "$NS" -l app=curl-fusioncore-28-0 \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  echo "  Pod: $POD"

  echo "  Triggering traffic during learning window..."
  kubectl exec -n "$NS" "$POD" -c curl -- nslookup fusioncore.ai 2>&1 || true
  kubectl exec -n "$NS" "$POD" -c curl -- curl -sm5 http://fusioncore.ai >/dev/null 2>&1 || true
  sleep 5
  kubectl exec -n "$NS" "$POD" -c curl -- nslookup fusioncore.ai 2>&1 || true
  kubectl exec -n "$NS" "$POD" -c curl -- curl -sm5 http://fusioncore.ai >/dev/null 2>&1 || true

  echo "  Waiting for NN to complete..."
  for i in $(seq 1 80); do
    NN_STATUS=$(kubectl get networkneighborhoods -n "$NS" \
      -o jsonpath='{.items[0].metadata.annotations.kubescape\.io/status}' 2>/dev/null || true)
    [ "$NN_STATUS" = "completed" ] && break
    sleep 10
  done
  echo "  NN status: $NN_STATUS"

  echo ""
  echo "  === Learned NetworkNeighborhood ==="
  kubectl get networkneighborhoods -n "$NS" -o yaml 2>&1
  echo "  ==================================="
  echo ""
  echo "  Namespace $NS left for inspection"
  echo "  Cleanup: kubectl delete namespace $NS"
}

case "$SCENARIO" in
  test)  run_test ;;
  learn) run_learn ;;
  *)
    echo "Usage: $0 [test|learn]"
    exit 1
    ;;
esac
