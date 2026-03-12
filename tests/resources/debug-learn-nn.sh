#!/usr/bin/env bash
#
# debug-learn-nn.sh — Deploy curl container without user-defined labels,
# trigger DNS+HTTP traffic, wait for NN to learn, dump the result.
#
# Usage:
#   ./debug-learn-nn.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="debug-nn-$(head -c4 /dev/urandom | xxd -p)"

echo "=== Creating namespace $NS ==="
kubectl create namespace "$NS"

echo "=== Deploying curl (no user-defined labels) ==="
kubectl apply -n "$NS" -f "$SCRIPT_DIR/curl-plain-deployment.yaml"
kubectl rollout status deployment/curl-fusioncore-deployment -n "$NS" --timeout=120s
POD=$(kubectl get pods -n "$NS" -l app=curl-fusioncore -o jsonpath='{.items[0].metadata.name}')
echo "Pod: $POD"

echo ""
echo "=== Checking available DNS tools ==="
echo "--- which nslookup ---"
kubectl exec -n "$NS" "$POD" -c curl -- which nslookup 2>&1 || echo "(not found)"
echo "--- which dig ---"
kubectl exec -n "$NS" "$POD" -c curl -- which dig 2>&1 || echo "(not found)"
echo "--- which host ---"
kubectl exec -n "$NS" "$POD" -c curl -- which host 2>&1 || echo "(not found)"
echo "--- busybox --list (dns-related) ---"
kubectl exec -n "$NS" "$POD" -c curl -- busybox --list 2>&1 | grep -iE 'nslookup|dig|host|wget|ping' || echo "(none found)"

echo ""
echo "=== Triggering DNS + network traffic ==="

echo "--- nslookup fusioncore.ai ---"
kubectl exec -n "$NS" "$POD" -c curl -- nslookup fusioncore.ai 2>&1 || true

echo "--- curl -sm5 http://fusioncore.ai ---"
kubectl exec -n "$NS" "$POD" -c curl -- curl -sm5 http://fusioncore.ai >/dev/null 2>&1 || true

echo "--- nslookup google.com ---"
kubectl exec -n "$NS" "$POD" -c curl -- nslookup google.com 2>&1 || true

echo "--- curl -sm5 http://google.com ---"
kubectl exec -n "$NS" "$POD" -c curl -- curl -sm5 http://google.com >/dev/null 2>&1 || true

sleep 5
echo "--- repeat: nslookup + curl fusioncore.ai ---"
kubectl exec -n "$NS" "$POD" -c curl -- nslookup fusioncore.ai 2>&1 || true
kubectl exec -n "$NS" "$POD" -c curl -- curl -sm5 http://fusioncore.ai >/dev/null 2>&1 || true

echo ""
echo "=== Waiting for NN to complete ==="
for i in $(seq 1 60); do
  NN_STATUS=$(kubectl get networkneighborhoods -n "$NS" \
    -o jsonpath='{.items[0].metadata.annotations.kubescape\.io/status}' 2>/dev/null || true)
  AP_STATUS=$(kubectl get applicationprofiles -n "$NS" \
    -o jsonpath='{.items[0].metadata.annotations.kubescape\.io/status}' 2>/dev/null || true)
  echo "  [$i] AP=$AP_STATUS  NN=$NN_STATUS"
  [ "$NN_STATUS" = "completed" ] && break
  sleep 10
done

echo ""
echo "========== Learned NetworkNeighborhood =========="
kubectl get networkneighborhoods -n "$NS" -o yaml 2>&1
echo "================================================="

echo ""
echo "========== Learned ApplicationProfile (execs) =========="
kubectl get applicationprofiles -n "$NS" \
  -o jsonpath='{.items[0].spec.containers[0].execs}' 2>&1 | python3 -m json.tool 2>/dev/null || \
  kubectl get applicationprofiles -n "$NS" \
  -o jsonpath='{.items[0].spec.containers[0].execs}' 2>&1
echo ""
echo "======================================================="

echo ""
echo "Namespace: $NS (left intact for inspection)"
echo "Cleanup:   kubectl delete namespace $NS"
