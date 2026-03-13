#!/usr/bin/env bash
#
# test-28-iterate.sh — Self-contained test for user-defined NN alerts
#
# Prerequisites:
#   - R0011 must be enabled with isTriggerAlert=true in the Rules CRD
#   - R0005 should have isTriggerAlert=true for DNS alerts
#   - Alertmanager port-forward active on localhost:9093
#
# Usage: ./test-28-iterate.sh
#
set -euo pipefail

ALERTMANAGER_URL="${ALERTMANAGER_URL:-http://localhost:9093}"
NA_POD=$(kubectl get pods -n kubescape -l app=node-agent -o jsonpath='{.items[0].metadata.name}')

# Ensure alertmanager reachable
if ! curl -s --max-time 2 "$ALERTMANAGER_URL/api/v2/alerts" >/dev/null 2>&1; then
  echo "ERROR: alertmanager not reachable at $ALERTMANAGER_URL"
  exit 1
fi

get_alerts() {
  local ns="$1"
  curl -s "$ALERTMANAGER_URL/api/v2/alerts" | jq "[.[] | select(.labels.namespace==\"$ns\")]"
}

cleanup_ns() {
  kubectl delete namespace "$1" --wait=false 2>/dev/null || true
}

# ================================================================
# Ensure R0005 and R0011 are enabled with isTriggerAlert=true
# ================================================================
echo "Patching rules: R0005 isTriggerAlert=true, R0011 enabled+isTriggerAlert=true"
kubectl get rules -n kubescape default-rules -o json | jq '
  .spec.rules = [
    .spec.rules[] |
    if .id == "R0005" then .isTriggerAlert = true
    elif .id == "R0011" then .enabled = true | .isTriggerAlert = true
    else .
    end
  ]
' | kubectl apply -f - >/dev/null 2>&1
echo "  Done"

# ================================================================
# TEST: User-defined AP + NN → R0011 for anomalous TCP egress
# ================================================================
NS="t28-$(head -c4 /dev/urandom | xxd -p)"
echo ""
echo "============================================================"
echo "TEST: User-defined AP + NN → R0011 Unexpected Egress Traffic"
echo "  ns=$NS"
echo "============================================================"

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

# Create user-defined ApplicationProfile
cat <<EOF | kubectl apply -f -
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata:
  name: nginx-ap
  namespace: "$NS"
  annotations:
    kubescape.io/managed-by: User
    kubescape.io/status: completed
    kubescape.io/completion: complete
  labels:
    kubescape.io/workload-api-group: apps
    kubescape.io/workload-api-version: v1
    kubescape.io/workload-kind: Deployment
    kubescape.io/workload-name: nginx-28
    kubescape.io/workload-namespace: "$NS"
spec:
  containers:
  - name: nginx
    capabilities: []
    execs:
    - path: /usr/sbin/nginx
    - path: /usr/bin/curl
    opens: []
    syscalls:
    - socket
    - connect
    - sendto
    - recvfrom
    - read
    - write
    - close
    - openat
    - mmap
    - mprotect
    - munmap
    - fcntl
    - ioctl
    - poll
    - epoll_create1
    - epoll_ctl
    - epoll_wait
    - bind
    - listen
    - accept4
    - getsockopt
    - setsockopt
    - getsockname
    - getpid
    - fstat
    - rt_sigaction
    - rt_sigprocmask
    - writev
EOF
echo "  AP nginx-ap created"

# Create user-defined NN allowing only fusioncore.ai on TCP/80
cat <<EOF | kubectl apply -f -
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: NetworkNeighborhood
metadata:
  name: nginx-nn
  namespace: "$NS"
  annotations:
    kubescape.io/managed-by: User
    kubescape.io/status: completed
    kubescape.io/completion: complete
  labels:
    kubescape.io/workload-api-group: apps
    kubescape.io/workload-api-version: v1
    kubescape.io/workload-kind: Deployment
    kubescape.io/workload-name: nginx-28
    kubescape.io/workload-namespace: "$NS"
spec:
  matchLabels:
    app: nginx-28
  containers:
  - name: nginx
    ingress: []
    egress:
    - dns: fusioncore.ai.
      dnsNames:
      - fusioncore.ai.
      identifier: fusioncore-egress
      ipAddress: "162.0.217.171"
      ports:
      - name: TCP-80
        port: 80
        protocol: TCP
      type: external
EOF
echo "  NN nginx-nn created"

# Deploy nginx with BOTH user-defined labels
cat <<EOF | kubectl apply -n "$NS" -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-28
  labels:
    app: nginx-28
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx-28
  template:
    metadata:
      labels:
        app: nginx-28
        kubescape.io/user-defined-network: nginx-nn
        kubescape.io/user-defined-profile: nginx-ap
    spec:
      containers:
      - name: nginx
        image: nginx:1.25.5
        ports:
        - containerPort: 80
EOF

kubectl rollout status deployment/nginx-28 -n "$NS" --timeout=120s
POD=$(kubectl get pods -n "$NS" -l app=nginx-28 -o jsonpath='{.items[0].metadata.name}')
echo "  Pod: $POD"

# Wait for profiles to load
echo "  Waiting for profiles to load..."
for i in $(seq 1 10); do
  GOT_NN=$(kubectl logs "$NA_POD" -n kubescape -c node-agent --since=30s 2>&1 \
    | grep -c "added user-defined network neighborhood" || true)
  GOT_AP=$(kubectl logs "$NA_POD" -n kubescape -c node-agent --since=30s 2>&1 \
    | grep -c "added user-defined application profile\|user defined profile" || true)
  echo "    NN=$GOT_NN AP=$GOT_AP"
  [ "$GOT_NN" -gt 0 ] && [ "$GOT_AP" -gt 0 ] && break
  sleep 3
done

# Trigger anomalous TCP egress (R0011)
echo ""
echo "  [anomaly] curl -sm5 http://8.8.8.8 (NOT in NN egress)"
kubectl exec -n "$NS" "$POD" -c nginx -- curl -sm5 http://8.8.8.8 2>&1 || true
echo "  [anomaly] curl -sm5 http://1.1.1.1 (NOT in NN egress)"
kubectl exec -n "$NS" "$POD" -c nginx -- curl -sm5 http://1.1.1.1 2>&1 || true

# Poll for alerts
echo ""
echo "  Polling for alerts..."
R0011_ALERTS=0
for i in 1 2 3 4; do
  sleep 5
  ALERTS=$(get_alerts "$NS")
  ALERT_COUNT=$(echo "$ALERTS" | jq 'length')
  R0011_ALERTS=$(echo "$ALERTS" | jq '[.[] | select(.labels.rule_id=="R0011")] | length')
  echo "    poll $i: total=$ALERT_COUNT R0011=$R0011_ALERTS"
  [ "$R0011_ALERTS" -gt 0 ] && break
done

echo ""
echo "  === All alerts in $NS ==="
echo "$ALERTS" | jq -r '.[] | "    [\(.labels.rule_id)] \(.labels.rule_name) | comm=\(.labels.comm // "?")"' 2>/dev/null || true
echo "  Total: $ALERT_COUNT  R0011: $R0011_ALERTS"
echo "  ========================"

if [ "$R0011_ALERTS" -gt 0 ]; then
  echo ""
  echo "  >>> RESULT: PASS — R0011 fires for user-defined AP+NN"
  cleanup_ns "$NS"
  exit 0
else
  echo ""
  echo "  >>> RESULT: FAIL — no R0011 alerts"
  echo "  >>> Namespace $NS left for inspection"
  exit 1
fi
