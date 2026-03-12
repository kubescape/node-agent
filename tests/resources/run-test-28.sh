#!/usr/bin/env bash
#
# run-test-28.sh — Manual execution of Test_28_UserDefinedNetworkNeighborhood
#
# Exercises user-defined NetworkNeighborhood + ApplicationProfile labels.
# Covers: both labels and NN-only scenarios (all user-defined NN, no NN learning).
#
# Usage:
#   ./run-test-28.sh                  # run all subtests
#   ./run-test-28.sh both             # only the "both labels" scenario
#   ./run-test-28.sh nn-only          # only NN label (AP auto-learns)
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
    imageID: "docker.io/curlimages/curl@sha256:08e466006f0860e54fc299378de998935333e0e130a15f6f98482e9f8dab3058"
    imageTag: "docker.io/curlimages/curl:8.5.0"
    capabilities:
    - CAP_CHOWN
    - CAP_DAC_OVERRIDE
    - CAP_DAC_READ_SEARCH
    - CAP_SETGID
    - CAP_SETPCAP
    - CAP_SETUID
    - CAP_SYS_ADMIN
    execs:
    - path: /bin/sleep
      args: ["/bin/sleep", "infinity"]
    - path: /bin/cat
      args: ["/bin/cat"]
    - path: /usr/bin/curl
      args: ["/usr/bin/curl", "-sm2", "fusioncore.ai"]
    - path: /usr/bin/nslookup
      args: ["/usr/bin/nslookup"]
    opens:
    - path: /etc/hosts
      flags: ["O_CLOEXEC", "O_RDONLY", "O_LARGEFILE"]
    - path: /etc/ld-musl-x86_64.path
      flags: ["O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"]
    - path: /etc/passwd
      flags: ["O_RDONLY", "O_CLOEXEC", "O_LARGEFILE"]
    - path: /etc/resolv.conf
      flags: ["O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"]
    - path: /etc/ssl/openssl.cnf
      flags: ["O_RDONLY", "O_LARGEFILE"]
    - path: /lib/libcurl.so.4
      flags: ["O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"]
    - path: /lib/libcrypto.so.3
      flags: ["O_CLOEXEC", "O_RDONLY", "O_LARGEFILE"]
    - path: /lib/libssl.so.3
      flags: ["O_RDONLY", "O_LARGEFILE", "O_CLOEXEC"]
    - path: /lib/libz.so.1.3
      flags: ["O_LARGEFILE", "O_CLOEXEC", "O_RDONLY"]
    syscalls:
    - arch_prctl
    - bind
    - brk
    - capget
    - capset
    - chdir
    - clone
    - close
    - close_range
    - connect
    - epoll_ctl
    - epoll_pwait
    - execve
    - exit
    - exit_group
    - faccessat2
    - fchown
    - fcntl
    - fstat
    - fstatfs
    - futex
    - getcwd
    - getdents64
    - getegid
    - geteuid
    - getgid
    - getpeername
    - getppid
    - getsockname
    - getsockopt
    - gettid
    - getuid
    - ioctl
    - membarrier
    - mmap
    - mprotect
    - munmap
    - nanosleep
    - newfstatat
    - open
    - openat
    - openat2
    - pipe
    - poll
    - prctl
    - read
    - recvfrom
    - recvmsg
    - rt_sigaction
    - rt_sigprocmask
    - rt_sigreturn
    - sendto
    - set_tid_address
    - setgid
    - setgroups
    - setsockopt
    - setuid
    - sigaltstack
    - socket
    - statx
    - tkill
    - unknown
    - write
    - writev
    endpoints:
    - endpoint: ":80/"
      direction: outbound
      methods: ["GET"]
      internal: false
      headers: '{"Host":["fusioncore.ai"]}'
    seccompProfile:
      spec:
        defaultAction: ""
    rulePolicies: {}
EOF
}

# ---------------------------------------------------------------
# Create user-defined NetworkNeighborhood in a namespace.
# Carries managed-by annotation and workload labels for cache lookup.
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
    kubescape.io/managed-by: User
    kubescape.io/status: completed
    kubescape.io/completion: complete
  labels:
    kubescape.io/workload-api-group: apps
    kubescape.io/workload-api-version: v1
    kubescape.io/workload-kind: Deployment
    kubescape.io/workload-name: curl-fusioncore-deployment
    kubescape.io/workload-namespace: "$ns"
spec:
  matchLabels:
    app: curl-fusioncore
  containers:
  - name: curl
    ingress: []
    egress:
    - identifier: kube-dns
      type: internal
      namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
      ports:
      - name: UDP-53
        protocol: UDP
        port: 53
    - identifier: fusioncore-ai
      type: external
      dns: "fusioncore.ai."
      dnsNames: ["fusioncore.ai."]
      ipAddress: "162.0.217.171"
      ports:
      - name: TCP-80
        protocol: TCP
        port: 80
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
  kubectl apply -n "$NS" -f "$SCRIPT_DIR/curl-both-user-defined-deployment.yaml"
  wait_for_pod "$NS"
  local POD; POD=$(get_pod "$NS")
  echo "Pod: $POD — sleeping 30s for node-agent to pick up resources..."
  sleep 30

  # --- a. Allowed activity → no alerts ---
  echo "  (a) Allowed exec + allowed DNS (nslookup) + allowed HTTP (curl)..."
  kubectl exec -n "$NS" "$POD" -c curl -- cat /etc/hosts >/dev/null 2>&1 || true
  kubectl exec -n "$NS" "$POD" -c curl -- \
    nslookup fusioncore.ai >/dev/null 2>&1 || true
  kubectl exec -n "$NS" "$POD" -c curl -- \
    curl -sm2 http://fusioncore.ai >/dev/null 2>&1 || true
  sleep 10

  local EXEC_ALERTS; EXEC_ALERTS=$(get_alerts "$NS" "Unexpected process launched" curl)
  local DNS_ALERTS;  DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" curl)
  [ "$EXEC_ALERTS" -eq 0 ] && pass "no R0001 for allowed exec" || fail "R0001 fired ($EXEC_ALERTS) for allowed exec"
  [ "$DNS_ALERTS" -eq 0 ]  && pass "no R0005 for allowed DNS"  || fail "R0005 fired ($DNS_ALERTS) for allowed DNS"

  # --- b. Unknown exec → R0001 ---
  echo "  (b) Unknown exec (ls)..."
  kubectl exec -n "$NS" "$POD" -c curl -- ls / >/dev/null 2>&1 || true
  sleep 10

  EXEC_ALERTS=$(get_alerts "$NS" "Unexpected process launched" curl)
  [ "$EXEC_ALERTS" -gt 0 ] && pass "R0001 fired for unknown exec" || fail "no R0001 for unknown exec"

  # --- c. Unknown DNS → R0005 ---
  echo "  (c) Unknown DNS (evil.example.com) via nslookup..."
  kubectl exec -n "$NS" "$POD" -c curl -- \
    nslookup evil.example.com >/dev/null 2>&1 || true
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
  echo "  (d) Allowed DNS (fusioncore.ai) via nslookup..."
  kubectl exec -n "$NS" "$POD" -c curl -- \
    nslookup fusioncore.ai >/dev/null 2>&1 || true
  sleep 30

  local DNS_ALERTS; DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" curl)
  [ "$DNS_ALERTS" -eq 0 ] && pass "no R0005 for allowed DNS (NN-only)" || fail "R0005 fired ($DNS_ALERTS) for allowed DNS (NN-only)"

  # --- e. Unknown DNS → R0005 ---
  echo "  (e) Unknown DNS (evil.example.com) via nslookup..."
  kubectl exec -n "$NS" "$POD" -c curl -- \
    nslookup evil.example.com >/dev/null 2>&1 || true
  sleep 30

  DNS_ALERTS=$(get_alerts "$NS" "DNS Anomalies in container" curl)
  [ "$DNS_ALERTS" -gt 0 ] && pass "R0005 fired for unknown DNS (NN-only)" || fail "no R0005 for unknown DNS (NN-only)"

  echo "  Cleanup: kubectl delete namespace $NS"
}

# =================================================================
# Scenario: LEARN — no user-defined labels, learn NN from scratch.
# Useful to inspect the correct NN schema.
# =================================================================
run_learn() {
  local NS="t28-learn-$(head -c4 /dev/urandom | xxd -p)"
  echo ""
  echo "=== Scenario: LEARN NN from scratch (no user-defined labels)  (ns=$NS) ==="

  kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
  kubectl apply -n "$NS" -f "$SCRIPT_DIR/curl-plain-deployment.yaml"
  wait_for_pod "$NS"
  local POD; POD=$(get_pod "$NS")
  echo "Pod: $POD"

  # Trigger DNS + network traffic DURING the learning window.
  echo "  Triggering DNS + network traffic during learning window..."

  # 1. nslookup — pure UDP DNS query to kube-dns
  echo "  (1) nslookup fusioncore.ai"
  kubectl exec -n "$NS" "$POD" -c curl -- nslookup fusioncore.ai 2>&1 || true

  # 2. curl — DNS lookup + TCP connection to fusioncore.ai:80
  echo "  (2) curl -sm5 http://fusioncore.ai"
  kubectl exec -n "$NS" "$POD" -c curl -- curl -sm5 http://fusioncore.ai >/dev/null 2>&1 || true

  # 3. wget — alternative HTTP client (busybox)
  echo "  (3) wget -q -O /dev/null http://fusioncore.ai"
  kubectl exec -n "$NS" "$POD" -c curl -- wget -q -O /dev/null http://fusioncore.ai 2>&1 || true

  # 4. Repeat a few times to ensure capture
  sleep 5
  echo "  (4) repeat: nslookup + curl"
  kubectl exec -n "$NS" "$POD" -c curl -- nslookup fusioncore.ai 2>&1 || true
  kubectl exec -n "$NS" "$POD" -c curl -- curl -sm5 http://fusioncore.ai >/dev/null 2>&1 || true

  echo "  Waiting for ApplicationProfile + NetworkNeighborhood to complete..."
  for i in $(seq 1 80); do
    AP_STATUS=$(kubectl get applicationprofiles -n "$NS" \
      -o jsonpath='{.items[0].metadata.annotations.kubescape\.io/status}' 2>/dev/null || true)
    [ "$AP_STATUS" = "completed" ] && break
    sleep 10
  done
  echo "  AP status: $AP_STATUS"

  # Check NN status
  local NN_STATUS
  NN_STATUS=$(kubectl get networkneighborhoods -n "$NS" \
    -o jsonpath='{.items[0].metadata.annotations.kubescape\.io/status}' 2>/dev/null || true)
  echo "  NN status: $NN_STATUS"

  # Dump the learned NN
  echo ""
  echo "  === Learned NetworkNeighborhood ==="
  kubectl get networkneighborhoods -n "$NS" -o yaml 2>&1
  echo "  ==================================="

  # Dump the learned AP (execs only, for brevity)
  echo ""
  echo "  === Learned ApplicationProfile (execs) ==="
  kubectl get applicationprofiles -n "$NS" -o jsonpath='{.items[0].spec.containers[0].execs}' 2>&1 | python3 -m json.tool 2>/dev/null || \
    kubectl get applicationprofiles -n "$NS" -o jsonpath='{.items[0].spec.containers[0].execs}' 2>&1
  echo ""
  echo "  ==========================================="

  echo ""
  echo "  Namespace $NS left intact for inspection."
  echo "  Inspect:  kubectl get networkneighborhoods -n $NS -o yaml"
  echo "  Cleanup:  kubectl delete namespace $NS"
}

# =================================================================
# Main
# =================================================================
echo "=== Test 28: User-Defined Network Neighborhood ==="
echo "Alertmanager: $ALERTMANAGER_URL"

case "$SCENARIO" in
  both)    run_both ;;
  nn-only) run_nn_only ;;
  learn)   run_learn ;;
  all)
    run_both
    run_nn_only
    ;;
  *)
    echo "Unknown scenario: $SCENARIO"
    echo "Usage: $0 [all|both|nn-only|learn]"
    exit 1
    ;;
esac

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
