#!/usr/bin/env bash
# issue79-eol-ladder.sh — E2E ladder for exec-event delivery at container
# end-of-life (issue #79, acceptance tests T4/T5).
#
# Measures, over N iterations on a live cluster running the kubescape stack:
#   T4: the forbidden terminal exec of the init container `setup`
#       (sh -c "sleep <runway>; /usr/bin/id") produces an R0001 alert — N/N.
#   T5: the forbidden terminal execs of an ephemeral container `debug`
#       (sh -c "sleep <runway>; /usr/bin/whoami; /usr/bin/id") produce R0001 —
#       N/N.
#
# Prerequisites:
#   - kubectl context pointing at the test cluster
#   - kubescape stack deployed (node-agent image under test), namespace
#     `kubescape`
#   - fixtures from tests/resources: mc37-cp-doc.yaml (grouped profile:
#     app allows id; setup forbids id; debug forbids id/whoami)
#
# Usage: issue79-eol-ladder.sh [ITERATIONS] [RUNWAY_SECONDS]
set -euo pipefail

ITERATIONS="${1:-5}"
RUNWAY="${2:-30}"
NS="node-agent-test-eol"
KS_NS="kubescape"
FIXTURE_DIR="$(cd "$(dirname "$0")/../resources" && pwd)"

t4_pass=0
t5_pass=0

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

node_agent_pod() {
  kubectl -n "$KS_NS" get pods -l app.kubernetes.io/name=node-agent \
    -o jsonpath='{.items[0].metadata.name}'
}

# Count R0001 alerts for a container name in node-agent logs since a given
# RFC3339 timestamp.
count_r0001() {
  # Read EVERY node-agent pod (DaemonSet - the workload may land on any node)
  # and match the alert JSON's containerName field explicitly.
  local container="$1" since="$2" total=0 n
  for pod in $(kubectl -n "$KS_NS" get pods -o name | grep node-agent); do
    n=$(kubectl -n "$KS_NS" logs "${pod#pod/}" -c node-agent --since-time="$since" 2>/dev/null \
      | grep '"RuleID":"R0001"' | grep -c "\"containerName\":\"${container}\"" || true)
    total=$((total + n))
  done
  echo "$total"
}

kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create ns "$NS"
kubectl -n "$NS" apply -f "$FIXTURE_DIR/mc37-cp-doc.yaml"

for i in $(seq 1 "$ITERATIONS"); do
  log "=== iteration $i/$ITERATIONS (runway ${RUNWAY}s) ==="
  kubectl -n "$NS" delete deployment mc37-deployment --ignore-not-found --wait
  sleep 3
  iter_start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Deploy with the requested init runway.
  sed "s/sleep 100/sleep ${RUNWAY}/" \
    "$FIXTURE_DIR/mc37-multi-subtype-userdefined-deployment.yaml" \
    | kubectl -n "$NS" apply -f -

  # Wait for the pod: init phase (runway) + margin.
  log "waiting for pod Ready (init runway ${RUNWAY}s)..."
  kubectl -n "$NS" rollout status deploy/mc37-deployment --timeout="$((RUNWAY + 150))s"
  pod="$(kubectl -n "$NS" get pod -l app=mc37 -o jsonpath='{.items[0].metadata.name}')"

  # T4: the init terminal exec happened just before the pod became Ready.
  # Give the pipeline a moment, then count.
  sleep 10
  init_r0001="$(count_r0001 setup "$iter_start")"
  if [ "${init_r0001:-0}" -gt 0 ]; then
    t4_pass=$((t4_pass + 1)); log "T4 init: PASS (R0001 setup=${init_r0001})"
  else
    log "T4 init: FAIL (R0001 setup=0)"
  fi

  # T5: attach ephemeral container with a terminal forbidden exec.
  eph_start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  eph_runway=20
  kubectl -n "$NS" debug "$pod" --image=debian:12-slim --container=debug \
    --profile=general -- sh -c "sleep ${eph_runway}; /usr/bin/whoami; /usr/bin/id" \
    >/dev/null
  log "waiting for ephemeral container debug to terminate..."
  for _ in $(seq 1 $((eph_runway + 60))); do
    state="$(kubectl -n "$NS" get pod "$pod" \
      -o jsonpath='{.status.ephemeralContainerStatuses[?(@.name=="debug")].state.terminated.exitCode}' 2>/dev/null || true)"
    [ -n "$state" ] && break
    sleep 2
  done
  sleep 10
  eph_r0001="$(count_r0001 debug "$eph_start")"
  if [ "${eph_r0001:-0}" -gt 0 ]; then
    t5_pass=$((t5_pass + 1)); log "T5 ephemeral: PASS (R0001 debug=${eph_r0001})"
  else
    log "T5 ephemeral: FAIL (R0001 debug=0)"
  fi
done

echo
echo "==== issue #79 EOL ladder result ===="
echo "T4 (init terminal exec R0001):      ${t4_pass}/${ITERATIONS}"
echo "T5 (ephemeral terminal exec R0001): ${t5_pass}/${ITERATIONS}"
[ "$t4_pass" -eq "$ITERATIONS" ] && [ "$t5_pass" -eq "$ITERATIONS" ]
