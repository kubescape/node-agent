#!/usr/bin/env bash
# Creates and removes only a new disposable cluster; never uses the current context.
set -euo pipefail
cluster=node-agent-963-gc
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
chart=${HOSTDATA_GC_CHART:-"$repo/../helm-charts/charts/kubescape-operator"}
cd "$repo"
if kind get clusters | grep -Fxq "$cluster"; then
  echo "Refusing to reuse existing cluster $cluster" >&2
  exit 1
fi
work=$(mktemp -d)
export KUBECONFIG="$work/kubeconfig"
created=false
cleanup() {
  if "$created"; then kind delete cluster --name "$cluster"; fi
  rm -rf "$work"
}
trap cleanup EXIT
created=true
kind create cluster --name "$cluster" --image kindest/node:v1.35.1 --kubeconfig "$KUBECONFIG" --wait 90s
kubectl create namespace gc-integration
args=()
for template in "$chart"/templates/node-agent-crds/*-crd.yaml; do
  args+=(--show-only "${template#"$chart"/}")
done
for template in serviceaccount clusterrole clusterrolebinding hostdata-gc-role hostdata-gc-rolebinding; do
  args+=(--show-only "templates/node-agent/$template.yaml")
done
helm template gc "$chart" --set clusterName="$cluster" --set ksNamespace=gc-integration --set unittest=true "${args[@]}" > "$work/resources.yaml"
kubectl apply -f "$work/resources.yaml"
kubectl wait --for=condition=Established crd --all --timeout=60s
HOSTDATA_GC_KUBECONFIG="$KUBECONFIG" GOTOOLCHAIN=${GOTOOLCHAIN:-go1.27.0} go test -mod=readonly -race -tags=integration ./pkg/hostsensormanager -run '^TestHostDataGCIntegration$' -count=1 -timeout=4m -v
