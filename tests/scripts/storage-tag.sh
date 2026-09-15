#!/bin/bash
set -eo pipefail

# 1. Latest release tag from kubescape/storage repository (using git ls-remote to avoid GitHub API rate limits)
LATEST_TAG=$(git ls-remote --tags --refs https://github.com/kubescape/storage.git 2>/dev/null | awk -F/ '{print $3}' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1 || true)

# 2. Pinned tag from helm-charts
curl -s https://raw.githubusercontent.com/kubescape/helm-charts/main/charts/kubescape-operator/values.yaml -o values.yaml 2>/dev/null || true
DYNAMIC_TAG=""
if [ -f values.yaml ]; then
    DYNAMIC_TAG=$(yq '.storage.image.tag' < values.yaml 2>/dev/null | tr -d '"' || true)
    rm -f values.yaml
fi

# 3. Floor: node-agent's own go.mod-pinned kubescape/storage client version. When
# kubescape/helm-charts' pinned server image (fetched above) lags behind what
# this repo's client library needs, component-tests would silently regress
# (an older server drops CRD fields the newer client sets). Take the newest
# available tag so CI runs against the latest server release.
FLOOR_TAG=$(go list -m -f '{{.Version}}' github.com/kubescape/storage 2>/dev/null || true)

printf '%s\n%s\n%s\n' "$LATEST_TAG" "$DYNAMIC_TAG" "$FLOOR_TAG" | grep -v '^$' | sort -V | tail -n1

