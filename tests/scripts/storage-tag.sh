#/bin/bash
# go.mod pins the k8sstormcenter storage fork (3844202a); CTs must run its server image.
if go list -m -f '{{with .Replace}}{{.Path}}{{end}}' github.com/kubescape/storage | grep -q k8sstormcenter/storage; then
  echo "net-v2-rc1"
  exit 0
fi

curl -s https://raw.githubusercontent.com/kubescape/helm-charts/main/charts/kubescape-operator/values.yaml -o values.yaml
DYNAMIC_TAG=$(yq '.storage.image.tag' < values.yaml | tr -d '"')
rm -rf values.yaml

# Floor: node-agent's own go.mod-pinned kubescape/storage client version. When
# kubescape/helm-charts' pinned server image (fetched above) lags behind what
# this repo's client library needs, component-tests would silently regress
# (an older server drops CRD fields the newer client sets). Take the newer of
# the two so CI never runs against a server that predates our client.
FLOOR_TAG=$(go list -m -f '{{.Version}}' github.com/kubescape/storage)

printf '%s\n%s\n' "$DYNAMIC_TAG" "$FLOOR_TAG" | sort -V | tail -n1
