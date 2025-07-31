#/bin/bash
curl -s https://raw.githubusercontent.com/kubescape/helm-charts/main/charts/kubescape-operator/values.yaml -o values.yaml
yq '.storage.image.tag' < values.yaml
rm -rf values.yaml
