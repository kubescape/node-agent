#/bin/bash
curl -s https://raw.githubusercontent.com/bob/test/localtestbuild/kubescape/values.yaml -o values.yaml
yq '.storage.image.tag' < values.yaml
rm -rf values.yaml
