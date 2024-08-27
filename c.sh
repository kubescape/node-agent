#!/bin/bash
make docker-build
docker tag armoafekb/afek-b-tests/node-agent:test docker.io/armoafekb/afek-b-tests:test$1
docker push armoafekb/afek-b-tests:test$1
helm upgrade --install kubescape kubescape/kubescape-operator -n kubescape --create-namespace --set capabilities.runtimeDetection=enable --set alertCRD.installDefault=true --set alertCRD.scopeClustered=true --set capabilities.nodeProfileService=enable --set nodeAgent.image.repository=docker.io/armoafekb/afek-b-tests --set nodeAgent.image.tag=test$1

echo $1
