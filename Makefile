DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=node-agent

IMAGE?=quay.io/kubescape/$(BINARY_NAME)

# Version
GIT_HEAD_COMMIT ?= $(shell git rev-parse --short HEAD)
VERSION         ?= $(or $(shell git describe --abbrev=0 --tags --match "v*" 2>/dev/null),$(GIT_HEAD_COMMIT))
GINKGO          := $(shell pwd)/bin/ginkgo
GINGKO_VERSION  := v2.13.2
ginkgo: ## Download ginkgo locally if necessary.
	$(call go-install-tool,$(GINKGO),github.com/onsi/ginkgo/v2/ginkgo@$(GINGKO_VERSION))

# go-install-tool will 'go install' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-install-tool
@[ -f $(1) ] || { \
set -e ;\
GOBIN=$(PROJECT_DIR)/bin go install $(2) ;\
}
endef

binary:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)

docker-build:
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(VERSION) -f $(DOCKERFILE_PATH) .
docker-push:
	docker push $(IMAGE):$(VERSION)
	
# Running e2e tests in a KinD instance
# this section was highly inspired from Capsule project (github.com/projectcapsule/capsule)
.PHONY: e2e
e2e/%: ginkgo
	$(MAKE) e2e-build/$* && $(MAKE) e2e-exec && $(MAKE) e2e-destroy

e2e-build/%:
	kind create cluster --wait=60s --name node-agent --image=kindest/node:$*
	make e2e-load-image
	make e2e-install

.PHONY: e2e-install
e2e-install:
	git clone git@github.com:kubescape/helm-charts.git; \
	cd helm-charts; \
	helm repo add kubescape https://kubescape.github.io/helm-charts/; \
       	helm repo update; \
	helm upgrade \
		--install kubescape \
		./charts/kubescape-operator \
		-n kubescape --create-namespace \
		--set nodeAgent.tag=$(VERSION) \
		--set nodeAgent.pullPolicy=Never \
		--set clusterName=`kubectl config current-context` \
		--set capabilities.networkPolicyService=enable \
		--set capabilities.vulnerabilityScan=disable \
		--set capabilities.configurationScan=disable

.PHONY: e2e-load-image
e2e-load-image: docker-build
	kind load docker-image --nodes node-agent-control-plane --name node-agent $(IMAGE):$(VERSION)

.PHONY: e2e-exec
e2e-exec: ginkgo
	$(GINKGO) -v ./e2e

.PHONY: e2e-destroy
e2e-destroy:
	kind delete cluster --name node-agent
