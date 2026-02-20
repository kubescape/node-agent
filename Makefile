DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=node-agent

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
GADGETS=advise_seccomp trace_capabilities trace_dns trace_exec trace_open
VERSION=v0.48.1
KUBESCAPE_GADGETS=bpf exit fork hardlink http iouring_new iouring_old kmod kubelet_tls network ptrace randomx ssh symlink unshare
TAG?=test
# TAG?=v0.0.1

binary:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) ./cmd/main.go

docker-build-only:
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) --load .

docker-build: gadgets
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) --load .

docker-push: docker-build
	docker push $(IMAGE):$(TAG)

STORAGE_LOCAL_PATH ?= ../storage

.PHONY: local
local:
	go mod edit -replace "github.com/kubescape/storage=$(STORAGE_LOCAL_PATH)"
	GONOSUMDB=github.com/matthyx/* GONOSUMCHECK=github.com/matthyx/* go mod tidy

.PHONY: unlocal
unlocal:
	go mod edit -dropreplace "github.com/kubescape/storage"
	GONOSUMDB=github.com/matthyx/* GONOSUMCHECK=github.com/matthyx/* GOFLAGS=-mod=mod go mod tidy

.PHONY: test
test: local
	go test ./pkg/rulemanager/cel/libraries/applicationprofile/... -v -count=1
	@$(MAKE) unlocal

gadgets:
	$(foreach img,$(KUBESCAPE_GADGETS),$(MAKE) -C ./pkg/ebpf/gadgets/$(img) build IMAGE=$(img) TAG=latest;)
	$(foreach img,$(GADGETS),sudo ig image pull ghcr.io/inspektor-gadget/gadget/$(img):$(VERSION);)
	sudo ig image export $(foreach img,$(GADGETS),ghcr.io/inspektor-gadget/gadget/$(img):$(VERSION)) $(foreach img,$(KUBESCAPE_GADGETS),$(img):latest) tracers.tar
