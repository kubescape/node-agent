DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=node-agent

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
# GADGETS are pulled unmodified from upstream IG. trace_open is intentionally NOT
# here: it is vendored and built from source (see BUILT_GADGETS) so the fpath
# resolver can resolve relative opens against their dirfd/cwd.
GADGETS=advise_seccomp trace_capabilities trace_dns trace_exec
VERSION=v0.48.1
KUBESCAPE_GADGETS=bpf exit fork hardlink http iouring_new iouring_old kmod network ptrace randomx ssh symlink unshare
# BUILT_GADGETS are vendored under pkg/ebpf/gadgets and built under their full
# upstream image name+tag so node-agent's pinned openImageName keeps resolving.
BUILT_GADGETS=trace_open
TAG?=test
# TAG?=v0.0.1

binary:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) ./cmd/main.go

.PHONY: check-legacy-packages
check-legacy-packages:
	go test ./tests/containerprofilecache -run TestLegacyPackagesDeleted

docker-build-only:
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) --load .

docker-build: gadgets
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) --load .

docker-push: docker-build
	docker push $(IMAGE):$(TAG)

gadgets:
	$(foreach img,$(KUBESCAPE_GADGETS),$(MAKE) -C ./pkg/ebpf/gadgets/$(img) build IMAGE=$(img) TAG=latest;)
	$(foreach img,$(BUILT_GADGETS),$(MAKE) -C ./pkg/ebpf/gadgets/$(img) build IMAGE=ghcr.io/inspektor-gadget/gadget/$(img) TAG=$(VERSION);)
	$(foreach img,$(GADGETS),sudo ig image pull ghcr.io/inspektor-gadget/gadget/$(img):$(VERSION);)
	sudo ig image export $(foreach img,$(GADGETS) $(BUILT_GADGETS),ghcr.io/inspektor-gadget/gadget/$(img):$(VERSION)) $(foreach img,$(KUBESCAPE_GADGETS),$(img):latest) tracers.tar
