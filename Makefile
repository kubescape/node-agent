DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=node-agent

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
GADGETS=advise_seccomp trace_capabilities trace_dns trace_exec trace_open
VERSION=:v0.45.0
KUBESCAPE_GADGETS=bpf exit fork hardlink http iouring_new iouring_old kmod network ptrace randomx ssh symlink unshare
TAG?=test
# TAG?=v0.0.1

binary:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) ./cmd/main.go

docker-build-only:
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) --load .

docker-build: gadgets
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) --load .

docker-push:
	docker push $(IMAGE):$(TAG)

gadgets:
	$(foreach img,$(KUBESCAPE_GADGETS),$(MAKE) -C ./pkg/ebpf/gadgets/$(img) build IMAGE=$(img) TAG=latest;)
	$(foreach img,$(GADGETS),sudo ig image pull $(img)$(VERSION);)
	sudo ig image export $(foreach img,$(GADGETS),$(img)$(VERSION)) $(foreach img,$(KUBESCAPE_GADGETS),$(img):latest) tracers.tar
