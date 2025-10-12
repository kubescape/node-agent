DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=node-agent

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
GADGETS=advise_seccomp:v0.45.0 trace_capabilities:v0.45.0 trace_dns:v0.45.0 trace_exec:v0.45.0 trace_open:v0.45.0 trace_tcp:v0.45.0
KUBESCAPE_GADGETS=exit:latest fork:latest hardlink:latest ptrace:latest ssh:latest symlink:latest http:latest # iouring:latest
TAG?=test
# TAG?=v0.0.1

binary:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) ./cmd/main.go

docker-build:
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) --load .

docker-push:
	docker push $(IMAGE):$(TAG)

gadgets:
	make -C ./pkg/ebpf/gadgets/exit build
	make -C ./pkg/ebpf/gadgets/fork build
	make -C ./pkg/ebpf/gadgets/hardlink build
	#make -C ./pkg/ebpf/gadgets/iouring build
	make -C ./pkg/ebpf/gadgets/ptrace build
	make -C ./pkg/ebpf/gadgets/ssh build
	make -C ./pkg/ebpf/gadgets/symlink build
	make -C ./pkg/ebpf/gadgets/http build
	$(foreach img,$(GADGETS),sudo ig image pull $(img);)
	sudo ig image export $(GADGETS) $(KUBESCAPE_GADGETS) tracers.tar
