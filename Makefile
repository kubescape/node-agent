DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=node-agent

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
TAG?=test
# TAG?=v0.0.1

host:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) ./cmd/host/main.go

run-host: host
	sudo -E CONFIG_DIR=./configuration/node-hash-sensor KS_LOGGER_LEVEL=debug ./node-agent

node:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) ./cmd/node/main.go

docker-build:
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) --load .

docker-push:
	docker push $(IMAGE):$(TAG)
