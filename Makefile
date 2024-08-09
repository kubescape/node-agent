DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=node-agent

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
TAG?=test
# TAG?=v0.0.1

binary:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)

docker-build:
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) .

docker-push:
	docker push $(IMAGE):$(TAG)
