DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=node-agent

IMAGE?=armoafekb/afek-b-tests/$(BINARY_NAME)
TAG?=test
# TAG?=v0.0.1

binary:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)

docker-build:
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) .

docker-push:
	docker tag armoafekb/afek-b-tests/node-agent:test docker.io/armoafekb/afek-b-tests:test
	docker push armoafekb/afek-b-tests:test
