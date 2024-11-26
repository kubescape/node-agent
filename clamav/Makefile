DOCKERFILE_PATH=./Dockerfile
BINARY_NAME=klamav

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
TAG?=1.3.1-34_base

docker-build:
	docker buildx build --build-arg CLAMAV_VERSION=$(TAG) --platform linux/amd64,linux/arm64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) . --load
docker-push:
	docker buildx build --build-arg CLAMAV_VERSION=$(TAG) --platform linux/amd64,linux/arm64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) . --push
