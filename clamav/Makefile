DOCKERFILE_PATH=./Dockerfile
BINARY_NAME=klamav

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
TAG?=1.2.0-6_base

docker-build:
	docker buildx build --build-arg CLAMAV_VERSION=$(TAG) --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) .
docker-push:
	docker push $(IMAGE):$(TAG)
