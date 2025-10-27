IMAGE?=iouring_new
TAG?=latest

build:
	sudo ig image build -t $(IMAGE):$(TAG) .

build-with-metadata:
	sudo ig image build -t $(IMAGE):$(TAG) . --update-metadata

run:
	sudo ig run $(IMAGE):$(TAG) --verify-image=false -o jsonpretty

build-and-run: build run
