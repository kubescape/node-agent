IMAGE?=ghcr.io/inspektor-gadget/gadget/trace_open
TAG?=v0.48.1
BUILDER_IMAGE?=ghcr.io/inspektor-gadget/gadget-builder@sha256:e0e88543a99bbc4b1263b7f9d07a08fb8f1107426525ef8b777bdd8df15d1ee8

build:
	sudo TMPDIR=$$TMPDIR ig image build -t $(IMAGE):$(TAG) . --update-metadata --builder-image $(BUILDER_IMAGE)

run:
	sudo ig run $(IMAGE):$(TAG) --verify-image=false -o jsonpretty

build-and-run: build run
