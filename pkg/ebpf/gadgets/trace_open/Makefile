IMAGE?=ghcr.io/inspektor-gadget/gadget/trace_open
TAG?=v0.57.0
BUILDER_IMAGE?=ghcr.io/inspektor-gadget/gadget-builder@sha256:1586c58ae4731fb8fb12546c031a352db34c0ce334709b9b54e6c648edae76ad

build:
	sudo TMPDIR=$$TMPDIR ig image build -t $(IMAGE):$(TAG) . --update-metadata --builder-image $(BUILDER_IMAGE)

run:
	sudo ig run $(IMAGE):$(TAG) --verify-image=false -o jsonpretty

build-and-run: build run
