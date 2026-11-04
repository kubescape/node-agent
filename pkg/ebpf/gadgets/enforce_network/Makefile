IMAGE?=enforce_network
TAG?=latest
# The gadget includes ../common headers. IG_SOURCE_PATH makes `ig image build`
# mount the repository root (instead of this folder only) so they resolve.
REPO_ROOT:=$(abspath $(CURDIR)/../../../..)

build:
	sudo TMPDIR=$$TMPDIR IG_SOURCE_PATH=$(REPO_ROOT) ig image build -t $(IMAGE):$(TAG) .
