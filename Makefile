DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=node-agent

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
# GADGETS are pulled unmodified from upstream IG. trace_open is intentionally NOT
# here: it is vendored and built from source (see BUILT_GADGETS) so the fpath
# resolver can resolve relative opens against their dirfd/cwd.
GADGETS=advise_seccomp trace_capabilities trace_dns trace_exec
VERSION=v0.57.0
KUBESCAPE_GADGETS=bpf enforce_file enforce_network enforce_privilege exit fork hardlink http iouring_new iouring_old kmod network ptrace randomx ssh symlink unshare
# BUILT_GADGETS are vendored under pkg/ebpf/gadgets and built under their full
# upstream image name+tag so node-agent's pinned openImageName keeps resolving.
BUILT_GADGETS=trace_open
TAG?=test
# TAG?=v0.0.1
# PRODUCT_IMAGES is the enforce_exec shared product image compiled into the
# agent (pkg/sandboxpolicy/integration/engine_kernels.go,
# compiledProductImage). IG pins one image per profile, kernel-neutral: the
# same image runs on every kernel IG's gate admits. It is never pulled from a
# registry: product-images rebuilds IG's 4 pinned images in the IG checkout
# that go.mod pins (the digests depend on IG's own module versions, so never
# from this module) and checks every digest against IG's pins; only this one
# is exported to tracers.tar.
PRODUCT_IMAGES=enforce-exec-shared:g19pkg128
IG_PRODUCT_REPO?=https://github.com/kubescape/inspektor-gadget.git
# The commit of the inspektor-gadget replace pseudo-version in go.mod.
ifeq ($(origin IG_PRODUCT_COMMIT),undefined)
IG_PRODUCT_COMMIT:=$(lastword $(subst -, ,$(shell GOWORK=off GOFLAGS= go list -m -f '{{.Replace.Version}}' github.com/inspektor-gadget/inspektor-gadget)))
endif
# Outside the repository: the docker build context is the repository. It
# holds the IG clone, one build directory and one image archive per IG commit.
# IG's pinned container writes the objects as root, so removing the build
# directories needs sudo; the archives are the cache (CI caches them).
PRODUCT_IMAGES_DIR?=$(HOME)/.cache/node-agent/product-images
PRODUCT_IMAGES_TAR=$(PRODUCT_IMAGES_DIR)/$(IG_PRODUCT_COMMIT).tar
# SKIP_PRODUCT_IMAGES=1 builds tracers.tar without the product images, for
# jobs that only run tests. No agent image may be built from such an archive.
SKIP_PRODUCT_IMAGES?=
ifneq ($(SKIP_PRODUCT_IMAGES),)
ifneq ($(filter docker-build docker-build-only docker-push,$(MAKECMDGOALS)),)
$(error SKIP_PRODUCT_IMAGES is set: tracers.tar would lack the enforce_exec product images; unset it to build the agent image)
endif
endif
# Run IG's make with none of this make's flags or command-line variables
# (TAG, IMAGE, ...), which IG's Makefile would otherwise pick up.
IG_PRODUCT_MAKE=env -u MAKEFLAGS -u MAKEOVERRIDES -u MFLAGS $(foreach o,$(MAKEOVERRIDES),-u $(firstword $(subst =, ,$(o)))) GOWORK=off GOFLAGS= $(MAKE)

binary:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) ./cmd

.PHONY: check-legacy-packages
check-legacy-packages:
	go test ./tests/containerprofilecache -run TestLegacyPackagesDeleted

# Guard against merging a temporary inspektor-gadget replace pin that was
# never re-pinned to a merged commit (see scripts/check-inspektor-gadget-pin.sh).
.PHONY: check-ig-pin
check-ig-pin:
	./scripts/check-inspektor-gadget-pin.sh go.mod

docker-build-only: check-product-images
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) --load .

docker-build: gadgets
	$(MAKE) check-product-images
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) --load .

docker-push: docker-build
	docker push $(IMAGE):$(TAG)

# Build the product images once per IG commit, in the IG checkout go.mod pins
# (pinned clang container, then IG's cmd/productimages, which fails unless
# every manifest and index digest equals fullruntime.SharedProductImagePins),
# into the archive $(PRODUCT_IMAGES_TAR). Needs git, docker and go. The clone
# fetches every branch head, so the commit is found wherever it was merged.
$(PRODUCT_IMAGES_TAR):
	@test -n "$(IG_PRODUCT_COMMIT)" || { echo "product-images: no inspektor-gadget replace commit in go.mod" >&2; exit 1; }
	test -d $(PRODUCT_IMAGES_DIR)/inspektor-gadget/.git || git clone --filter=blob:none --no-checkout $(IG_PRODUCT_REPO) $(PRODUCT_IMAGES_DIR)/inspektor-gadget
	git -C $(PRODUCT_IMAGES_DIR)/inspektor-gadget cat-file -e $(IG_PRODUCT_COMMIT)^{commit} 2>/dev/null || git -C $(PRODUCT_IMAGES_DIR)/inspektor-gadget fetch --filter=blob:none origin '+refs/heads/*:refs/remotes/origin/*'
	git -C $(PRODUCT_IMAGES_DIR)/inspektor-gadget -c advice.detachedHead=false checkout --force $(IG_PRODUCT_COMMIT)
	$(IG_PRODUCT_MAKE) -C $(PRODUCT_IMAGES_DIR)/inspektor-gadget enforce-exec-product-images ENFORCE_EXEC_PRODUCT_OUT=$(PRODUCT_IMAGES_DIR)/$(IG_PRODUCT_COMMIT)
	tar -C $(PRODUCT_IMAGES_DIR)/$(IG_PRODUCT_COMMIT)/layout -cf $@.tmp oci-layout index.json blobs
	mv $@.tmp $@

# Import the product images into ig's local store for the export below.
.PHONY: product-images
product-images: $(PRODUCT_IMAGES_TAR)
	sudo ig image import $(PRODUCT_IMAGES_TAR)

# Print the IG commit the product images are built from (the CI cache key).
.PHONY: ig-product-commit
ig-product-commit:
	@echo $(IG_PRODUCT_COMMIT)

# Check the exec, privilege, network and file images with the agent's start check
# against the compiled-in table (each must resolve to its pinned amd64
# manifest). docker-build and the release workflow run it.
.PHONY: check-product-images
check-product-images:
	GOWORK=off GOFLAGS= CGO_ENABLED=0 go run ./cmd/check-product-images tracers.tar

gadgets: $(if $(SKIP_PRODUCT_IMAGES),,product-images)
	$(foreach img,$(KUBESCAPE_GADGETS),$(MAKE) -C ./pkg/ebpf/gadgets/$(img) build IMAGE=$(img) TAG=latest || exit 1;)
	$(foreach img,$(BUILT_GADGETS),$(MAKE) -C ./pkg/ebpf/gadgets/$(img) build IMAGE=ghcr.io/inspektor-gadget/gadget/$(img) TAG=$(VERSION);)
	$(foreach img,$(GADGETS),sudo ig image pull ghcr.io/inspektor-gadget/gadget/$(img):$(VERSION);)
	sudo ig image export $(foreach img,$(GADGETS) $(BUILT_GADGETS),ghcr.io/inspektor-gadget/gadget/$(img):$(VERSION)) $(foreach img,$(KUBESCAPE_GADGETS),$(img):latest) $(if $(SKIP_PRODUCT_IMAGES),,$(PRODUCT_IMAGES)) tracers.tar
