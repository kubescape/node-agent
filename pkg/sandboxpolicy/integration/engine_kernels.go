//go:build !sandbox_shared_qualification

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	"oras.land/oras-go/v2"
)

// sharedProductImageArch is the architecture of the product image (IG's
// product objects target x86 and its gate admits only amd64 kernels).
const sharedProductImageArch = "amd64"

// sharedProductProfile is the product object geometry compiled in, the size
// of the AL2023 qualification runs.
const sharedProductProfile = "g19pkg128"

// compiledProductImage is the one product image the shared engine runs, on
// every kernel IG's product kernel gate admits: the image is kernel-neutral
// (one CO-RE object per profile). Its local name and manifest digest are
// IG's fullruntime.SharedProductImagePins() entry for sharedProductProfile,
// copied here so that a pin rotation in IG needs a reviewed change here
// (TestCompiledInImageMatchesIGPin); its profile is the pin's SharedProfile.
// `make gadgets` rebuilds the image from the pinned IG checkout into
// tracers.tar and `make check-product-images` checks it there. Configuration
// never replaces it.
var compiledProductImage = igbackend.SharedProductImage{
	Image:          "enforce-exec-shared:g19pkg128",
	ManifestDigest: "sha256:036e99e41408b669b879f925a942af68689c1734c2d9b0d8033207387f25de6a",
	Profile:        pinnedProductProfile(sharedProductProfile),
}

// pinnedProductProfile is the SharedProfile of IG's product image pin for
// profile, or nil if IG pins no such image (the engine then refuses: no
// profile file is configured for the compiled-in image).
func pinnedProductProfile(profile string) *fullruntime.SharedProfile {
	for _, pin := range fullruntime.SharedProductImagePins() {
		if pin.Profile == profile {
			return &pin.SharedProfile
		}
	}
	return nil
}

// VerifyCompiledInImages checks the compiled-in product image in store (the
// agent's tracers.tar) with the agent's own start check, for amd64: its name
// resolves to an index with exactly one amd64 manifest, whose digest is the
// compiled-in one, and every blob that manifest references is present and
// digest-verified. `make check-product-images` runs it on the built archive,
// so an agent image cannot ship with a missing or different product image.
func VerifyCompiledInImages(ctx context.Context, store oras.ReadOnlyTarget) error {
	if err := igbackend.VerifySharedImage(ctx, store, compiledProductImage.Image, compiledProductImage.ManifestDigest, sharedProductImageArch); err != nil {
		return fmt.Errorf("product image %s: %w", compiledProductImage.Image, err)
	}
	return nil
}

// perBindingProofKernels are the BTF sha256 of the two custom proof kernels
// the per-binding engine admits (IG verifySupportedKernel). No other kernel
// selects it.
var perBindingProofKernels = map[string]struct{}{
	fullruntime.SupportedKernelBTF:           {},
	fullruntime.SupportedKubernetesKernelBTF: {},
}

// Kernel probes; tests replace them.
var (
	sharedProductKernel = fullruntime.SharedProductKernel
	runningKernelBTF    = readKernelBTF
)

// kernelEngine is the engine the running kernel selects.
type kernelEngine int

const (
	// engineShared: IG's product kernel gate admits the kernel.
	engineShared kernelEngine = iota + 1
	// enginePerBinding: the kernel is a per-binding proof kernel.
	enginePerBinding
	// engineRefused: any other kernel.
	engineRefused
)

// selectKernelEngine selects the engine from the running kernel, never from
// configuration: a per-binding proof kernel (by BTF sha256) selects the
// per-binding engine; any other kernel IG's product kernel gate admits
// (fullruntime.SharedProductKernel: amd64, readable BTF digest, release and
// build-id, bpf LSM active, ftrace enabled, no livepatch) selects the shared
// engine and returns its identity. Every kernel is admitted the same way;
// there is no kernel list. A refusal keeps the reason: the architecture or an
// identity check with igbackend.ErrKernelNotQualified, a failed control
// check (bpf LSM, ftrace, livepatch) with that check's error.
func selectKernelEngine() (kernelEngine, fullruntime.KernelIdentity, error) {
	if digest, err := runningKernelBTF(); err == nil {
		if _, ok := perBindingProofKernels[digest]; ok {
			return enginePerBinding, fullruntime.KernelIdentity{}, nil
		}
	}
	id, err := sharedProductKernel()
	if err == nil {
		return engineShared, id, nil
	}
	var check *fullruntime.KernelCheckError
	if errors.As(err, &check) {
		switch check.Check {
		case fullruntime.KernelCheckArch, fullruntime.KernelCheckBTF, fullruntime.KernelCheckRelease, fullruntime.KernelCheckBuildID:
			return engineRefused, fullruntime.KernelIdentity{}, fmt.Errorf("%w: %s check: %w", igbackend.ErrKernelNotQualified, check.Check, err)
		}
	}
	return engineRefused, fullruntime.KernelIdentity{}, fmt.Errorf("kernel check: %w", err)
}

// readKernelBTF returns the sha256 (lowercase hex) of the running kernel's
// vmlinux BTF. It only tells the per-binding proof kernels apart; IG checks
// the kernel again before either engine loads anything.
func readKernelBTF() (string, error) {
	data, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
