//go:build !sandbox_shared_qualification

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
)

// sharedProductKernel is one kernel build the agent runs the shared product
// engine on, and the product image pinned for it in this build.
type sharedProductKernel struct {
	Kernel fullruntime.KernelIdentity
	// Image is the product image compiled in for this build: its name in the
	// agent's tracers archive, its amd64 manifest digest (sha256, required)
	// and the profile it was built with. Nil: no image is pinned in this
	// build, and only a sandboxPolicySharedImages entry for this BTF supplies
	// one.
	Image *igbackend.SharedProductImage
}

// sharedProductKernels is the agent's compiled-in kernel table: the exact
// builds the shared product engine is selected on. It must be a subset of
// IG's fullruntime.QualifiedKernels() (TestSharedProductKernelsQualified);
// configuration never adds an entry. Values from IG
// gadgets/enforce_exec/fullruntime/kernel_matrix.go (sharedProductPins).
//
// No product image is pinned yet: no product image has been published with a
// manifest digest, so each kernel's image comes from sandboxPolicySharedImages
// until one is pinned here.
var sharedProductKernels = []sharedProductKernel{
	{Kernel: fullruntime.KernelIdentity{Arch: "amd64", Release: "6.12.113-138.209.amzn2023.x86_64", BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", BuildID: "1d135d67e6d0ea8f77d60a2984915eadd28a5fcf"}},
	{Kernel: fullruntime.KernelIdentity{Arch: "amd64", Release: "6.18.56-125.164.amzn2023.x86_64", BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", BuildID: "884ed4548406a1461ac5fb658c0dffdd87f1b3b2"}},
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
	verifyKernel     = fullruntime.VerifyKernel
	runningKernelBTF = readKernelBTF
)

// kernelEngine is the engine the running kernel selects.
type kernelEngine int

const (
	// engineShared: the kernel is an exact entry of the table.
	engineShared kernelEngine = iota + 1
	// enginePerBinding: the kernel is a per-binding proof kernel.
	enginePerBinding
	// engineRefused: any other kernel, or a failed kernel check.
	engineRefused
)

// selectKernelEngine selects the engine from the running kernel's identity,
// never from configuration: an exact entry of table (fullruntime.VerifyKernel:
// architecture, BTF sha256, release, GNU build-id, bpf LSM, ftrace, no
// livepatch) selects the shared engine and returns that entry; a per-binding
// proof kernel selects the per-binding engine; anything else is refused with
// the reason. A kernel whose identity is not in table is refused with
// igbackend.ErrKernelNotQualified; a qualified kernel failing a control check
// (bpf LSM, ftrace, livepatch) is refused with that check's error.
func selectKernelEngine(table []sharedProductKernel) (kernelEngine, sharedProductKernel, error) {
	identities := make([]fullruntime.KernelIdentity, 0, len(table))
	for _, k := range table {
		identities = append(identities, k.Kernel)
	}
	id, err := verifyKernel(identities)
	if err == nil {
		for _, k := range table {
			if k.Kernel == id {
				return engineShared, k, nil
			}
		}
		return engineRefused, sharedProductKernel{}, fmt.Errorf("kernel check admitted %s, which is not in the table: %w", id.Release, igbackend.ErrKernelNotQualified)
	}
	if digest, berr := runningKernelBTF(); berr == nil {
		if _, ok := perBindingProofKernels[digest]; ok {
			return enginePerBinding, sharedProductKernel{}, nil
		}
	}
	var check *fullruntime.KernelCheckError
	if errors.As(err, &check) {
		switch check.Check {
		case fullruntime.KernelCheckArch, fullruntime.KernelCheckBTF, fullruntime.KernelCheckRelease, fullruntime.KernelCheckBuildID:
			return engineRefused, sharedProductKernel{}, fmt.Errorf("%w: %s check: %w", igbackend.ErrKernelNotQualified, check.Check, err)
		}
	}
	return engineRefused, sharedProductKernel{}, fmt.Errorf("kernel check: %w", err)
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
