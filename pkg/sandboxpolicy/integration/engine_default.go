//go:build !sandbox_shared_qualification

package integration

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	"oras.land/oras-go/v2"
)

// newFullEngine selects the product engine from the running kernel's
// identity, at agent start, over the compiled-in sharedProductKernels.
func newFullEngine(ctx context.Context, r runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, options ServiceOptions, report func(error)) (igbackend.FullEngine, error) {
	return newKernelEngine(ctx, r, kube, store, options, report, sharedProductKernels)
}

// newKernelEngine: a kernel in table selects the G020 shared node engine on
// that kernel's product image (the compiled-in one, else its
// sandboxPolicySharedImages entry); any other kernel IG admits on its probes
// selects it on the common compiled-in image; a per-binding proof kernel selects one
// persistent native owner per binding (the only engine that takes the legacy
// per-cgroup Owner budget); every other kernel gets a shared engine that
// never starts and reports the refusal (KernelNotQualified, or
// SharedEngineUnavailable with the reason). Configuration never selects the
// engine and never adds a kernel: sandboxPolicyEngine is ignored and an image
// entry for a kernel outside table is never used.
func newKernelEngine(ctx context.Context, r runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, options ServiceOptions, report func(error), table []sharedProductKernel) (igbackend.FullEngine, error) {
	product, err := config.SandboxSharedProductFrom(options.Engine)
	if err != nil {
		return nil, err
	}
	diagnose(options.OnWarning, product, table)
	engine, kernel, err := selectKernelEngine(table)
	switch engine {
	case enginePerBinding:
		if product.Engine == config.SandboxPolicyEngineShared && options.OnWarning != nil {
			options.OnWarning(fmt.Errorf("per-binding engine selected on proof kernel; sandboxPolicyEngine %q ignored", product.Engine))
		}
		budget, err := newLegacyBudget(options.MaxOwners)
		if err != nil {
			return nil, err
		}
		return igbackend.NewNativeFullEngine(r, kube, store, options.ImageName, options.ControlRoot, budget, report)
	case engineShared:
		image, ok := sharedProductImage(kernel, product)
		if !ok {
			return igbackend.NewUnavailableSharedEngine(fmt.Errorf("kernel %s (BTF sha256 %s) is qualified but no product image is pinned for it: set its sandboxPolicySharedImages entry", kernel.Kernel.Release, kernel.Kernel.BTF), report), nil
		}
		// IG's own gate selects the entry again: by BTF sha256 on a
		// qualified kernel, by fullruntime.SharedProbedKernelEntry on a
		// probed one.
		key := kernel.Kernel.BTF
		if kernel.Tier == fullruntime.KernelTierProbed {
			key = fullruntime.SharedProbedKernelEntry
			if options.OnWarning != nil {
				options.OnWarning(fmt.Errorf("kernel %s (BTF sha256 %s) is not a qualified build: the shared exec engine runs on it as a probed kernel", kernel.Kernel.Release, kernel.Kernel.BTF))
			}
		}
		shared, err := igbackend.NewSharedProductEngine(ctx, r, sharedProductConfig(product, key, kernel.Tier, kernel.Kernel, image, store, options), report)
		if err != nil {
			return nil, err
		}
		return shared, nil
	default:
		return igbackend.NewUnavailableSharedEngine(err, report), nil
	}
}

// sharedProductImage is kernel's compiled-in image, else its configured
// entry. A compiled-in image is never replaced by configuration.
func sharedProductImage(kernel sharedProductKernel, product config.SandboxSharedProduct) (igbackend.SharedProductImage, bool) {
	if kernel.Image != nil {
		return *kernel.Image, true
	}
	image, ok := product.Images[kernel.Kernel.BTF]
	if !ok {
		return igbackend.SharedProductImage{}, false
	}
	return igbackend.SharedProductImage{Image: image.Image, ProfileFile: image.ProfileFile, ManifestDigest: image.ManifestDigest}, true
}

// diagnose warns, once at start, of the configuration the agent ignores: the
// deprecated engine key, image entries for kernels outside table, and image
// entries of kernels whose image is compiled in. None changes enforcement,
// so they go to the warning path, not the OnError diagnostics.
func diagnose(report func(error), product config.SandboxSharedProduct, table []sharedProductKernel) {
	if report == nil {
		return
	}
	if product.Engine != "" {
		report(fmt.Errorf("sandboxPolicyEngine %q is deprecated and ignored: the engine is selected from the running kernel", product.Engine))
	}
	var unknown, pinned []string
	for btf := range product.Images {
		i := slices.IndexFunc(table, func(k sharedProductKernel) bool { return k.Kernel.BTF == btf })
		switch {
		case i < 0:
			unknown = append(unknown, btf)
		case table[i].Image != nil:
			pinned = append(pinned, btf)
		}
	}
	if len(unknown) != 0 {
		slices.Sort(unknown)
		report(fmt.Errorf("sandboxPolicySharedImages entries for kernels outside the agent's qualified table are ignored: %s", strings.Join(unknown, ", ")))
	}
	if len(pinned) != 0 {
		slices.Sort(pinned)
		report(fmt.Errorf("sandboxPolicySharedImages entries for kernels with a compiled-in image are ignored: %s", strings.Join(pinned, ", ")))
	}
}

// sharedProductConfig is the shared engine configuration for the one selected
// kernel, under key (its BTF sha256, or fullruntime.SharedProbedKernelEntry
// on a probed kernel): IG's own gate (fullruntime.SelectSharedProductImage)
// checks the running kernel again and must select the same entry.
func sharedProductConfig(product config.SandboxSharedProduct, key string, tier fullruntime.KernelTier, kernel fullruntime.KernelIdentity, image igbackend.SharedProductImage, store oras.ReadOnlyTarget, options ServiceOptions) igbackend.SharedProductConfig {
	return igbackend.SharedProductConfig{Tier: tier, Kernel: kernel, Images: map[string]igbackend.SharedProductImage{key: image}, Store: store, ContainerdAddress: options.ContainerdSocket, ImageProcRoot: product.ImageProcRoot, ImageHostRoot: product.ImageHostRoot}
}
