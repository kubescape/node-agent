//go:build !sandbox_shared_qualification

package integration

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	"oras.land/oras-go/v2"
)

// newFullEngine selects the engine from the running kernel, at agent start
// (selectKernelEngine): a kernel IG's product kernel gate admits selects the
// G020 shared node engine on the compiled-in product image; a per-binding
// proof kernel selects one persistent native owner per binding (the only
// engine that takes the legacy per-cgroup Owner budget); every other kernel
// gets a shared engine that never starts and reports the refusal
// (KernelNotQualified, or SharedEngineUnavailable with the reason).
// Configuration never selects the engine or the image: sandboxPolicyEngine
// and sandboxPolicySharedImages are ignored.
func newFullEngine(ctx context.Context, r runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, options ServiceOptions, report func(error)) (igbackend.FullEngine, error) {
	product, err := config.SandboxSharedProductFrom(options.Engine)
	if err != nil {
		return nil, err
	}
	diagnose(options.OnWarning, product)
	engine, kernel, err := selectKernelEngine()
	switch engine {
	case enginePerBinding:
		budget, err := newLegacyBudget(options.MaxOwners)
		if err != nil {
			return nil, err
		}
		return igbackend.NewNativeFullEngine(r, kube, store, options.ImageName, options.ControlRoot, budget, report)
	case engineShared:
		logger.L().Info("sandbox exec engine: kernel admitted by IG's product kernel gate", helpers.String("release", kernel.Release), helpers.String("btf", kernel.BTF), helpers.String("image", compiledProductImage.Image))
		return igbackend.NewSharedProductEngine(ctx, r, sharedProductConfig(product, store, options), report)
	default:
		return igbackend.NewUnavailableSharedEngine(err, report), nil
	}
}

// diagnose warns, once at start, of the configuration the agent ignores: the
// deprecated engine key and sandboxPolicySharedImages (the product image is
// compiled in). Neither changes enforcement, so they go to the warning path,
// not the OnError diagnostics.
func diagnose(report func(error), product config.SandboxSharedProduct) {
	if report == nil {
		return
	}
	if product.Engine != "" {
		report(fmt.Errorf("sandboxPolicyEngine %q is deprecated and ignored: the engine is selected from the running kernel", product.Engine))
	}
	if len(product.Images) != 0 {
		keys := slices.Sorted(maps.Keys(product.Images))
		if len(keys) > 4 {
			keys = append(keys[:4], fmt.Sprintf("and %d more", len(keys)-4))
		}
		report(fmt.Errorf("sandboxPolicySharedImages is ignored: the product image %s is compiled in (%d entries: %s)", compiledProductImage.Image, len(product.Images), strings.Join(keys, ", ")))
	}
}

// sharedProductConfig is the shared engine configuration on the compiled-in
// image: IG's product kernel gate checks the running kernel again at engine
// construction and at start.
func sharedProductConfig(product config.SandboxSharedProduct, store oras.ReadOnlyTarget, options ServiceOptions) igbackend.SharedProductConfig {
	return igbackend.SharedProductConfig{Image: compiledProductImage, Store: store, ContainerdAddress: options.ContainerdSocket, ImageProcRoot: product.ImageProcRoot, ImageHostRoot: product.ImageHostRoot}
}
