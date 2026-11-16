//go:build !sandbox_shared_qualification

package integration

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	"oras.land/oras-go/v2"
)

// newFullEngine selects the product engine: one persistent native owner per
// binding, unless sandboxPolicyEngine is "shared" (the G020 shared node
// engine on the image configured for the running kernel build, selected
// here, at agent start). Only the per-binding engine takes the legacy
// per-cgroup Owner budget.
func newFullEngine(ctx context.Context, r runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, options ServiceOptions, report func(error)) (igbackend.FullEngine, error) {
	product, err := config.SandboxSharedProductFrom(options.Engine)
	if err != nil {
		return nil, err
	}
	if product.Engine != config.SandboxPolicyEngineShared {
		budget, err := newLegacyBudget(options.MaxOwners)
		if err != nil {
			return nil, err
		}
		return igbackend.NewNativeFullEngine(r, kube, store, options.ImageName, options.ControlRoot, budget, report)
	}
	engine, err := igbackend.NewSharedProductEngine(ctx, r, sharedProductConfig(product, store, options), report)
	if err != nil {
		return nil, err
	}
	return engine, nil
}

func sharedProductConfig(product config.SandboxSharedProduct, store oras.ReadOnlyTarget, options ServiceOptions) igbackend.SharedProductConfig {
	images := make(map[string]igbackend.SharedProductImage, len(product.Images))
	for btf, image := range product.Images {
		images[btf] = igbackend.SharedProductImage{Image: image.Image, ProfileFile: image.ProfileFile, ManifestDigest: image.ManifestDigest}
	}
	return igbackend.SharedProductConfig{Images: images, Store: store, ContainerdAddress: options.ContainerdSocket, ImageProcRoot: product.ImageProcRoot, ImageHostRoot: product.ImageHostRoot}
}
