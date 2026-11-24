package igbackend

// G020 shared node engine, product start (default build): the engine runs
// the one compiled-in product image on every kernel IG's product kernel gate
// admits (fullruntime.SharedProductKernel). The gate runs again at agent
// start and right before the node starts, the image's manifest digest is
// bound both times, and the node starts through fullruntime.WithSharedNodeHost
// (IG runs its gate a third time and admits only a product image of its
// release).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	goruntime "runtime"

	"github.com/distribution/reference"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
)

// ErrSharedManifestMismatch: the trusted store resolves the selected image
// to a manifest other than the configured one.
var ErrSharedManifestMismatch = errors.New("shared image manifest digest mismatch")

// ErrKernelNotQualified: the running kernel fails the architecture or an
// identity check of IG's product kernel gate (another architecture, or an
// unreadable BTF digest, release or GNU build-id). Health reports it with
// reason KernelNotQualified.
var ErrKernelNotQualified = errors.New("running kernel fails the architecture or identity check of IG's product kernel gate")

// SharedProductImage is the product image: the image reference in Store, the
// profile it was built with (Profile when set, else the JSON at ProfileFile)
// and the digest of its manifest for this architecture.
type SharedProductImage struct {
	Image, ProfileFile, ManifestDigest string
	Profile                            *fullruntime.SharedProfile
}

// SharedProductConfig is the product engine's administrator configuration.
type SharedProductConfig struct {
	// Image is the one product image, the same on every kernel.
	Image SharedProductImage
	// Store is the agent's read-only image archive.
	Store oras.ReadOnlyTarget
	// ContainerdAddress, ImageProcRoot and ImageHostRoot as in
	// SharedEngineConfig.
	ContainerdAddress            string
	ImageProcRoot, ImageHostRoot string
}

// sharedProductKernel is IG's product kernel gate; tests replace it.
var sharedProductKernel = fullruntime.SharedProductKernel

// NewSharedProductEngine runs IG's product kernel gate now, at agent start,
// loads the image's profile and binds its manifest digest. Any refusal
// leaves an engine that never starts: every Start fails and Health reports
// the reason (wrapping fullruntime.ErrSharedNativeUnavailable); nothing falls
// back to another image or engine. Otherwise the node starts on the first
// Start, through a manager of the borrowed runtime, after running the gate
// and binding the manifest again.
func NewSharedProductEngine(ctx context.Context, rt runtime.Runtime, c SharedProductConfig, onError func(error)) (*SharedEngine, error) {
	if fullruntime.SharedNodeAPIVersion != SharedEngineAPIVersion {
		return nil, fmt.Errorf("IG shared node API version %d, engine requires %d", fullruntime.SharedNodeAPIVersion, SharedEngineAPIVersion)
	}
	if rt == nil || c.Store == nil {
		return nil, fmt.Errorf("runtime and trusted shared image store are required")
	}
	manager, err := instancemanager.New(rt)
	if err != nil {
		return nil, err
	}
	e := newSharedEngine(sharedProduct, nil, onError)
	config, err := selectSharedProduct(ctx, c)
	if err != nil {
		e.refuse(err)
		return e, nil
	}
	e.start = func(ctx context.Context) (sharedNode, error) {
		// The kernel controls can change after agent start, and IG resolves
		// the same reference in the same read-only store: check both again
		// right before the start.
		kernel, err := admitSharedProductKernel()
		if err != nil {
			return nil, err
		}
		if err := verifySharedManifest(ctx, c.Store, c.Image.Image, c.Image.ManifestDigest); err != nil {
			return nil, fmt.Errorf("kernel %s: %w: %w", kernel.Release, err, fullruntime.ErrSharedNativeUnavailable)
		}
		return e.startNode(ctx, manager, config, productHost)
	}
	return e, nil
}

// NewUnavailableSharedEngine returns a product engine refused at agent start
// for reason (for example ErrKernelNotQualified): it never starts, every
// Start fails and Health reports the reason, wrapping
// fullruntime.ErrSharedNativeUnavailable. The reason is reported once.
func NewUnavailableSharedEngine(reason error, onError func(error)) *SharedEngine {
	e := newSharedEngine(sharedProduct, nil, onError)
	e.refuse(reason)
	return e
}

// refuse makes e unavailable for reason. Construction only.
func (e *SharedEngine) refuse(reason error) {
	if !errors.Is(reason, fullruntime.ErrSharedNativeUnavailable) {
		reason = fmt.Errorf("%w: %w", reason, fullruntime.ErrSharedNativeUnavailable)
	}
	e.unavailable = fmt.Errorf("shared product engine unavailable: %w", reason)
	e.start = func(context.Context) (sharedNode, error) { return nil, e.unavailable }
	e.report(e.unavailable)
}

// admitSharedProductKernel runs IG's product kernel gate and refuses a
// malformed admission (an identity that is not amd64 or has an empty field).
// Every refusal wraps fullruntime.ErrSharedNativeUnavailable.
func admitSharedProductKernel() (fullruntime.KernelIdentity, error) {
	kernel, err := sharedProductKernel()
	if err != nil {
		if !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) {
			err = fmt.Errorf("%w: %w", err, fullruntime.ErrSharedNativeUnavailable)
		}
		return fullruntime.KernelIdentity{}, err
	}
	if kernel.Arch != "amd64" || kernel.Release == "" || kernel.BTF == "" || kernel.BuildID == "" {
		return fullruntime.KernelIdentity{}, fmt.Errorf("product kernel gate admitted a malformed kernel identity %+v: %w", kernel, fullruntime.ErrSharedNativeUnavailable)
	}
	return kernel, nil
}

// selectSharedProduct runs IG's product kernel gate, loads the image's
// profile and binds its manifest digest. Every refusal wraps
// fullruntime.ErrSharedNativeUnavailable.
func selectSharedProduct(ctx context.Context, c SharedProductConfig) (SharedEngineConfig, error) {
	kernel, err := admitSharedProductKernel()
	if err != nil {
		return SharedEngineConfig{}, err
	}
	image := c.Image
	var profile fullruntime.SharedProfile
	if image.Profile != nil {
		profile = *image.Profile
	} else if profile, err = LoadSharedProfile(image.ProfileFile); err != nil {
		return SharedEngineConfig{}, fmt.Errorf("kernel %s: %w: %w", kernel.Release, err, fullruntime.ErrSharedNativeUnavailable)
	}
	if err := verifySharedManifest(ctx, c.Store, image.Image, image.ManifestDigest); err != nil {
		return SharedEngineConfig{}, fmt.Errorf("kernel %s: %w: %w", kernel.Release, err, fullruntime.ErrSharedNativeUnavailable)
	}
	return SharedEngineConfig{Profile: profile, Image: image.Image, Store: c.Store, ContainerdAddress: c.ContainerdAddress, ImageProcRoot: c.ImageProcRoot, ImageHostRoot: c.ImageHostRoot}, nil
}

// verifySharedManifest is the agent's start check of a product image:
// selectSharedManifest for the running architecture.
func verifySharedManifest(ctx context.Context, store oras.ReadOnlyTarget, image, expected string) error {
	_, err := selectSharedManifest(ctx, store, image, expected, goruntime.GOARCH)
	return err
}

// selectSharedManifest resolves image the way IG's OCI handler does (its
// normalized name must be an image index; the first manifest of arch is the
// one loaded) and requires that manifest's digest to be expected. The index
// and the manifest are fetched digest- and size-verified, and the manifest
// is returned. An index with a manifest without a platform, or with more
// than one manifest of arch, is refused.
func selectSharedManifest(ctx context.Context, store oras.ReadOnlyTarget, image, expected, arch string) (ocispec.Manifest, error) {
	var manifest ocispec.Manifest
	ref, err := normalizeSharedImage(image)
	if err != nil {
		return manifest, err
	}
	desc, err := store.Resolve(ctx, ref)
	if err != nil {
		return manifest, fmt.Errorf("shared image %q: resolve %q: %w", image, ref, err)
	}
	if desc.MediaType != ocispec.MediaTypeImageIndex {
		return manifest, fmt.Errorf("shared image %q: %s is not an image index", image, desc.MediaType)
	}
	data, err := content.FetchAll(ctx, store, desc)
	if err != nil {
		return manifest, fmt.Errorf("shared image %q: index: %w", image, err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(data, &index); err != nil {
		return manifest, fmt.Errorf("shared image %q: index: %w", image, err)
	}
	var selected []ocispec.Descriptor
	for _, m := range index.Manifests {
		if m.Platform == nil {
			return manifest, fmt.Errorf("shared image %q: index manifest %s has no platform", image, m.Digest)
		}
		if m.Platform.Architecture == arch {
			selected = append(selected, m)
		}
	}
	if len(selected) != 1 {
		return manifest, fmt.Errorf("shared image %q: %d manifests for %s, want 1", image, len(selected), arch)
	}
	if selected[0].Digest.String() != expected {
		return manifest, fmt.Errorf("shared image %q: %w: resolved %s, configured %s", image, ErrSharedManifestMismatch, selected[0].Digest, expected)
	}
	if selected[0].MediaType != ocispec.MediaTypeImageManifest {
		return manifest, fmt.Errorf("shared image %q: manifest %s is %s", image, selected[0].Digest, selected[0].MediaType)
	}
	data, err = content.FetchAll(ctx, store, selected[0])
	if err != nil {
		return manifest, fmt.Errorf("shared image %q: manifest: %w", image, err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("shared image %q: manifest: %w", image, err)
	}
	return manifest, nil
}

// VerifySharedImage is the build-time check of a product image in the
// agent's tracers.tar: the agent's start check for arch (the image's
// architecture, amd64, not the builder's), then every blob the manifest references
// (its config and layers) is fetched digest- and size-verified, so the
// archive cannot ship content other than the pinned image's.
func VerifySharedImage(ctx context.Context, store oras.ReadOnlyTarget, image, expected, arch string) error {
	manifest, err := selectSharedManifest(ctx, store, image, expected, arch)
	if err != nil {
		return err
	}
	for _, blob := range append([]ocispec.Descriptor{manifest.Config}, manifest.Layers...) {
		if _, err := content.FetchAll(ctx, store, blob); err != nil {
			return fmt.Errorf("shared image %q: blob %s: %w", image, blob.Digest, err)
		}
	}
	return nil
}

// normalizeSharedImage is IG's image name normalization (pkg/oci: the IG
// default registry for a name without one, then the tag "latest" if none).
func normalizeSharedImage(image string) (string, error) {
	domain, remainder := oci.SplitIGDomain(image)
	named, err := reference.ParseNormalizedNamed(domain + "/" + remainder)
	if err != nil {
		return "", fmt.Errorf("shared image %q: %w", image, err)
	}
	return reference.TagNameOnly(named).String(), nil
}

func productHost(ctx context.Context, run func(context.Context, gadgetcontext.Option) (func(context.Context) error, <-chan error, error)) context.Context {
	return fullruntime.WithSharedNodeHost(ctx, fullruntime.SharedNodeHost{Run: run})
}
