package igbackend

// G020 shared node engine, product start (default build): the image is
// selected for the running kernel build at agent start, its manifest digest
// is bound, and the node starts through fullruntime.WithSharedNodeHost (IG
// admits only an exact pinned kernel build and the pinned product image).

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

// ErrKernelNotQualified: the running kernel is not one of the agent's
// compiled-in qualified kernel builds (its architecture, BTF sha256, release
// or GNU build-id differs). Health reports it with reason KernelNotQualified.
var ErrKernelNotQualified = errors.New("running kernel is not a qualified kernel build")

// SharedProductImage is one kernel build's product image: the image
// reference in Store, the profile it was built with (Profile when set, else
// the JSON at ProfileFile) and the digest of its manifest for this
// architecture.
type SharedProductImage struct {
	Image, ProfileFile, ManifestDigest string
	Profile                            *fullruntime.SharedProfile
}

// SharedProductConfig is the product engine's administrator configuration.
type SharedProductConfig struct {
	// Images is keyed by kernel BTF sha256.
	Images map[string]SharedProductImage
	// Store is the agent's read-only image archive.
	Store oras.ReadOnlyTarget
	// ContainerdAddress, ImageProcRoot and ImageHostRoot as in
	// SharedEngineConfig.
	ContainerdAddress            string
	ImageProcRoot, ImageHostRoot string
}

// NewSharedProductEngine selects the running kernel build's image now, at
// agent start (fullruntime.SelectSharedProductImage), loads its profile and
// binds its manifest digest. Any refusal leaves an engine that never starts:
// every Start fails and Health reports the reason (wrapping
// fullruntime.ErrSharedNativeUnavailable); nothing falls back to another
// image or engine. Otherwise the node starts on the first Start, through a
// manager of the borrowed runtime, after binding the manifest again.
func NewSharedProductEngine(ctx context.Context, rt runtime.Runtime, c SharedProductConfig, onError func(error)) (*SharedEngine, error) {
	return newSharedProductEngine(ctx, rt, c, onError, fullruntime.SelectSharedProductImage[SharedProductImage])
}

func newSharedProductEngine(ctx context.Context, rt runtime.Runtime, c SharedProductConfig, onError func(error), selectImage func(map[string]SharedProductImage) (string, SharedProductImage, error)) (*SharedEngine, error) {
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
	config, image, err := selectSharedProduct(ctx, c, selectImage)
	if err != nil {
		e.refuse(err)
		return e, nil
	}
	e.start = func(ctx context.Context) (sharedNode, error) {
		// IG resolves the same reference in the same read-only store; bind it
		// again right before the start.
		if err := verifySharedManifest(ctx, c.Store, image.Image, image.ManifestDigest); err != nil {
			return nil, err
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

// selectSharedProduct selects the running kernel's entry, loads its profile
// and binds its manifest digest. Every refusal wraps
// fullruntime.ErrSharedNativeUnavailable.
func selectSharedProduct(ctx context.Context, c SharedProductConfig, selectImage func(map[string]SharedProductImage) (string, SharedProductImage, error)) (SharedEngineConfig, SharedProductImage, error) {
	btf, image, err := selectImage(c.Images)
	if err != nil {
		if !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) {
			err = fmt.Errorf("%w: %w", err, fullruntime.ErrSharedNativeUnavailable)
		}
		return SharedEngineConfig{}, image, err
	}
	var profile fullruntime.SharedProfile
	if image.Profile != nil {
		profile = *image.Profile
	} else if profile, err = LoadSharedProfile(image.ProfileFile); err != nil {
		return SharedEngineConfig{}, image, fmt.Errorf("kernel BTF %s: %w: %w", btf, err, fullruntime.ErrSharedNativeUnavailable)
	}
	if err := verifySharedManifest(ctx, c.Store, image.Image, image.ManifestDigest); err != nil {
		return SharedEngineConfig{}, image, fmt.Errorf("kernel BTF %s: %w: %w", btf, err, fullruntime.ErrSharedNativeUnavailable)
	}
	return SharedEngineConfig{Profile: profile, Image: image.Image, Store: c.Store, ContainerdAddress: c.ContainerdAddress, ImageProcRoot: c.ImageProcRoot, ImageHostRoot: c.ImageHostRoot}, image, nil
}

// verifySharedManifest resolves image the way IG's OCI handler does (its
// normalized name must be an image index; the first manifest of this
// architecture is the one loaded) and requires that manifest's digest to be
// expected. The index and the manifest are fetched digest- and
// size-verified. An index with a manifest without a platform, or with more
// than one manifest of this architecture, is refused.
func verifySharedManifest(ctx context.Context, store oras.ReadOnlyTarget, image, expected string) error {
	ref, err := normalizeSharedImage(image)
	if err != nil {
		return err
	}
	desc, err := store.Resolve(ctx, ref)
	if err != nil {
		return fmt.Errorf("shared image %q: resolve %q: %w", image, ref, err)
	}
	if desc.MediaType != ocispec.MediaTypeImageIndex {
		return fmt.Errorf("shared image %q: %s is not an image index", image, desc.MediaType)
	}
	data, err := content.FetchAll(ctx, store, desc)
	if err != nil {
		return fmt.Errorf("shared image %q: index: %w", image, err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(data, &index); err != nil {
		return fmt.Errorf("shared image %q: index: %w", image, err)
	}
	var selected []ocispec.Descriptor
	for _, m := range index.Manifests {
		if m.Platform == nil {
			return fmt.Errorf("shared image %q: index manifest %s has no platform", image, m.Digest)
		}
		if m.Platform.Architecture == goruntime.GOARCH {
			selected = append(selected, m)
		}
	}
	if len(selected) != 1 {
		return fmt.Errorf("shared image %q: %d manifests for %s, want 1", image, len(selected), goruntime.GOARCH)
	}
	if selected[0].Digest.String() != expected {
		return fmt.Errorf("shared image %q: %w: resolved %s, configured %s", image, ErrSharedManifestMismatch, selected[0].Digest, expected)
	}
	if selected[0].MediaType != ocispec.MediaTypeImageManifest {
		return fmt.Errorf("shared image %q: manifest %s is %s", image, selected[0].Digest, selected[0].MediaType)
	}
	if _, err := content.FetchAll(ctx, store, selected[0]); err != nil {
		return fmt.Errorf("shared image %q: manifest: %w", image, err)
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
