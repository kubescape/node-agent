package igbackend

import (
	"bytes"
	"context"
	"fmt"
	"io"
	goruntime "runtime"

	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
)

// These amd64 manifests are built by make gadgets with IG v0.57.0 and
// SOURCE_DATE_EPOCH=0. Review and rotate a pin when its gadget changes.
var sectionManifests = map[string]string{
	sandboxpolicy.SectionPrivilege: "sha256:a22d4922017cd95556b222cabc6de9838db957683a24019c3a7f3b9cefb6fc6c",
	sandboxpolicy.SectionNetwork:   "sha256:0104faebaa04f7ff8ecf5279c5119ccc8a731d5bd689596861bd937db91b15c2",
	sandboxpolicy.SectionFile:      "sha256:710b9c35fd19a43e3752353e84c7d2928f100182d87ff7a59f0f5612e4835823",
}

// VerifySectionImages checks the release archive with the same manifest
// selection and blob verification as the exec product image.
func VerifySectionImages(ctx context.Context, store oras.ReadOnlyTarget) error {
	for section, pin := range sectionManifests {
		if err := VerifySharedImage(ctx, store, "enforce_"+section+":latest", pin, "amd64"); err != nil {
			return err
		}
	}
	return nil
}

// sectionImageStore keeps the resolved index for the lifetime of the engine.
// Admission, IG and restart identity all resolve the same descriptor even if
// a caller retags its backing store between construction and Start.
type sectionImageStore struct {
	content.ReadOnlyStorage
	ref   string
	index ocispec.Descriptor
}

func (s sectionImageStore) Resolve(_ context.Context, name string) (ocispec.Descriptor, error) {
	ref, err := normalizeSharedImage(name)
	if err != nil || ref != s.ref {
		return ocispec.Descriptor{}, fmt.Errorf("unexpected section image %q (want %q)", name, s.ref)
	}
	return s.index, nil
}

// IG consumes Fetch streams directly. Verify the bytes it receives against
// the descriptor, including the config and eBPF layers of the pinned manifest.
func (s sectionImageStore) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	data, err := content.FetchAll(ctx, s.ReadOnlyStorage, desc)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func admitSectionImage(ctx context.Context, store oras.ReadOnlyTarget, image, pin string) (sectionImageStore, error) {
	ref, err := normalizeSharedImage(image)
	if err != nil {
		return sectionImageStore{}, err
	}
	index, err := store.Resolve(ctx, ref)
	if err != nil {
		return sectionImageStore{}, fmt.Errorf("resolve %q: %w", ref, err)
	}
	bound := sectionImageStore{ReadOnlyStorage: store, ref: ref, index: index}
	if err := VerifySharedImage(ctx, bound, image, pin, goruntime.GOARCH); err != nil {
		return sectionImageStore{}, err
	}
	return bound, nil
}

func newNativeNodeEngine(rt runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, image, section string, report SectionReporter) (nativeNodeEngine, error) {
	if rt == nil || kube == nil || store == nil || image == "" {
		return nativeNodeEngine{}, fmt.Errorf("runtime, Kubernetes operator, OCI store and %s image are required", section)
	}
	bound, err := admitSectionImage(context.Background(), store, image, sectionManifests[section])
	if err != nil {
		return nativeNodeEngine{}, &sandboxpolicy.EnforcementUnavailableError{Section: section, Reason: "SectionImageNotAdmitted", Detail: err.Error()}
	}
	manager, err := instancemanager.New(rt)
	if err != nil {
		return nativeNodeEngine{}, err
	}
	return nativeNodeEngine{manager: manager, kube: kube, store: bound, image: image, report: report}, nil
}
