package igbackend

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestNativeSectionsRefuseUnpinnedManifest(t *testing.T) {
	rt, kube := local.New(), simple.New("no-kubernetes")
	image := "ghcr.io/inspektor-gadget/gadget/fixture:latest"
	store, digest := testImageStore(t, image, &ocispec.Platform{Architecture: runtime.GOARCH})
	for _, section := range []string{sandboxpolicy.SectionPrivilege, sandboxpolicy.SectionNetwork, sandboxpolicy.SectionFile} {
		t.Run(section, func(t *testing.T) {
			var err error
			switch section {
			case sandboxpolicy.SectionPrivilege:
				_, err = NewNativePrivilegeEngine(rt, kube, store, image, nil)
			case sandboxpolicy.SectionNetwork:
				_, err = NewNativeNetworkEngine(rt, kube, store, image, nil)
			case sandboxpolicy.SectionFile:
				_, err = NewNativeFileEngine(rt, kube, store, image, nil)
			}
			var refusal *sandboxpolicy.EnforcementUnavailableError
			if !errors.As(err, &refusal) || refusal.Section != section || refusal.Reason != "SectionImageNotAdmitted" || !strings.Contains(refusal.Detail, digest) {
				t.Fatalf("unexpected admission result: %v", err)
			}
		})
	}
}

func TestAdmittedSectionKeepsResolvedIndex(t *testing.T) {
	ctx := t.Context()
	ref := "ghcr.io/inspektor-gadget/gadget/fixture:latest"
	store, manifests := testImageStoreManifests(t, ref, &ocispec.Platform{Architecture: runtime.GOARCH})
	index, err := store.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := admitSectionImage(ctx, store, "fixture", manifests[0].Digest.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, manifests[0], ref); err != nil {
		t.Fatal(err)
	}
	got, err := bound.Resolve(ctx, ref)
	if err != nil || got.Digest != index.Digest {
		t.Fatalf("admitted index changed after retag: %v %v", got, err)
	}
}

func TestAdmittedSectionVerifiesLayerOnRead(t *testing.T) {
	ctx := t.Context()
	ref := "ghcr.io/inspektor-gadget/gadget/fixture:latest"
	store, pin := testImageStore(t, ref, &ocispec.Platform{Architecture: runtime.GOARCH})
	manifest, err := selectSharedManifest(ctx, store, ref, pin, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	layer := manifest.Layers[0]
	source := &corruptingStore{Store: store}
	bound, err := admitSectionImage(ctx, source, ref, pin)
	if err != nil {
		t.Fatal(err)
	}
	source.target = layer.Digest
	if _, err := admitSectionImage(ctx, source, ref, pin); err == nil {
		t.Fatal("admitted a corrupt layer")
	}
	if rc, err := bound.Fetch(ctx, layer); err == nil {
		rc.Close()
		t.Fatal("returned layer bytes that differ from the admitted manifest")
	}
}
