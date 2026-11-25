package integration

import (
	"encoding/json"
	"runtime"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
)

func TestUnpinnedPrivilegeImageReportsNotReady(t *testing.T) {
	ctx := t.Context()
	store := memory.New()
	manifest, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, "application/example", oras.PackManifestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	manifest.Platform = &ocispec.Platform{OS: "linux", Architecture: runtime.GOARCH}
	data, err := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{manifest}})
	if err != nil {
		t.Fatal(err)
	}
	index, err := oras.PushBytes(ctx, store, ocispec.MediaTypeImageIndex, data)
	if err != nil {
		t.Fatal(err)
	}
	const ref = "ghcr.io/inspektor-gadget/gadget/enforce_privilege:latest"
	if err := store.Tag(ctx, index, ref); err != nil {
		t.Fatal(err)
	}
	engine, refusal := igbackend.NewNativePrivilegeEngine(local.New(), simple.New("no-kubernetes"), store, ref, nil)
	if engine != nil || refusal == nil {
		t.Fatal("expected the constructor to refuse the unpinned image")
	}

	s, exec := testService(t)
	policies := s.options.Dynamic.Resource(sandboxpolicy.PolicyGVR).Namespace("ns")
	policy, err := policies.Get(ctx, "test", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedMap(policy.Object, map[string]any{"default": "deny"}, "spec", "privilege"); err != nil {
		t.Fatal(err)
	}
	if _, err := policies.Update(ctx, policy, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	sections, err := sandboxpolicy.NewSectionBackend(exec, nil, refusal)
	if err != nil {
		t.Fatal(err)
	}
	writer := &readinessCapture{}
	controller, err := sandboxpolicy.NewController(s.options.Dynamic, sections, nil, writer, sandboxpolicy.Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(writer.reports) != 1 || len(writer.reports[0].Status.Conditions) == 0 {
		t.Fatalf("expected a policy status, got %+v", writer.reports)
	}
	ready := writer.reports[0].Status.Conditions[0]
	if ready.Type != "Ready" || ready.Status != metav1.ConditionFalse || ready.Reason != "SectionImageNotAdmitted" {
		t.Fatalf("unexpected readiness after image refusal: %+v", ready)
	}
}
