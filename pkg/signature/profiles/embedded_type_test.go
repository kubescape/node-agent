//go:build experimental_signing

package profiles

import (
	"errors"
	"testing"

	bindingtypes "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	ruletypes "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// alteredContent signs authentic bytes with an intentionally invalid resource
// identity, so tests exercise binding rather than a broken cryptographic hash.
type alteredContent struct {
	signature.SignableObject
	content interface{}
}

func (a alteredContent) GetContent() interface{} { return a.content }

func resourceAdapters() []struct {
	name      string
	newObject func() signature.ResourceSignableObject
	portable  bool
} {
	meta := metav1.ObjectMeta{Name: "shared-name", Namespace: "source"}
	return []struct {
		name      string
		newObject func() signature.ResourceSignableObject
		portable  bool
	}{
		{"ContainerProfile", func() signature.ResourceSignableObject {
			return NewContainerProfileAdapter(&v1beta1.ContainerProfile{ObjectMeta: meta})
		}, true},
		{"SeccompProfile", func() signature.ResourceSignableObject {
			return NewSeccompProfileAdapter(&v1beta1.SeccompProfile{ObjectMeta: meta})
		}, false},
		{"Rules", func() signature.ResourceSignableObject {
			return NewRulesAdapter(&ruletypes.Rules{ObjectMeta: meta})
		}, true},
		{"RuleBinding", func() signature.ResourceSignableObject {
			return NewRuleBindingAdapter(&bindingtypes.RuntimeAlertRuleBinding{ObjectMeta: meta})
		}, true},
	}
}

func signEmbedded(t *testing.T, obj signature.SignableObject) {
	t.Helper()
	if err := signature.SignObject(obj, signature.WithKeyless(false), signature.WithEmbedContent(true)); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedResourceRejectsContainerProfileReplay(t *testing.T) {
	source := NewContainerProfileAdapter(&v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-name", Namespace: "source"},
		Spec:       v1beta1.ContainerProfileSpec{Architectures: []string{"amd64"}},
	})
	signEmbedded(t, source)
	if err := signature.VerifyObjectAllowUntrusted(source); err != nil {
		t.Fatalf("source signature must be valid: %v", err)
	}
	for _, tc := range resourceAdapters()[1:] {
		t.Run(tc.name, func(t *testing.T) {
			target := tc.newObject()
			target.SetAnnotations(source.GetAnnotations())
			// Spoofing the live TypeMeta must not change the expected adapter type.
			carrier := target.GetUpdatedObject().(interface {
				GetObjectKind() schema.ObjectKind
			})
			carrier.GetObjectKind().SetGroupVersionKind(schema.GroupVersionKind{
				Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Kind: "ContainerProfile",
			})
			if err := signature.VerifyObjectAllowUntrusted(target); !errors.Is(err, signature.ErrSignatureMismatch) {
				t.Fatalf("cross-resource replay must fail as tampering: %v", err)
			}
		})
	}
}

func TestEmbeddedResourceRequiresExpectedType(t *testing.T) {
	for _, tc := range resourceAdapters() {
		t.Run(tc.name, func(t *testing.T) {
			for _, field := range []string{"apiVersion", "kind"} {
				for _, value := range []string{"", "other"} {
					t.Run(field+"/"+value, func(t *testing.T) {
						obj := tc.newObject()
						content := obj.GetContent().(map[string]interface{})
						if value == "" {
							delete(content, field)
						} else {
							content[field] = value
						}
						signEmbedded(t, alteredContent{SignableObject: obj, content: content})
						if err := signature.VerifyObjectAllowUntrusted(obj); !errors.Is(err, signature.ErrSignatureMismatch) {
							t.Fatalf("missing or mismatched %s must fail: %v", field, err)
						}
					})
				}
			}
		})
	}
}

func TestEmbeddedResourceEmptyTypeMetaAndNamespacePortability(t *testing.T) {
	for _, tc := range resourceAdapters() {
		t.Run(tc.name, func(t *testing.T) {
			obj := tc.newObject()
			content := obj.GetContent().(map[string]interface{})
			apiVersion, kind := obj.ExpectedResourceType()
			if content["apiVersion"] != apiVersion || content["kind"] != kind {
				t.Fatal("empty TypeMeta must use the expected resource type")
			}
			signEmbedded(t, obj)
			if err := signature.VerifyObjectAllowUntrusted(obj); err != nil {
				t.Fatalf("canonical fallback must verify: %v", err)
			}
			obj.GetUpdatedObject().(interface{ SetNamespace(string) }).SetNamespace("destination")
			err := signature.VerifyObjectAllowUntrusted(obj)
			if tc.portable && err != nil {
				t.Fatalf("same-kind relocation must remain portable: %v", err)
			}
			if !tc.portable && !errors.Is(err, signature.ErrSignatureMismatch) {
				t.Fatalf("namespace-bound resource relocation must fail: %v", err)
			}
		})
	}
}
