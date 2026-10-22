//go:build experimental_signing

package signature

import (
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
)

type resourceAnnotationFixture struct{ *MockSignableObject }

func (*resourceAnnotationFixture) ExpectedResourceType() (string, string) { return "v1", "Example" }

func TestSignResourceAnnotationsRejectOverflowAtomically(t *testing.T) {
	for _, embed := range []bool{false, true} {
		t.Run(map[bool]string{false: "signature", true: "embedded"}[embed], func(t *testing.T) {
			obj := &resourceAnnotationFixture{embeddedObjectAtSize(t, 100)}
			obj.SetAnnotations(map[string]string{"existing": strings.Repeat("x", apivalidation.TotalAnnotationSizeLimitB-len("existing")), AnnotationSignature: "old-signature", AnnotationContent: "old-content"})
			before := maps.Clone(obj.GetAnnotations())
			err := SignObject(obj, WithKeyless(false), WithEmbedContent(embed))
			require.ErrorContains(t, err, "Kubernetes annotation limit")
			require.Equal(t, before, obj.GetAnnotations())
		})
	}
}

func TestPublishSignedAnnotationsResourceBoundary(t *testing.T) {
	// Generate authentic signature/certificate/content annotations once; their
	// variable-length encoding must count toward the resource's total budget.
	signedObj := embeddedObjectAtSize(t, 100)
	require.NoError(t, SignObject(signedObj, WithKeyless(false), WithEmbedContent(true)))
	signed := signedObj.GetAnnotations()
	signedSize := 0
	for k, v := range signed {
		signedSize += len(k) + len(v)
	}
	for _, extra := range []int{0, 1} {
		t.Run(map[int]string{0: "exact limit", 1: "one byte over"}[extra], func(t *testing.T) {
			obj := &resourceAnnotationFixture{embeddedObjectAtSize(t, 100)}
			obj.SetAnnotations(map[string]string{"existing": strings.Repeat("x", apivalidation.TotalAnnotationSizeLimitB-signedSize-len("existing")+extra)})
			before := maps.Clone(obj.GetAnnotations())
			alias := obj.GetAnnotations()
			err := publishSignedAnnotations(obj, signed)
			require.Equal(t, before, alias, "publication must never mutate the original annotation map")
			if extra == 0 {
				require.NoError(t, err)
				require.NoError(t, apivalidation.ValidateAnnotationsSize(obj.GetAnnotations()))
				require.Equal(t, signed[AnnotationCertificate], obj.GetAnnotations()[AnnotationCertificate])
			} else {
				require.ErrorContains(t, err, "262145")
				require.Equal(t, before, obj.GetAnnotations())
			}
		})
	}
	t.Run("nil remains nil on rejection", func(t *testing.T) {
		obj := &resourceAnnotationFixture{embeddedObjectAtSize(t, 100)}
		obj.SetAnnotations(nil)
		require.Error(t, publishSignedAnnotations(obj, map[string]string{AnnotationContent: strings.Repeat("x", apivalidation.TotalAnnotationSizeLimitB)}))
		require.Nil(t, obj.GetAnnotations())
	})
}

func TestSignNonResourceHasNoKubernetesAnnotationLimit(t *testing.T) {
	obj := embeddedObjectAtSize(t, 100)
	obj.SetAnnotations(map[string]string{"existing": strings.Repeat("x", apivalidation.TotalAnnotationSizeLimitB)})
	require.NoError(t, SignObject(obj, WithKeyless(false), WithEmbedContent(true)))
	require.NoError(t, VerifyObjectAllowUntrusted(obj))
}
