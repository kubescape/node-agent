//go:build experimental_signing

package signature

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func embeddedObjectAtSize(t *testing.T, size int) *MockSignableObject {
	t.Helper()
	content := map[string]interface{}{
		"metadata": map[string]string{"name": "boundary", "namespace": "ns"},
		"spec":     "",
	}
	empty, err := json.Marshal(content)
	require.NoError(t, err)
	content["spec"] = strings.Repeat("x", size-len(empty))
	encoded, err := json.Marshal(content)
	require.NoError(t, err)
	require.Len(t, encoded, size)
	return NewMockSignableObject("uid", "ns", "boundary", content)
}

func TestSignEmbeddedContentSizeBoundary(t *testing.T) {
	t.Run("exact limit round trip", func(t *testing.T) {
		obj := embeddedObjectAtSize(t, maxEmbeddedContentBytes)
		require.NoError(t, SignObject(obj, WithKeyless(false), WithEmbedContent(true)))
		embedded, present, err := EmbeddedContent(obj)
		require.NoError(t, err)
		require.True(t, present)
		require.Len(t, embedded, maxEmbeddedContentBytes)
		require.NoError(t, VerifyObjectAllowUntrusted(obj))
	})
	for _, existing := range []bool{false, true} {
		name := "over limit unsigned"
		if existing {
			name = "over limit preserves annotations"
		}
		t.Run(name, func(t *testing.T) {
			obj := embeddedObjectAtSize(t, maxEmbeddedContentBytes+1)
			if existing {
				obj.SetAnnotations(map[string]string{AnnotationSignature: "old-signature", AnnotationContent: "old-content", "unrelated": "retained"})
			}
			before := maps.Clone(obj.GetAnnotations())
			err := SignObject(obj, WithKeyless(false), WithEmbedContent(true))
			require.ErrorContains(t, err, "embedded content exceeds")
			require.Equal(t, before, obj.GetAnnotations(), "rejection must leave all annotations untouched")
		})
	}
}
