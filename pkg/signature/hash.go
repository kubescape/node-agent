//go:build experimental_signing

package signature

import (
	"encoding/json"
	"fmt"

	"github.com/kubescape/storage/pkg/utils"
)

// HashSignableContent returns the canonical content hash of a SignableObject —
// the exact hash that Sign/Verify compute over (json.Marshal of GetContent
// through utils.CanonicalHash, order-independent). Exposed so the bundle layer
// can derive a fragment's leaf digest identically to what its signature covers.
func HashSignableContent(obj SignableObject) (string, error) {
	if obj == nil {
		return "", fmt.Errorf("nil object")
	}
	data, err := json.Marshal(obj.GetContent())
	if err != nil {
		return "", fmt.Errorf("failed to marshal object: %w", err)
	}
	return utils.CanonicalHash(data)
}

// HashBytes returns the canonical hash of raw content bytes — the same hash
// Sign/Verify compute for embedded content.
func HashBytes(content []byte) (string, error) {
	return utils.CanonicalHash(content)
}
