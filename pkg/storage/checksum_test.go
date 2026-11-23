package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKnownChecksumContext(t *testing.T) {
	baseCtx := context.Background()
	assert.Equal(t, "", KnownChecksumFromContext(baseCtx))

	ctxWithChecksum := WithKnownChecksum(baseCtx, "sha256:1234567890abcdef")
	assert.Equal(t, "sha256:1234567890abcdef", KnownChecksumFromContext(ctxWithChecksum))

	// Parent context remains unmodified
	assert.Equal(t, "", KnownChecksumFromContext(baseCtx))

	// Overwriting checksum in derived context updates value
	updatedCtx := WithKnownChecksum(ctxWithChecksum, "sha256:fedcba0987654321")
	assert.Equal(t, "sha256:fedcba0987654321", KnownChecksumFromContext(updatedCtx))
	assert.Equal(t, "sha256:1234567890abcdef", KnownChecksumFromContext(ctxWithChecksum))
}
