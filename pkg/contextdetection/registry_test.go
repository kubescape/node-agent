package contextdetection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubContextInfo struct {
	ctx        EventSourceContext
	workloadID string
}

func (s *stubContextInfo) Context() EventSourceContext {
	return s.ctx
}

func (s *stubContextInfo) WorkloadID() string {
	return s.workloadID
}

func TestMntnsRegistry_RegisterAndLookup(t *testing.T) {
	reg := NewMntnsRegistry()
	require.NotNil(t, reg)

	info1 := &stubContextInfo{ctx: Kubernetes, workloadID: "default/nginx"}
	info2 := &stubContextInfo{ctx: Standalone, workloadID: "redis:12345"}

	// Zero mntns must be rejected
	err := reg.Register(0, info1)
	assert.ErrorIs(t, err, ErrInvalidMntns)

	// Unknown mntns lookup
	got, ok := reg.Lookup(100)
	assert.False(t, ok)
	assert.Nil(t, got)

	// Valid registration
	err = reg.Register(100, info1)
	require.NoError(t, err)

	got, ok = reg.Lookup(100)
	require.True(t, ok)
	assert.Equal(t, Kubernetes, got.Context())
	assert.Equal(t, "default/nginx", got.WorkloadID())

	// Duplicate registration is skipped and keeps the original entry
	err = reg.Register(100, info2)
	require.NoError(t, err)

	got, ok = reg.Lookup(100)
	require.True(t, ok)
	assert.Equal(t, Kubernetes, got.Context())
	assert.Equal(t, "default/nginx", got.WorkloadID())
}

func TestMntnsRegistry_Unregister(t *testing.T) {
	reg := NewMntnsRegistry()
	info1 := &stubContextInfo{ctx: Host, workloadID: "node-1"}
	info2 := &stubContextInfo{ctx: Standalone, workloadID: "worker:abc"}

	// Unregistering a non-existent entry is a no-op
	reg.Unregister(999)

	require.NoError(t, reg.Register(200, info1))
	_, ok := reg.Lookup(200)
	require.True(t, ok)

	// Unregister removes the entry
	reg.Unregister(200)
	got, ok := reg.Lookup(200)
	assert.False(t, ok)
	assert.Nil(t, got)

	// Re-registering after unregister succeeds with the new info
	require.NoError(t, reg.Register(200, info2))
	got, ok = reg.Lookup(200)
	require.True(t, ok)
	assert.Equal(t, Standalone, got.Context())
	assert.Equal(t, "worker:abc", got.WorkloadID())
}
