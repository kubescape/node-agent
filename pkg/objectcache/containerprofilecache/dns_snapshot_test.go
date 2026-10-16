package containerprofilecache

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/require"
)

func TestDNSProfileSnapshotKeepsStateAndProjectionTogether(t *testing.T) {
	cache, _ := newTestCache(t, &fakeProfileClient{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10000; i++ {
			for _, version := range []string{"authored", "learned"} {
				cache.entries.Set("container", &CachedContainerProfile{
					State:     &objectcache.ProfileState{Name: version},
					Projected: &objectcache.ProjectedContainerProfile{SpecHash: version},
				})
			}
		}
	}()
	// Join the writer even when an assertion stops this test.
	defer func() { <-done }()
	for i := 0; i < 10000; i++ {
		projection, state := cache.GetContainerProfileSnapshot("container")
		if projection == nil {
			continue
		}
		require.NotNil(t, state)
		require.Equal(t, projection.SpecHash, state.Name)
	}
	projection, state := cache.GetContainerProfileSnapshot("missing")
	require.Nil(t, projection)
	require.Error(t, state.Error)
}
