package containerprofilecache

import (
	"sync"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

func TestApplyCacheGenerationUniqueAcrossConcurrentRebuilds(t *testing.T) {
	const builds = 32
	generations := make(chan uint64, builds)
	var wg sync.WaitGroup
	profile := &v1beta1.ContainerProfile{}
	for range builds {
		wg.Go(func() { generations <- Apply(nil, profile, nil).CacheGeneration })
	}
	wg.Wait()
	close(generations)
	seen := make(map[uint64]bool, builds)
	for generation := range generations {
		require.NotZero(t, generation)
		require.False(t, seen[generation], "each rebuild needs a fresh CEL cache key")
		seen[generation] = true
	}
}
