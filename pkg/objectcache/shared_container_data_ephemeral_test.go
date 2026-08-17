package objectcache

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetContainerInfo_ClassifiesEphemeralContainer pins that an ephemeral
// container is enumerated and typed as EphemeralContainer, so the learning
// manager receives it and treats it like any other container.
func TestSetContainerInfo_ClassifiesEphemeralContainer(t *testing.T) {
	pod := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "victim", "namespace": "ns"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{"name": "app", "image": "debian:12-slim"},
			},
			"ephemeralContainers": []interface{}{
				map[string]interface{}{"name": "ephcon", "image": "debian:12-slim"},
			},
		},
		"status": map[string]interface{}{
			"containerStatuses": []interface{}{
				map[string]interface{}{"name": "app", "imageID": "docker.io/app@sha256:aaa"},
			},
			"ephemeralContainerStatuses": []interface{}{
				map[string]interface{}{"name": "ephcon", "imageID": "docker.io/eph@sha256:bbb"},
			},
		},
	}
	wl := workloadinterface.NewWorkloadObj(pod)
	require.NotNil(t, wl)

	eph := &WatchedContainerData{ContainerInfos: map[ContainerType][]ContainerInfo{}}
	require.NoError(t, eph.SetContainerInfo(wl, "ephcon"))
	assert.Equal(t, ContainerType(EphemeralContainer), eph.ContainerType,
		"an ephemeral container must be classified as EphemeralContainer (so it reaches the learning path)")
	assert.NotEmpty(t, eph.ContainerInfos[EphemeralContainer], "the ephemeral subtype must be enumerated")

	reg := &WatchedContainerData{ContainerInfos: map[ContainerType][]ContainerInfo{}}
	require.NoError(t, reg.SetContainerInfo(wl, "app"))
	assert.Equal(t, ContainerType(Container), reg.ContainerType, "a regular container stays Container-typed")
}
