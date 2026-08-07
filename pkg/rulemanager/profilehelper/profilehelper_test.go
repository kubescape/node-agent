package profilehelper

import (
	"testing"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func newMock() *objectcachev1.RuleObjectCacheMock {
	return &objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
}

// TestGetProjectedContainerProfile covers the success and no-profile paths.
func TestGetProjectedContainerProfile(t *testing.T) {
	t.Run("profile available", func(t *testing.T) {
		objCache := newMock()
		objCache.SetSharedContainerData("cid", &objectcache.WatchedContainerData{
			ContainerType: objectcache.Container,
			ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
				objectcache.Container: {{Name: "c"}},
			},
		})
		profile := &v1beta1.ContainerProfile{}
		profile.Spec = v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{{Path: "/bin/ls"}},
		}
		objCache.SetContainerProfile(profile)

		pcp, checksum, err := GetProjectedContainerProfile(objCache, "cid")
		require.NoError(t, err)
		require.NotNil(t, pcp)
		assert.Equal(t, pcp.SyncChecksum, checksum)
		_, ok := pcp.Execs.Values["/bin/ls"]
		assert.True(t, ok, "projected profile should carry the exec path")
	})

	t.Run("no profile available", func(t *testing.T) {
		objCache := newMock()
		pcp, _, err := GetProjectedContainerProfile(objCache, "cid")
		assert.Error(t, err)
		assert.Nil(t, pcp)
	})
}

// TestGetPodSpec covers success, missing shared data, and missing pod spec.
func TestGetPodSpec(t *testing.T) {
	t.Run("pod spec available", func(t *testing.T) {
		objCache := newMock()
		objCache.SetSharedContainerData("cid", &objectcache.WatchedContainerData{
			ContainerType: objectcache.Container,
			ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
				objectcache.Container: {{Name: "c"}},
			},
		})
		want := &corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}
		objCache.SetPodSpec(want)

		got, err := GetPodSpec(objCache, "cid")
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("shared data not found", func(t *testing.T) {
		objCache := newMock() // no shared data registered
		got, err := GetPodSpec(objCache, "cid")
		assert.Error(t, err)
		assert.Nil(t, got)
	})

	t.Run("pod spec not found", func(t *testing.T) {
		objCache := newMock()
		objCache.SetSharedContainerData("cid", &objectcache.WatchedContainerData{
			ContainerType: objectcache.Container,
		})
		// no SetPodSpec -> GetPodSpec returns nil -> error
		got, err := GetPodSpec(objCache, "cid")
		assert.Error(t, err)
		assert.Nil(t, got)
	})
}

// TestGetContainerName covers name resolution and both lookup-failure paths.
func TestGetContainerName(t *testing.T) {
	t.Run("name resolved", func(t *testing.T) {
		objCache := newMock()
		objCache.SetSharedContainerData("cid", &objectcache.WatchedContainerData{
			ContainerType: objectcache.Container,
			ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
				objectcache.Container: {{Name: "my-container"}},
			},
		})
		assert.Equal(t, "my-container", GetContainerName(objCache, "cid"))
	})

	t.Run("no shared data", func(t *testing.T) {
		objCache := newMock()
		assert.Equal(t, "", GetContainerName(objCache, "cid"))
	})

	t.Run("empty container infos", func(t *testing.T) {
		objCache := newMock()
		objCache.SetSharedContainerData("cid", &objectcache.WatchedContainerData{
			ContainerType:  objectcache.Container,
			ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{},
		})
		assert.Equal(t, "", GetContainerName(objCache, "cid"))
	})
}
