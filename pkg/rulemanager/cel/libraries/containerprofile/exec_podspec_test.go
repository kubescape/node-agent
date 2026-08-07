package containerprofile

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// newExecPodSpecCache builds a RuleObjectCacheMock with shared container data
// for "test-container-id" (container name "test-container") and the supplied
// PodSpec. Used to exercise isExecInPodSpec, which is the podspec-exempt
// branch feeding wasExecuted / wasExecutedWithArgs.
func newExecPodSpecCache(podSpec *corev1.PodSpec) *objectcachev1.RuleObjectCacheMock {
	objCache := &objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: "test-container"}},
		},
	})
	if podSpec != nil {
		objCache.SetPodSpec(podSpec)
	}
	return objCache
}

// TestIsExecInPodSpec covers the allow-path of the podspec exemption:
// an exec whose path equals a container's Command entry (or a lifecycle
// hook command) is exempt (true); a path that matches nothing is not
// exempt (false); and the two lookup-failure guards (missing pod spec,
// unresolvable container name) both answer false.
func TestIsExecInPodSpec(t *testing.T) {
	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:    "test-container",
				Command: []string{"/bin/sh", "/entrypoint.sh"},
				Lifecycle: &corev1.Lifecycle{
					PreStop: &corev1.LifecycleHandler{
						Exec: &corev1.ExecAction{Command: []string{"/bin/prestop"}},
					},
					PostStart: &corev1.LifecycleHandler{
						Exec: &corev1.ExecAction{Command: []string{"/bin/poststart"}},
					},
				},
			},
			{
				Name:    "other-container",
				Command: []string{"/bin/other"},
			},
		},
		InitContainers: []corev1.Container{
			{Name: "test-container", Command: []string{"/bin/init"}},
		},
	}

	t.Run("path matches container command -> exempt", func(t *testing.T) {
		lib := &containerProfileLibrary{objectCache: newExecPodSpecCache(podSpec), preStopCache: NewPreStopHookCache(DefaultPreStopCacheSize, DefaultPreStopCacheTTL)}
		got := lib.isExecInPodSpec(types.String("test-container-id"), types.String("/bin/sh"))
		assert.Equal(t, types.Bool(true), got)
	})

	t.Run("second command entry matches -> exempt", func(t *testing.T) {
		lib := &containerProfileLibrary{objectCache: newExecPodSpecCache(podSpec), preStopCache: NewPreStopHookCache(DefaultPreStopCacheSize, DefaultPreStopCacheTTL)}
		got := lib.isExecInPodSpec(types.String("test-container-id"), types.String("/entrypoint.sh"))
		assert.Equal(t, types.Bool(true), got)
	})

	t.Run("prestop hook command matches -> exempt", func(t *testing.T) {
		lib := &containerProfileLibrary{objectCache: newExecPodSpecCache(podSpec), preStopCache: NewPreStopHookCache(DefaultPreStopCacheSize, DefaultPreStopCacheTTL)}
		got := lib.isExecInPodSpec(types.String("test-container-id"), types.String("/bin/prestop"))
		assert.Equal(t, types.Bool(true), got)
	})

	t.Run("poststart hook command matches -> exempt", func(t *testing.T) {
		lib := &containerProfileLibrary{objectCache: newExecPodSpecCache(podSpec), preStopCache: NewPreStopHookCache(DefaultPreStopCacheSize, DefaultPreStopCacheTTL)}
		got := lib.isExecInPodSpec(types.String("test-container-id"), types.String("/bin/poststart"))
		assert.Equal(t, types.Bool(true), got)
	})

	t.Run("path not in matching container -> not exempt", func(t *testing.T) {
		// /bin/init belongs to the init container of the same name, but the
		// primary container match returns first and short-circuits to false.
		lib := &containerProfileLibrary{objectCache: newExecPodSpecCache(podSpec), preStopCache: NewPreStopHookCache(DefaultPreStopCacheSize, DefaultPreStopCacheTTL)}
		got := lib.isExecInPodSpec(types.String("test-container-id"), types.String("/bin/nonexistent"))
		assert.Equal(t, types.Bool(false), got)
	})

	t.Run("pod spec lookup failure -> false", func(t *testing.T) {
		// Shared data present but no pod spec installed: GetPodSpec errors.
		lib := &containerProfileLibrary{objectCache: newExecPodSpecCache(nil), preStopCache: NewPreStopHookCache(DefaultPreStopCacheSize, DefaultPreStopCacheTTL)}
		got := lib.isExecInPodSpec(types.String("test-container-id"), types.String("/bin/sh"))
		assert.Equal(t, types.Bool(false), got)
	})

	t.Run("container name lookup failure -> false", func(t *testing.T) {
		// Shared data with empty ContainerInfos -> GetContainerName == "".
		objCache := &objectcachev1.RuleObjectCacheMock{
			ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
		}
		objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
			ContainerType:  objectcache.Container,
			ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{},
		})
		objCache.SetPodSpec(podSpec)
		lib := &containerProfileLibrary{objectCache: objCache, preStopCache: NewPreStopHookCache(DefaultPreStopCacheSize, DefaultPreStopCacheTTL)}
		got := lib.isExecInPodSpec(types.String("test-container-id"), types.String("/bin/sh"))
		assert.Equal(t, types.Bool(false), got)
	})

	t.Run("nil object cache -> error", func(t *testing.T) {
		lib := &containerProfileLibrary{objectCache: nil}
		got := lib.isExecInPodSpec(types.String("test-container-id"), types.String("/bin/sh"))
		assert.True(t, types.IsError(got))
	})
}

// TestWasExecutedPodSpecExempt pins the podspec-exempt fall-through of
// wasExecuted: a profile that does NOT list the exec path still answers
// true when that path is a container Command entry in the pod spec.
func TestWasExecutedPodSpecExempt(t *testing.T) {
	objCache := newExecPodSpecCache(&corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "test-container", Command: []string{"/bin/sh"}},
		},
	})
	// Profile present (so projection succeeds) but path absent from Execs.
	profile := &v1beta1.ContainerProfile{}
	profile.Spec = v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/bin/ls", Args: []string{"-la"}}},
	}
	objCache.SetContainerProfile(profile)

	lib := &containerProfileLibrary{objectCache: objCache, preStopCache: NewPreStopHookCache(DefaultPreStopCacheSize, DefaultPreStopCacheTTL)}

	// /bin/sh is not in the profile Execs but IS the pod spec command.
	assert.Equal(t, types.Bool(true),
		lib.wasExecuted(types.String("test-container-id"), types.String("/bin/sh")),
		"exec exempt via pod spec command")

	// /bin/other is in neither the profile nor the pod spec.
	assert.Equal(t, types.Bool(false),
		lib.wasExecuted(types.String("test-container-id"), types.String("/bin/other")),
		"exec not exempt and not profiled")
}

// TestWasExecutedWithArgsPodSpecExempt pins the same fall-through for the
// args-carrying variant: unprofiled path + pod-spec command entry -> true.
func TestWasExecutedWithArgsPodSpecExempt(t *testing.T) {
	objCache := newExecPodSpecCache(&corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "test-container", Command: []string{"/bin/sh"}},
		},
	})
	profile := &v1beta1.ContainerProfile{}
	profile.Spec = v1beta1.ContainerProfileSpec{
		Execs: []v1beta1.ExecCalls{{Path: "/bin/ls", Args: []string{"-la"}}},
	}
	objCache.SetContainerProfile(profile)

	lib := &containerProfileLibrary{objectCache: objCache, preStopCache: NewPreStopHookCache(DefaultPreStopCacheSize, DefaultPreStopCacheTTL)}

	args := types.DefaultTypeAdapter.NativeToValue([]string{"-c", "echo hi"})
	assert.Equal(t, types.Bool(true),
		lib.wasExecutedWithArgs(types.String("test-container-id"), types.String("/bin/sh"), args),
		"exec-with-args exempt via pod spec command (args ignored on exemption)")

	noArgs := types.DefaultTypeAdapter.NativeToValue([]string{})
	assert.Equal(t, types.Bool(false),
		lib.wasExecutedWithArgs(types.String("test-container-id"), types.String("/bin/other"), noArgs),
		"exec-with-args not exempt and not profiled")
}
