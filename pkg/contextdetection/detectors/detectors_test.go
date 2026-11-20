package detectors

import (
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/contextdetection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestK8sDetector(t *testing.T) {
	d := NewK8sDetector()
	require.NotNil(t, d)
	assert.Equal(t, 0, d.Priority())

	// Nil container
	info, ok := d.Detect(nil)
	assert.False(t, ok)
	assert.Nil(t, info)

	// Missing PodName
	info, ok = d.Detect(&containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace: "default",
			},
		},
	})
	assert.False(t, ok)
	assert.Nil(t, info)

	// Missing Namespace
	info, ok = d.Detect(&containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				PodName: "api-pod",
			},
		},
	})
	assert.False(t, ok)
	assert.Nil(t, info)

	// Valid K8s container
	info, ok = d.Detect(&containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace: "kubescape",
				PodName:   "node-agent-xyz",
			},
		},
	})
	require.True(t, ok)
	require.NotNil(t, info)
	assert.Equal(t, contextdetection.Kubernetes, info.Context())
	assert.Equal(t, "kubescape/node-agent-xyz", info.WorkloadID())
}

func TestHostDetector(t *testing.T) {
	d := NewHostDetector()
	require.NotNil(t, d)
	assert.Equal(t, 1, d.Priority())

	// Nil container
	info, ok := d.Detect(nil)
	assert.False(t, ok)
	assert.Nil(t, info)

	// Container with K8s metadata should not be detected as Host even if PID == 1
	info, ok = d.Detect(&containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerPID: 1,
			},
		},
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace: "default",
			},
		},
	})
	assert.False(t, ok)
	assert.Nil(t, info)

	// Non-PID-1 container without K8s metadata
	info, ok = d.Detect(&containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerPID: 1234,
			},
		},
	})
	assert.False(t, ok)
	assert.Nil(t, info)

	// Host container (PID == 1, no K8s metadata)
	info, ok = d.Detect(&containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerPID: 1,
			},
		},
	})
	require.True(t, ok)
	require.NotNil(t, info)
	assert.Equal(t, contextdetection.Host, info.Context())
	assert.NotEmpty(t, info.WorkloadID())

	// HostContextInfo WorkloadID fallback when HostName is empty
	emptyHost := &HostContextInfo{}
	assert.Equal(t, "host", emptyHost.WorkloadID())

	namedHost := &HostContextInfo{HostName: "worker-node-01"}
	assert.Equal(t, "worker-node-01", namedHost.WorkloadID())
}

func TestStandaloneDetector(t *testing.T) {
	d := NewStandaloneDetector()
	require.NotNil(t, d)
	assert.Equal(t, 2, d.Priority())

	// Nil container
	info, ok := d.Detect(nil)
	assert.False(t, ok)
	assert.Nil(t, info)

	// Both ContainerName and ContainerID present
	info, ok = d.Detect(&containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerID:   "cid-123",
				ContainerName: "my-app",
			},
		},
	})
	require.True(t, ok)
	require.NotNil(t, info)
	assert.Equal(t, contextdetection.Standalone, info.Context())
	assert.Equal(t, "my-app:cid-123", info.WorkloadID())

	// Only ContainerName present (ContainerID empty)
	onlyName := &StandaloneContextInfo{ContainerName: "my-app"}
	assert.Equal(t, "my-app", onlyName.WorkloadID())

	// Only ContainerID present (ContainerName empty)
	onlyID := &StandaloneContextInfo{ContainerID: "cid-123"}
	assert.Equal(t, "cid-123", onlyID.WorkloadID())
}

func TestDetectorManager_DetectContext(t *testing.T) {
	reg := contextdetection.NewMntnsRegistry()
	dm := NewDetectorManager(reg)
	require.NotNil(t, dm)

	// Nil container returns ErrInvalidContainer
	info, err := dm.DetectContext(nil)
	assert.ErrorIs(t, err, ErrInvalidContainer)
	assert.Nil(t, info)

	// Priority 0: K8s takes precedence
	k8sContainer := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerID:   "k8s-cid",
				ContainerName: "k8s-cname",
				ContainerPID:  1,
			},
		},
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace: "prod",
				PodName:   "web-0",
			},
		},
	}
	info, err = dm.DetectContext(k8sContainer)
	require.NoError(t, err)
	assert.Equal(t, contextdetection.Kubernetes, info.Context())
	assert.Equal(t, "prod/web-0", info.WorkloadID())

	// Priority 1: Host container when K8s metadata is absent and PID == 1
	hostContainer := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerID:   "host-cid",
				ContainerName: "host",
				ContainerPID:  1,
			},
		},
	}
	info, err = dm.DetectContext(hostContainer)
	require.NoError(t, err)
	assert.Equal(t, contextdetection.Host, info.Context())

	// Priority 2: Standalone container when K8s metadata is absent and PID != 1
	standaloneContainer := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerID:   "docker-123",
				ContainerName: "redis",
				ContainerPID:  4321,
			},
		},
	}
	info, err = dm.DetectContext(standaloneContainer)
	require.NoError(t, err)
	assert.Equal(t, contextdetection.Standalone, info.Context())
	assert.Equal(t, "redis:docker-123", info.WorkloadID())

	// Fallback when no detectors match
	emptyManager := &DetectorManager{registry: reg}
	info, err = emptyManager.DetectContext(standaloneContainer)
	require.NoError(t, err)
	assert.Equal(t, contextdetection.Standalone, info.Context())
	assert.Equal(t, "redis:docker-123", info.WorkloadID())
}
