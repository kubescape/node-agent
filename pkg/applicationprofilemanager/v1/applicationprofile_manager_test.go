package applicationprofilemanager

import (
	"context"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/storage"
	"sort"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestApplicationProfileManager(t *testing.T) {
	cfg := config.Config{
		InitialDelay:     1 * time.Second,
		MaxSniffingTime:  5 * time.Minute,
		UpdateDataPeriod: 20 * time.Second,
	}
	ctx := context.TODO()
	k8sClient := &k8sclient.K8sClientMock{}
	storageClient := &storage.StorageHttpClientMock{}
	am, err := CreateApplicationProfileManager(ctx, cfg, "cluster", k8sClient, storageClient)
	assert.NoError(t, err)
	// report container started
	container := &containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "ns",
				PodName:       "pod",
				ContainerName: "cont",
			},
		},
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				ContainerID: "5fff6a395ce4e6984a9447cc6cfb09f473eaf278498243963fcc944889bc8400",
			},
		},
	}
	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})
	// register peek function for syscall tracer
	am.RegisterPeekFunc(func(_ uint64) ([]string, error) {
		return []string{"dup", "listen"}, nil
	})
	// report capability
	am.ReportCapability("ns/pod/cont", "NET_BIND_SERVICE")
	// report file exec
	am.ReportFileExec("ns/pod/cont", "/bin/bash", []string{"-c", "ls"})
	// report file open
	am.ReportFileOpen("ns/pod/cont", "/etc/passwd", []string{"O_RDONLY"})
	// let it run for a while
	time.Sleep(12 * time.Second) // need to sleep longer because of AddRandomDuration in startApplicationProfiling
	// report container stopped
	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	})
	// let it stop
	time.Sleep(1 * time.Second)
	// verify generated CRDs
	assert.Equal(t, 2, len(storageClient.ApplicationActivities))
	sort.Strings(storageClient.ApplicationActivities[0].Spec.Syscalls)
	assert.Equal(t, []string{"dup", "listen", "open"}, storageClient.ApplicationActivities[0].Spec.Syscalls)
	assert.Equal(t, 2, len(storageClient.ApplicationProfiles))
	sort.Strings(storageClient.ApplicationProfiles[0].Spec.Containers[0].Capabilities)
	assert.Equal(t, []string{"NET_BIND_SERVICE", "NET_BROADCAST"}, storageClient.ApplicationProfiles[0].Spec.Containers[1].Capabilities)
	assert.Equal(t, []v1beta1.ExecCalls{{Path: "/bin/bash", Args: []string{"-c", "ls"}, Envs: []string(nil)}}, storageClient.ApplicationProfiles[0].Spec.Containers[1].Execs)
	assert.Equal(t, []v1beta1.OpenCalls{{Path: "/etc/passwd", Flags: []string{"O_RDONLY"}}}, storageClient.ApplicationProfiles[0].Spec.Containers[1].Opens)
	assert.Equal(t, 2, len(storageClient.ApplicationProfileSummaries))
}
