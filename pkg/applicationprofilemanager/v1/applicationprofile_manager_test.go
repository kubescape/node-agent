package applicationprofilemanager

import (
	"context"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/storage"
	"sort"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestApplicationProfileManager(t *testing.T) {
	cfg := config.Config{
		InitialDelay:     1 * time.Second,
		MaxSniffingTime:  5 * time.Minute,
		UpdateDataPeriod: 1 * time.Second,
	}
	ctx := context.TODO()
	k8sClient := &k8sclient.K8sClientMock{}
	storageClient := &storage.StorageHttpClientMock{}
	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	am, err := CreateApplicationProfileManager(ctx, cfg, "cluster", k8sClient, storageClient, mapset.NewSet[string](), k8sObjectCacheMock)
	assert.NoError(t, err)
	// prepare container
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
	// report syscall events
	go am.ReportSyscallEvent("ns/pod/cont", "dup")
	go am.ReportSyscallEvent("ns/pod/cont", "listen")
	// report capability
	go am.ReportCapability("ns/pod/cont", "NET_BIND_SERVICE")
	// report file exec
	go am.ReportFileExec("ns/pod/cont", "", []string{"ls"}) // will not be reported
	go am.ReportFileExec("ns/pod/cont", "/bin/bash", []string{"-c", "ls"})
	go am.ReportFileExec("ns/pod/cont", "/bin/bash", []string{"-c", "ls"})       // duplicate - not reported
	go am.ReportFileExec("ns/pod/cont", "/bin/bash", []string{"-c", "ls", "-l"}) // additional arg - reported
	go am.ReportFileExec("ns/pod/cont", "/bin/bash", []string{"ls", "-c"})       // different order of args - reported
	go am.ReportFileExec("ns/pod/cont", "/bin/ls", []string{"-l"})
	// report file open
	go am.ReportFileOpen("ns/pod/cont", "/etc/passwd", []string{"O_RDONLY"})
	// report container started (race condition with reports)
	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})
	// let it run for a while
	time.Sleep(15 * time.Second) // need to sleep longer because of AddRandomDuration in startApplicationProfiling
	// report another file open
	go am.ReportFileOpen("ns/pod/cont", "/etc/hosts", []string{"O_RDONLY"})
	// report another file open
	go am.ReportFileExec("ns/pod/cont", "/bin/bash", []string{"-c", "ls"}) // duplicate - will not be reported
	// sleep more
	time.Sleep(2 * time.Second)
	// report container stopped
	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	})
	// let it stop
	time.Sleep(2 * time.Second)
	// verify generated CRDs
	assert.Equal(t, 2, len(storageClient.ApplicationProfiles))
	// check the first profile
	sort.Strings(storageClient.ApplicationProfiles[0].Spec.Containers[0].Capabilities)
	assert.Equal(t, []string{"dup", "listen"}, storageClient.ApplicationProfiles[0].Spec.Containers[1].Syscalls)
	assert.Equal(t, []string{"NET_BIND_SERVICE"}, storageClient.ApplicationProfiles[0].Spec.Containers[1].Capabilities)

	reportedExecs := storageClient.ApplicationProfiles[0].Spec.Containers[1].Execs
	expectedExecs := []v1beta1.ExecCalls{
		{Path: "/bin/bash", Args: []string{"-c", "ls"}, Envs: []string(nil)},
		{Path: "/bin/bash", Args: []string{"-c", "ls", "-l"}, Envs: []string(nil)},
		{Path: "/bin/bash", Args: []string{"ls", "-c"}, Envs: []string(nil)},
		{Path: "/bin/ls", Args: []string{"-l"}, Envs: []string(nil)},
	}
	assert.Len(t, reportedExecs, len(expectedExecs))
	for _, expectedExec := range expectedExecs {
		assert.Contains(t, reportedExecs, expectedExec)
	}
	assert.Equal(t, []v1beta1.OpenCalls{{Path: "/etc/passwd", Flags: []string{"O_RDONLY"}}}, storageClient.ApplicationProfiles[0].Spec.Containers[1].Opens)
	// check the second profile - this is a patch for execs and opens
	sort.Strings(storageClient.ApplicationProfiles[1].Spec.Containers[0].Capabilities)
	assert.Equal(t, []string{"NET_BIND_SERVICE"}, storageClient.ApplicationProfiles[1].Spec.Containers[1].Capabilities)
	assert.Equal(t, storageClient.ApplicationProfiles[0].Spec.Containers[1].Execs, storageClient.ApplicationProfiles[1].Spec.Containers[1].Execs)
	assert.Equal(t, []v1beta1.OpenCalls{
		{Path: "/etc/passwd", Flags: []string{"O_RDONLY"}},
		{Path: "/etc/hosts", Flags: []string{"O_RDONLY"}},
	}, storageClient.ApplicationProfiles[1].Spec.Containers[1].Opens)
}
