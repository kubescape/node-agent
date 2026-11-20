package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestDecodeOpenFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags int32
		want  []string
	}{
		{
			name:  "read only without bit flags",
			flags: O_RDONLY,
			want:  []string{"O_RDONLY"},
		},
		{
			name:  "write only with create and trunc",
			flags: O_WRONLY | O_CREAT | O_TRUNC,
			want:  []string{"O_WRONLY", "O_CREAT", "O_TRUNC"},
		},
		{
			name:  "read write with append nonblock and cloexec",
			flags: O_RDWR | O_APPEND | O_NONBLOCK | O_CLOEXEC,
			want:  []string{"O_RDWR", "O_APPEND", "O_NONBLOCK", "O_CLOEXEC"},
		},
		{
			name:  "directory and nofollow flags",
			flags: O_RDONLY | O_DIRECTORY | O_NOFOLLOW,
			want:  []string{"O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, decodeOpenFlags(tt.flags))
		})
	}
}

func TestParseStringToMap(t *testing.T) {
	assert.Empty(t, parseStringToMap(""))
	assert.Empty(t, parseStringToMap("   ,  , "))

	got := parseStringToMap("app=nginx, env = prod , mal-formed, key=val=extra, ")
	assert.Equal(t, map[string]string{
		"app": "nginx",
		"env": "prod",
		"key": "val=extra",
	}, got)
}

func TestMergePolicies(t *testing.T) {
	p1 := v1beta1.RulePolicy{
		AllowedContainer: false,
		AllowedProcesses: []string{"/bin/sh", "/usr/bin/curl"},
	}
	p2 := v1beta1.RulePolicy{
		AllowedContainer: true,
		AllowedProcesses: []string{"/usr/bin/curl", "/usr/bin/python3"},
	}

	merged := MergePolicies(p1, p2)
	assert.True(t, merged.AllowedContainer)
	assert.ElementsMatch(t, []string{"/bin/sh", "/usr/bin/curl", "/usr/bin/python3"}, merged.AllowedProcesses)

	bothFalse := MergePolicies(
		v1beta1.RulePolicy{AllowedContainer: false},
		v1beta1.RulePolicy{AllowedContainer: false},
	)
	assert.False(t, bothFalse.AllowedContainer)
	assert.Empty(t, bothFalse.AllowedProcesses)
}

func TestK8sHelpers(t *testing.T) {
	assert.Equal(t, "default/web-pod", CreateK8sPodID("default", "web-pod"))

	assert.Equal(t, "plain", EscapeJSONPointerElement("plain"))
	assert.Equal(t, "a~0b~1c~01", EscapeJSONPointerElement("a~b/c~1"))

	podStatus := corev1.PodStatus{
		ContainerStatuses:          []corev1.ContainerStatus{{Name: "app", ContainerID: "c1"}},
		InitContainerStatuses:      []corev1.ContainerStatus{{Name: "init", ContainerID: "c2"}},
		EphemeralContainerStatuses: []corev1.ContainerStatus{{Name: "debug", ContainerID: "c3"}},
	}

	allStatuses := GetContainerStatuses(podStatus)
	require.Len(t, allStatuses, 3)

	mapped := MapContainerStatuses(allStatuses)
	require.Len(t, mapped, 3)
	assert.Equal(t, "c1", mapped["app"].ContainerID)
	assert.Equal(t, "c2", mapped["init"].ContainerID)
	assert.Equal(t, "c3", mapped["debug"].ContainerID)
}

func TestHashHelpers(t *testing.T) {
	openHash := CalculateSHA256FileOpenHash("/etc/shadow")
	assert.Equal(t, "52a70a6e00ef7eaccc9ee6efbbefaa0be2ef10523c674523b5ce6f2a7f340e12", openHash)

	_, _, err := CalculateFileHashes(filepath.Join(t.TempDir(), "nonexistent.txt"))
	assert.Error(t, err)

	tmpFile := filepath.Join(t.TempDir(), "sample.txt")
	require.NoError(t, os.WriteFile(tmpFile, []byte("kubescape-node-agent"), 0o600))

	sha1Hex, md5Hex, err := CalculateFileHashes(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, "3a6c8e4d70f3e60878a3501c58761529400f3c6a", sha1Hex)
	assert.Equal(t, "e49f2a3099a44ebae8f239d124c68621", md5Hex)
}

func TestContainerIdentityHelpers(t *testing.T) {
	assert.False(t, IsHostContainer(nil))
	assert.False(t, HasKubernetesPodIdentity(nil))
	assert.False(t, IsHost("regular-container-id"))
	assert.True(t, IsHost(armotypes.HostContainerID))

	pid1Container := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerPID: 1,
			},
		},
	}
	assert.True(t, IsHostContainer(pid1Container))

	hostIDContainer := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerID:  armotypes.HostContainerID,
				ContainerPID: 99,
			},
		},
	}
	assert.True(t, IsHostContainer(hostIDContainer))

	k8sContainer := &containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace: "default",
				PodName:   "nginx",
			},
		},
	}
	assert.True(t, HasKubernetesPodIdentity(k8sContainer))
	assert.False(t, HasKubernetesPodIdentity(pid1Container))
}
