package utils

import (
	"strings"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/stretchr/testify/assert"
)

func TestUtilsBetween(t *testing.T) {
	str := "TYPE=openat(fd: <f>/lib/x86_64-linux-gnu/libc.so.6, dirfd: AT_FDCWD, name: /lib/x86_64-linux-gnu/libc.so.6, flags: O_RDONLY|O_CLOEXEC, mode: 0, dev: 34, ino: 1321)"
	fileName := Between(str, "name: ", ", flags")
	if fileName != "/lib/x86_64-linux-gnu/libc.so.6" {
		t.Fatalf("filename s not as expected")
	}

	fileName = Between(str, "name: dsjcksbdnjkavsnbvkjd", ", flags")
	if fileName != "" {
		t.Fatalf("filename s not as expected")
	}

	fileName = Between(str, "name: ", ", flags dsjcksbdnjkavsnbvkjd")
	if fileName != "" {
		t.Fatalf("filename s not as expected")
	}

	fileName = Between(str, ", flags", "name: ")
	if fileName != "" {
		t.Fatalf("filename s not as expected")
	}
}

func TestAfter(t *testing.T) {
	str := "123456789"
	substrAfter := After(str, "567")
	if substrAfter != "89" {
		t.Fatalf("TestAfter failed, expected 89 Get: %s", substrAfter)
	}
}

func TestCurrentDir(t *testing.T) {
	dir := CurrentDir()
	if !strings.Contains(dir, "pkg/utils") {
		t.Fatalf("CurrentDir failed")
	}
}

func TestCreateK8sContainerID(t *testing.T) {
	type args struct {
		namespaceName string
		podName       string
		containerName string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "normal",
			args: args{
				namespaceName: "namespaceName",
				podName:       "podName",
				containerName: "containerName",
			},
			want: "namespaceName/podName/containerName",
		},
		{
			name: "missing namespaceName",
			args: args{
				podName:       "podName",
				containerName: "containerName",
			},
			want: "/podName/containerName",
		},
		{
			name: "missing podName",
			args: args{
				namespaceName: "namespaceName",
				containerName: "containerName",
			},
			want: "namespaceName//containerName",
		},
		{
			name: "missing containerName",
			args: args{
				namespaceName: "namespaceName",
				podName:       "podName",
			},
			want: "namespaceName/podName/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CreateK8sContainerID(tt.args.namespaceName, tt.args.podName, tt.args.containerName); got != tt.want {
				t.Errorf("CreateK8sContainerID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRandomSleep(t *testing.T) {
	type args struct {
		min int
		max int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "normal",
			args: args{
				min: 1,
				max: 3,
			},
		},
		{
			name: "min equals max",
			args: args{
				min: 1,
				max: 1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			time.Sleep(AddRandomDuration(tt.args.min, tt.args.max, 0))
			elapsed := int(time.Since(start).Seconds())
			if elapsed < tt.args.min || elapsed > tt.args.max {
				t.Errorf("AddRandomDuration() = %v, want between %v and %v", elapsed, tt.args.min, tt.args.max)
			}
		})
	}
}

func TestAtoi(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "normal",
			args: args{
				s: "123",
			},
			want: 123,
		},
		{
			name: "failure returns 0",
			args: args{
				s: "not a number",
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Atoi(tt.args.s); got != tt.want {
				t.Errorf("Atoi() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GetLabels(t *testing.T) {
	type args struct {
		watchedContainer *WatchedContainerData
		stripContainer   bool
	}
	instanceID, _ := instanceidhandler.GenerateInstanceIDFromString("apiVersion-v1/namespace-aaa/kind-deployment/name-redis/containerName-redis")
	tests := []struct {
		name string
		args args
		want map[string]string
	}{
		{
			name: "TestGetLabels",
			args: args{
				watchedContainer: &WatchedContainerData{
					InstanceID: instanceID,
					Wlid:       "wlid://cluster-name/namespace-aaa/deployment-redis",
				},
			},
			want: map[string]string{
				"kubescape.io/workload-api-version":    "v1",
				"kubescape.io/workload-container-name": "redis",
				"kubescape.io/workload-kind":           "Deployment",
				"kubescape.io/workload-name":           "redis",
				"kubescape.io/workload-namespace":      "aaa",
			},
		},
		{
			name: "TestGetLabels",
			args: args{
				watchedContainer: &WatchedContainerData{
					InstanceID: instanceID,
					Wlid:       "wlid://cluster-name/namespace-aaa/deployment-redis",
				},
				stripContainer: true,
			},
			want: map[string]string{
				"kubescape.io/workload-api-version": "v1",
				"kubescape.io/workload-kind":        "Deployment",
				"kubescape.io/workload-name":        "redis",
				"kubescape.io/workload-namespace":   "aaa",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetLabels(tt.args.watchedContainer, tt.args.stripContainer)
			assert.Equal(t, tt.want, got)
		})
	}
}
