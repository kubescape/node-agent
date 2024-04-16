package utils

import (
	"reflect"
	"strings"
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/stretchr/testify/assert"
)

func TestCalculateSHA256FileExecHash(t *testing.T) {
	tests := []struct {
		name string
		path string
		args []string
		want string
	}{
		{
			name: "Test with path only",
			path: "/usr/local/bin/python",
			args: []string{},
			want: "c3c3590ac3929a993cce758788838263ce47309429f486d8ebb8ee59fba42650",
		},
		{
			name: "Test with path and one argument",
			path: "/usr/local/bin/python",
			args: []string{"-v"},
			want: "5b4db099511640892a59a841aa0d13914610f60e8ca3922b0adaada599002a15",
		},
		{
			name: "Test with path and multiple arguments",
			path: "/usr/local/bin/python",
			args: []string{"-v", "-m", "pip"},
			want: "4fa7e242cfbe5b2d5ec4440821cae0b9830672c01dfb3959834aad5b46a6cec5",
		},
		{
			name: "Test with path and multiple arguments different order",
			path: "/usr/local/bin/python",
			args: []string{"-v", "pip", "-m"},
			want: "0fbe286986472240a59623fa225c96c02a2976bb248083a06f220c00f8863490",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CalculateSHA256FileExecHash(tt.path, tt.args); got != tt.want {
				t.Errorf("CalculateSHA256FileExecHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

func TestGetProcessFromProcessTree(t *testing.T) {
	type args struct {
		process *apitypes.Process
		pid     uint32
	}
	tests := []struct {
		name string
		args args
		want *apitypes.Process
	}{
		{
			name: "Test Case 1: Process found in tree",
			args: args{
				process: &apitypes.Process{
					PID: 1,
					Children: []apitypes.Process{
						{
							PID: 2,
						},
						{
							PID: 3,
						},
					},
				},
				pid: 2,
			},
			want: &apitypes.Process{
				PID: 2,
			},
		},
		{
			name: "Test Case 2: Process not found in tree",
			args: args{
				process: &apitypes.Process{
					PID: 1,
					Children: []apitypes.Process{
						{
							PID: 2,
						},
						{
							PID: 3,
						},
					},
				},
				pid: 4,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetProcessFromProcessTree(tt.args.process, tt.args.pid); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetProcessFromProcessTree() = %v, want %v", got, tt.want)
			}
		})
	}
}
