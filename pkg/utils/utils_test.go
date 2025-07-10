package utils

import (
	"reflect"
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
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
					ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
						{PID: 2}: {
							PID: 2,
						},
						{PID: 3}: {
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
					ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
						{PID: 2}: {
							PID: 2,
						},
						{PID: 3}: {
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

func TestTrimRuntimePrefix(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{
			name: "Test with valid runtime prefix",
			id:   "runtime//containerID",
			want: "containerID",
		},
		{
			name: "Test with no runtime prefix",
			id:   "containerID",
			want: "",
		},
		{
			name: "Test with docker runtime prefix",
			id:   "docker://containerID",
			want: "containerID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TrimRuntimePrefix(tt.id)

			if got != tt.want {
				t.Errorf("TrimRuntimePrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}
