package utils

import (
	"reflect"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
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
			want: "3608506635c019b279ef561e999dace6b75735ab89611ce9f5c977bb5b9424a5",
		},
		{
			name: "Test with path and one argument",
			path: "/usr/local/bin/python",
			args: []string{"-v"},
			want: "17c24802e9bd6668cc207b91bbf5584f25c42b4209e18a07f5e6102ffbaff0a6",
		},
		{
			name: "Test with path and multiple arguments",
			path: "/usr/local/bin/python",
			args: []string{"-v", "-m", "pip"},
			want: "f005865e9bbb5fb613475d4539067f681f8a1d9579e0cb21cc502a02953e4d6a",
		},
		{
			name: "Test with path and multiple arguments different order",
			path: "/usr/local/bin/python",
			args: []string{"-v", "pip", "-m"},
			want: "b9245e8ce8c8f844ae150e4ac9bbc1ab813e7b66215a0ac34da3f894592a686c",
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

func TestCalculateSHA256FileExecHash_ArgvBoundaryCollision(t *testing.T) {
	path := "/bin/sh"
	hash1 := CalculateSHA256FileExecHash(path, []string{"/bin/sh", "a b"})
	hash2 := CalculateSHA256FileExecHash(path, []string{"/bin/sh", "a", "b"})

	if hash1 == hash2 {
		t.Errorf("CalculateSHA256FileExecHash() collision detected for distinct argv boundaries: %v == %v", hash1, hash2)
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
		process *armotypes.Process
		pid     uint32
	}
	tests := []struct {
		name string
		args args
		want *armotypes.Process
	}{
		{
			name: "Test Case 1: Process found in tree",
			args: args{
				process: &armotypes.Process{
					PID: 1,
					ChildrenMap: map[armotypes.CommPID]*armotypes.Process{
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
			want: &armotypes.Process{
				PID: 2,
			},
		},
		{
			name: "Test Case 2: Process not found in tree",
			args: args{
				process: &armotypes.Process{
					PID: 1,
					ChildrenMap: map[armotypes.CommPID]*armotypes.Process{
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
