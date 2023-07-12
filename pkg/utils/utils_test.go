package utils

import (
	"strings"
	"testing"
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
			name: "test1",
			args: args{
				namespaceName: "default",
				podName:       "pod1",
				containerName: "container1",
			},
			want: "default/pod1/container1",
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
