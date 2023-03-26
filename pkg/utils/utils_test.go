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
