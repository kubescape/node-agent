package utils

import (
	"testing"
)

func TestUtilsBetween(t *testing.T) {
	str := "TYPE=openat(fd: <f>/lib/x86_64-linux-gnu/libc.so.6, dirfd: AT_FDCWD, name: /lib/x86_64-linux-gnu/libc.so.6, flags: O_RDONLY|O_CLOEXEC, mode: 0, dev: 34, ino: 1321)"
	fileName := Between(str, "name: ", ", flags")
	if fileName != "/lib/x86_64-linux-gnu/libc.so.6" {
		t.Fatalf("filename s not as expected")
	}
}
