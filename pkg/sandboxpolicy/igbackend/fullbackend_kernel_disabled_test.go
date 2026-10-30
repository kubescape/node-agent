//go:build !linux || !sandboxpolicy_kernel

package igbackend

import (
	"os"
	"testing"
)

// Keep the opt-in test discoverable when kernel support is not compiled in.
func TestFullBackendContainerdKernel(t *testing.T) {
	if os.Getenv("IG_FULL_BACKEND_KERNEL_TEST") == "1" {
		t.Fatal("kernel qualification requires Linux and -tags=sandboxpolicy_kernel; the build tag admits kernel initialization even without the opt-in environment variable")
	}
	t.Skip("kernel qualification unavailable: requires Linux, -tags=sandboxpolicy_kernel and IG_FULL_BACKEND_KERNEL_TEST=1")
}
