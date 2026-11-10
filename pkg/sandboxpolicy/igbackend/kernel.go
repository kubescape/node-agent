package igbackend

import (
	"fmt"
	"runtime"
	"slices"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"golang.org/x/sys/unix"
)

// QualifiedKernels are the kernel releases (uname -r) on which the privilege
// section passed its kernel qualification: the AL2023 amd64 fleet kernels.
var QualifiedKernels = []string{
	"6.12.113-138.209.amzn2023.x86_64",
	"6.18.56-125.164.amzn2023.x86_64",
}

// AnyKernel in a qualified list admits every kernel (test clusters).
const AnyKernel = "*"

// CheckQualifiedKernel returns an EnforcementUnavailableError with reason
// PrivilegeKernelUnqualified unless release is in qualified (empty:
// QualifiedKernels). The privilege section still enforces on such a kernel,
// but never reports Ready.
func CheckQualifiedKernel(release string, qualified []string) error {
	if len(qualified) == 0 {
		qualified = QualifiedKernels
	}
	if slices.Contains(qualified, AnyKernel) || slices.Contains(qualified, release) {
		return nil
	}
	return &sandboxpolicy.EnforcementUnavailableError{Section: "privilege", Reason: "PrivilegeKernelUnqualified", Enforcing: true,
		Detail: fmt.Sprintf("kernel %s (%s) is not in the qualified list %v", release, runtime.GOARCH, qualified)}
}

// KernelRelease returns the running kernel release (uname -r).
func KernelRelease() (string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(u.Release[:]), nil
}
