package igbackend

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// A kernel IG refuses is refused with a reason that names the failed check;
// a kernel IG admits loads the section.
func TestVerifySectionKernelRefusal(t *testing.T) {
	old := admitKernel
	t.Cleanup(func() { admitKernel = old })
	for check, reason := range map[string]string{
		fullruntime.KernelCheckBTF:       "PrivilegeKernelUnqualified",
		fullruntime.KernelCheckRelease:   "PrivilegeKernelUnqualified",
		fullruntime.KernelCheckBuildID:   "PrivilegeKernelUnqualified",
		fullruntime.KernelCheckArch:      "PrivilegeKernelUnqualified",
		fullruntime.KernelCheckBPFLSM:    "BPFLSMInactive",
		fullruntime.KernelCheckFtrace:    "FtraceDisabled",
		fullruntime.KernelCheckLivepatch: "KernelLivepatched",
	} {
		admitKernel = func() (fullruntime.KernelIdentity, error) {
			return fullruntime.KernelIdentity{}, &fullruntime.KernelCheckError{Check: check, Err: fmt.Errorf("%s failed", check)}
		}
		err := VerifySectionKernel("privilege")
		var u *sandboxpolicy.EnforcementUnavailableError
		if !errors.As(err, &u) || u.Reason != reason || u.Section != "privilege" || !strings.Contains(u.Detail, "until node-agent restarts") {
			t.Fatalf("%s: %v", check, err)
		}
	}
	admitKernel = func() (fullruntime.KernelIdentity, error) {
		return fullruntime.KernelIdentity{}, errors.New("no check named")
	}
	var u *sandboxpolicy.EnforcementUnavailableError
	if err := VerifySectionKernel("network"); !errors.As(err, &u) || u.Reason != "NetworkKernelUnqualified" {
		t.Fatalf("an error naming no check: %v", err)
	}
	admitKernel = func() (fullruntime.KernelIdentity, error) {
		return fullruntime.KernelIdentity{Arch: "amd64", Release: "6.1.158", BTF: strings.Repeat("a", 64), BuildID: "00"}, nil
	}
	if err := VerifySectionKernel("privilege"); err != nil {
		t.Fatalf("an admitted kernel loads the section: %v", err)
	}
}

// The runtime check is re-read at every call and is never cached.
func TestCheckSectionKernelRuntime(t *testing.T) {
	old := checkKernelRuntime
	t.Cleanup(func() { checkKernelRuntime = old })
	calls := 0
	var fail error
	checkKernelRuntime = func() error { calls++; return fail }
	if err := CheckSectionKernelRuntime("privilege"); err != nil {
		t.Fatal(err)
	}
	fail = &fullruntime.KernelCheckError{Check: fullruntime.KernelCheckFtrace, Err: errors.New("ftrace_enabled is 0")}
	err := CheckSectionKernelRuntime("privilege")
	var u *sandboxpolicy.EnforcementUnavailableError
	if !errors.As(err, &u) || u.Reason != "FtraceDisabled" || calls != 2 {
		t.Fatalf("ftrace off: %v (calls %d)", err, calls)
	}
}
