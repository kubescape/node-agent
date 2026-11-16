package igbackend

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// Every evidence entry is an IG qualified build, so a section never loses a
// kernel silently when IG changes its pins.
func TestSectionKernelsAreQualifiedBuilds(t *testing.T) {
	for section, digests := range sectionKernelEvidence {
		got := SectionKernels(section)
		if len(got) != len(digests) {
			t.Fatalf("%s: %d of %d evidence builds are IG qualified kernels: %+v", section, len(got), len(digests), got)
		}
		for _, k := range got {
			if !slices.Contains(fullruntime.QualifiedKernels(), k) {
				t.Fatalf("%s: %+v is not an IG qualified kernel", section, k)
			}
		}
	}
	if len(SectionKernels("privilege")) != 2 {
		t.Fatal("privilege is qualified on both fleet kernels")
	}
}

// A section without evidence has an empty list, and IG refuses an empty list:
// there is no wildcard.
func TestSectionWithoutEvidenceIsRefused(t *testing.T) {
	_, err := fullruntime.VerifyKernel(SectionKernels("none"))
	var check *fullruntime.KernelCheckError
	if !errors.As(err, &check) || check.Check != fullruntime.KernelCheckQualifiedList {
		t.Fatalf("empty list: %v", err)
	}
	if _, err := fullruntime.VerifyKernel([]fullruntime.KernelIdentity{{Arch: "amd64", Release: "*", BTF: "*", BuildID: "*"}}); !errors.As(err, &check) {
		t.Fatalf("a wildcard entry is malformed: %v", err)
	}
}

// On a kernel outside the section's list the section is refused with a reason
// that names the failed check.
func TestVerifySectionKernelRefusal(t *testing.T) {
	old := verifyKernel
	t.Cleanup(func() { verifyKernel = old })
	var passed []fullruntime.KernelIdentity
	for check, reason := range map[string]string{
		fullruntime.KernelCheckBTF:           "PrivilegeKernelUnqualified",
		fullruntime.KernelCheckRelease:       "PrivilegeKernelUnqualified",
		fullruntime.KernelCheckBuildID:       "PrivilegeKernelUnqualified",
		fullruntime.KernelCheckArch:          "PrivilegeKernelUnqualified",
		fullruntime.KernelCheckQualifiedList: "PrivilegeKernelUnqualified",
		fullruntime.KernelCheckBPFLSM:        "BPFLSMInactive",
		fullruntime.KernelCheckFtrace:        "FtraceDisabled",
		fullruntime.KernelCheckLivepatch:     "KernelLivepatched",
	} {
		verifyKernel = func(q []fullruntime.KernelIdentity) (fullruntime.KernelIdentity, error) {
			passed = q
			return fullruntime.KernelIdentity{}, &fullruntime.KernelCheckError{Check: check, Err: fmt.Errorf("%s failed", check)}
		}
		err := VerifySectionKernel("privilege")
		var u *sandboxpolicy.EnforcementUnavailableError
		if !errors.As(err, &u) || u.Reason != reason || u.Section != "privilege" || !strings.Contains(u.Detail, "until node-agent restarts") {
			t.Fatalf("%s: %v", check, err)
		}
		if !slices.Equal(passed, SectionKernels("privilege")) {
			t.Fatalf("%s: the section's own list is checked: %+v", check, passed)
		}
	}
	verifyKernel = func([]fullruntime.KernelIdentity) (fullruntime.KernelIdentity, error) {
		return fullruntime.KernelIdentity{}, nil
	}
	if err := VerifySectionKernel("privilege"); err != nil {
		t.Fatalf("a qualified kernel loads the section: %v", err)
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
