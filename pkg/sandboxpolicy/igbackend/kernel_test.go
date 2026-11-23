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
	for _, section := range []string{sandboxpolicy.SectionPrivilege, sandboxpolicy.SectionNetwork, sandboxpolicy.SectionFile} {
		if len(SectionKernels(section)) != 2 {
			t.Fatalf("%s is qualified on both fleet kernels", section)
		}
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

// A kernel the section's check refuses is refused with a reason that names
// the failed check; an exact entry loads the section as qualified, any other
// kernel IG admits on its probes as probed.
func TestVerifySectionKernelRefusal(t *testing.T) {
	old := admitKernel
	t.Cleanup(func() { admitKernel = old })
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
		admitKernel = func(q []fullruntime.KernelIdentity) (fullruntime.KernelIdentity, fullruntime.KernelTier, error) {
			passed = q
			return fullruntime.KernelIdentity{}, "", &fullruntime.KernelCheckError{Check: check, Err: fmt.Errorf("%s failed", check)}
		}
		tier, _, err := VerifySectionKernel("privilege")
		var u *sandboxpolicy.EnforcementUnavailableError
		if !errors.As(err, &u) || u.Reason != reason || u.Section != "privilege" || !strings.Contains(u.Detail, "until node-agent restarts") || tier != "" {
			t.Fatalf("%s: %q %v", check, tier, err)
		}
		if !slices.Equal(passed, SectionKernels("privilege")) {
			t.Fatalf("%s: the section's own list is checked: %+v", check, passed)
		}
	}
	for _, want := range []fullruntime.KernelTier{fullruntime.KernelTierQualified, fullruntime.KernelTierProbed} {
		running := fullruntime.KernelIdentity{Arch: "amd64", Release: "6.1.158", BTF: strings.Repeat("a", 64), BuildID: "00"}
		admitKernel = func([]fullruntime.KernelIdentity) (fullruntime.KernelIdentity, fullruntime.KernelTier, error) {
			return running, want, nil
		}
		if tier, id, err := VerifySectionKernel("privilege"); err != nil || tier != want || id != running {
			t.Fatalf("%s kernel: %q %+v %v", want, tier, id, err)
		}
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
