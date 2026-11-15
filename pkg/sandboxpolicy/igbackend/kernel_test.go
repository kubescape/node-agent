package igbackend

import (
	"errors"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

func TestCheckQualifiedKernel(t *testing.T) {
	listed := QualifiedKernels[sandboxpolicy.SectionPrivilege]
	fleet := listed[0]
	if note, err := CheckQualifiedKernel(sandboxpolicy.SectionPrivilege, fleet, listed, false); err != nil || note != "" {
		t.Fatalf("a fleet kernel is qualified: %q %v", note, err)
	}
	// Same release, another build: the BTF digest differs.
	rebuilt := fleet
	rebuilt.BTF = strings.Repeat("0", 64)
	_, err := CheckQualifiedKernel(sandboxpolicy.SectionPrivilege, rebuilt, listed, false)
	var u *sandboxpolicy.EnforcementUnavailableError
	if !errors.As(err, &u) || u.Reason != "PrivilegeKernelUnqualified" || !u.Enforcing || !strings.Contains(u.Error(), "enforces") {
		t.Fatalf("another BTF build is not qualified: %v", err)
	}
	arm := fleet
	arm.Arch = "aarch64"
	if _, err := CheckQualifiedKernel(sandboxpolicy.SectionPrivilege, arm, listed, false); err == nil {
		t.Fatal("another architecture is not qualified")
	}
	// Network has its own gate: not qualified until its run passes.
	if _, err := CheckQualifiedKernel(sandboxpolicy.SectionNetwork, fleet, QualifiedKernels[sandboxpolicy.SectionNetwork], false); !errors.As(err, &u) || u.Reason != "NetworkKernelUnqualified" {
		t.Fatalf("network keeps its own gate: %v", err)
	}
	note, err := CheckQualifiedKernel(sandboxpolicy.SectionNetwork, Kernel{Release: "6.17.0-lab", Arch: "x86_64"}, nil, true)
	if err != nil || !strings.Contains(note, "gate disabled") {
		t.Fatalf("the wildcard admits every kernel with a distinct note: %q %v", note, err)
	}
}

func TestParseQualifiedKernels(t *testing.T) {
	if k, any, err := ParseQualifiedKernels(nil); err != nil || any || k != nil {
		t.Fatalf("an empty list (a Helm default) means the built-in lists: %v %v %v", k, any, err)
	}
	k, any, err := ParseQualifiedKernels([]string{"*", "6.1.0,x86_64," + strings.Repeat("Ab", 32)})
	if err != nil || !any || len(k) != 1 || k[0].BTF != strings.Repeat("ab", 32) {
		t.Fatalf("parse: %v %v %v", k, any, err)
	}
	for _, bad := range []string{"6.12.113-138.209.amzn2023.x86_64", "r,x86_64,abc", "r,," + strings.Repeat("a", 64), "r,a," + strings.Repeat("z", 64)} {
		if _, _, err := ParseQualifiedKernels([]string{bad}); err == nil {
			t.Errorf("%q must be refused: a kernel needs release, arch and BTF digest", bad)
		}
	}
}
