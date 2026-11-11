package igbackend

import (
	"errors"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

func TestCheckQualifiedKernel(t *testing.T) {
	if err := CheckQualifiedKernel("6.18.56-125.164.amzn2023.x86_64", nil); err != nil {
		t.Fatal(err)
	}
	if err := CheckQualifiedKernel("6.12.113-138.209.amzn2023.x86_64", nil); err != nil {
		t.Fatalf("a fleet kernel is qualified: %v", err)
	}
	err := CheckQualifiedKernel("6.12.114-139.1.amzn2023.x86_64", nil)
	var u *sandboxpolicy.EnforcementUnavailableError
	if !errors.As(err, &u) || u.Reason != "PrivilegeKernelUnqualified" {
		t.Fatalf("another kernel is not qualified: %v", err)
	}
	if err := CheckQualifiedKernel("6.17.0-lab", []string{AnyKernel}); err != nil {
		t.Fatalf("the wildcard admits every kernel: %v", err)
	}
	if err := CheckQualifiedKernel("6.12.113-138.209.amzn2023.x86_64", []string{}); err != nil {
		t.Fatalf("an empty list (a Helm default) is the built-in list: %v", err)
	}
	if !u.Enforcing || !strings.Contains(u.Error(), "enforces") {
		t.Fatalf("the section still enforces: %q", u.Error())
	}
}
