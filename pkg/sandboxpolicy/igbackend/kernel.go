package igbackend

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// sectionKernelEvidence lists, per slot section, the vmlinux BTF digests of
// the kernel builds on which that section's kernel suites passed with the run
// logs posted on the PRs. Each must be a build of fullruntime.QualifiedKernels:
// the IG kernel check identifies it (BTF, release, build-id). Add a build only
// with posted evidence; there is no configuration path.
var sectionKernelEvidence = map[string][]string{
	// Qualification reports 2026-11-11-full-b5a68891-two-kernels.md and
	// 2026-11-16-r2-ff313df7-two-kernels.md (AL2023 amd64).
	sandboxpolicy.SectionPrivilege: {
		"0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", // 6.12.113-138.209
		"d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", // 6.18.56-125.164
	},
	// Qualification report 2026-11-16-r2-ff313df7-two-kernels.md: the network
	// suite (outside-scope deny, missing publication, publish under traffic,
	// coexistence) passes on both builds.
	sandboxpolicy.SectionNetwork: {
		"0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", // 6.12.113-138.209
		"d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", // 6.18.56-125.164
	},
}

// SectionKernels returns the compiled-in qualified kernel list of a section:
// the builds of fullruntime.QualifiedKernels with evidence for the section.
// A section without evidence gets an empty list, which VerifyKernel refuses.
func SectionKernels(section string) []fullruntime.KernelIdentity {
	var out []fullruntime.KernelIdentity
	for _, k := range fullruntime.QualifiedKernels() {
		if slices.Contains(sectionKernelEvidence[section], k.BTF) {
			out = append(out, k)
		}
	}
	return out
}

// verifyKernel and checkKernelRuntime are the IG kernel checks; tests replace
// them.
var (
	verifyKernel       = fullruntime.VerifyKernel
	checkKernelRuntime = fullruntime.CheckKernelRuntime
)

// VerifySectionKernel runs the IG kernel check against the section's
// compiled-in list. On a failure the section must not load: the error is an
// EnforcementUnavailableError whose reason names the failed check.
func VerifySectionKernel(section string) error {
	if _, err := verifyKernel(SectionKernels(section)); err != nil {
		return kernelUnavailable(section, err)
	}
	return nil
}

// CheckSectionKernelRuntime re-reads ftrace and the livepatch taint. Call it
// at every status write. On an error no binding of the section is protected:
// with ftrace off the BPF LSM trampolines do not run, so a deny becomes an
// allow. This is detected here, not guarded.
func CheckSectionKernelRuntime(section string) error {
	if err := checkKernelRuntime(); err != nil {
		return kernelUnavailable(section, err)
	}
	return nil
}

// kernelUnavailable maps a failed IG kernel check to the Ready reason of the
// section: FtraceDisabled, KernelLivepatched, BPFLSMInactive, or
// <Section>KernelUnqualified for an identity check (and for an error that
// names no check).
func kernelUnavailable(section string, err error) error {
	reason := strings.ToUpper(section[:1]) + section[1:] + "KernelUnqualified"
	detail := err.Error()
	var check *fullruntime.KernelCheckError
	if errors.As(err, &check) {
		switch check.Check {
		case fullruntime.KernelCheckFtrace:
			reason = "FtraceDisabled"
		case fullruntime.KernelCheckLivepatch:
			reason = "KernelLivepatched"
		case fullruntime.KernelCheckBPFLSM:
			reason = "BPFLSMInactive"
		}
		detail = fmt.Sprintf("kernel check %s: %v", check.Check, err)
	}
	return &sandboxpolicy.EnforcementUnavailableError{Section: section, Reason: reason, Detail: detail}
}
