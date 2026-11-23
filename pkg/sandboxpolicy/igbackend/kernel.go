package igbackend

import (
	"errors"
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// admitKernel and checkKernelRuntime are the IG kernel checks; tests replace
// them.
var (
	admitKernel        = fullruntime.AdmitKernel
	checkKernelRuntime = fullruntime.CheckKernelRuntime
)

// VerifySectionKernel runs IG's kernel admission (fullruntime.AdmitKernel:
// amd64, a readable BTF digest, release and build-id, bpf LSM active, ftrace
// enabled, no livepatch). Every kernel is admitted the same way; no build
// list is consulted. On a failure the section must not load: the error is an
// EnforcementUnavailableError whose reason names the failed check. It runs
// once, at start, so a refused section stays unloaded until node-agent
// restarts.
func VerifySectionKernel(section string) error {
	if _, err := admitKernel(); err != nil {
		u := kernelUnavailable(section, err).(*sandboxpolicy.EnforcementUnavailableError)
		u.Detail += "; the section is not loaded until node-agent restarts"
		return u
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
// <Section>KernelUnqualified for the architecture or an identity check (and
// for an error that names no check).
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
