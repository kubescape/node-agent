// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
)

// Attach capacity (measured on AL2023 6.12.113-138.209 and 6.18.56-125.164):
// one BPF trampoline holds 38 links, shared by fentry, fexit and LSM programs
// on the same function; the kernel refuses the next link with E2BIG. Each
// enforcement family uses at most MaxFamilyLinksPerHook links on one hook and
// leaves ReservePerHook free for third parties.
const (
	TrampolineLinks       = 38
	MaxFamilyLinksPerHook = 8
	ReservePerHook        = 8
)

// AttachCapacityError is an attach that the kernel refused because the hook's
// trampoline is full (E2BIG). It is a capacity NotReady: retry with backoff;
// it never means the gadget or the kernel is unsupported.
type AttachCapacityError struct {
	Program, Hook string
	Err           error
}

func (e *AttachCapacityError) Error() string {
	return fmt.Sprintf("attach capacity: hook %s is full (program %s): %v", e.Hook, e.Program, e.Err)
}

func (e *AttachCapacityError) Unwrap() error { return e.Err }

// attachRE matches the program name of the IG ebpf operator's attach error.
var attachRE = regexp.MustCompile(`attaching eBPF program "([^"]+)"`)

// AsAttachCapacity returns an *AttachCapacityError when err is an attach
// refused with E2BIG, naming the program and its hook (programs: program
// name -> hook). Other errors are returned unchanged. A failed start of an
// IG instance closes every link it attached (the instance's Close), so a
// partial attach leaves no link behind.
func AsAttachCapacity(err error, programs map[string]string) error {
	if err == nil || !errors.Is(err, unix.E2BIG) {
		return err
	}
	var already *AttachCapacityError
	if errors.As(err, &already) {
		return err
	}
	// IG's transactional attach names the trampoline target
	// (bpf_lsm_<hook>), not the program.
	var native *nativeattach.ErrAttachCapacity
	if errors.As(err, &native) && strings.Contains(native.Error(), "above K=") {
		// The family needs more links than its limit: no retry fixes it.
		return err
	}
	if errors.As(err, &native) {
		e := &AttachCapacityError{Err: err, Program: "unknown", Hook: strings.TrimPrefix(native.Target, "bpf_lsm_")}
		names := make([]string, 0, len(programs))
		for name := range programs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if programs[name] == e.Hook {
				e.Program = name
				break
			}
		}
		return e
	}
	// Only an attach: E2BIG also comes from a map or a program too large
	// for the verifier, which no retry fixes.
	m := attachRE.FindStringSubmatch(err.Error())
	if m == nil {
		return err
	}
	e := &AttachCapacityError{Err: err, Program: m[1], Hook: "unknown"}
	if hook, ok := programs[m[1]]; ok {
		e.Hook = hook
	}
	return e
}

// CheckAttached confirms that each program (program name -> hook) has a live
// link of this instance: the IG ebpf operator publishes one receipt per LSM
// program, and its Check reads the link by its ID and compares the program
// ID. A missing receipt or a link that no longer references the program is an
// error naming the hook. Run it on each status read, not only at start.
func CheckAttached(gc operators.GadgetContext, programs map[string]string) error {
	if gc == nil {
		return fmt.Errorf("no running instance")
	}
	names := make([]string, 0, len(programs))
	for name := range programs {
		names = append(names, name)
	}
	sort.Strings(names)
	var errs []error
	for _, name := range names {
		hook := programs[name]
		value, _ := gc.GetVar(operators.NativeAttachmentPrefix + name)
		r, ok := value.(*operators.NativeAttachment)
		switch {
		case !ok || r == nil:
			errs = append(errs, fmt.Errorf("hook %s: no live link of %s", hook, name))
		case r.Check == nil:
			errs = append(errs, fmt.Errorf("hook %s: link of %s cannot be checked", hook, name))
		default:
			if err := r.Check(); err != nil {
				errs = append(errs, fmt.Errorf("hook %s: %w", hook, err))
			}
		}
	}
	return errors.Join(errs...)
}

// Attached checks that every program of Config.Programs has a live link
// (CheckAttached). Nil when no programs are configured.
func (b *Bindings) Attached() error {
	b.mu.Lock()
	gc, programs := b.gc, b.config.Programs
	b.mu.Unlock()
	if len(programs) == 0 {
		return nil
	}
	return CheckAttached(gc, programs)
}
