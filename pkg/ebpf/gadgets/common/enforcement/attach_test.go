// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func TestAsAttachCapacity(t *testing.T) {
	programs := map[string]string{"ig_priv_capable": "capable"}
	raw := fmt.Errorf("attaching eBPF program %q: %w", "ig_priv_capable", fmt.Errorf("create link: %w", syscall.E2BIG))
	err := AsAttachCapacity(raw, programs)
	var c *AttachCapacityError
	if !errors.As(err, &c) || c.Hook != "capable" || c.Program != "ig_priv_capable" || !errors.Is(err, unix.E2BIG) {
		t.Fatalf("capacity error: %#v", err)
	}
	if !strings.Contains(err.Error(), "hook capable is full") {
		t.Fatalf("message must name the hook: %v", err)
	}
	other := fmt.Errorf("attaching eBPF program %q: %w", "ig_priv_capable", syscall.EPERM)
	if got := AsAttachCapacity(other, programs); got != other {
		t.Fatalf("other errors stay as they are: %v", got)
	}
	unknown := AsAttachCapacity(fmt.Errorf("start: %w", syscall.E2BIG), programs)
	if !errors.As(unknown, &c) || c.Hook != "unknown" {
		t.Fatalf("E2BIG without a program: %#v", unknown)
	}
}

type varsGC struct {
	operators.GadgetContext
	vars map[string]any
}

func (g varsGC) GetVar(name string) (any, bool) { v, ok := g.vars[name]; return v, ok }

func TestCheckAttached(t *testing.T) {
	ok := func() error { return nil }
	gone := func() error { return fmt.Errorf("attachment program changed") }
	programs := map[string]string{"ig_net_connect": "socket_connect", "ig_net_sendmsg": "socket_sendmsg"}
	gc := varsGC{vars: map[string]any{
		operators.NativeAttachmentPrefix + "ig_net_connect": &operators.NativeAttachment{Target: "socket_connect", Check: ok},
		operators.NativeAttachmentPrefix + "ig_net_sendmsg": &operators.NativeAttachment{Target: "socket_sendmsg", Check: ok},
	}}
	if err := CheckAttached(gc, programs); err != nil {
		t.Fatal(err)
	}
	// One of two hooks attached is never ready.
	delete(gc.vars, operators.NativeAttachmentPrefix+"ig_net_sendmsg")
	if err := CheckAttached(gc, programs); err == nil || !strings.Contains(err.Error(), "socket_sendmsg") {
		t.Fatalf("a missing hook must be named: %v", err)
	}
	gc.vars[operators.NativeAttachmentPrefix+"ig_net_sendmsg"] = &operators.NativeAttachment{Target: "socket_sendmsg", Check: gone}
	if err := CheckAttached(gc, programs); err == nil || !strings.Contains(err.Error(), "socket_sendmsg") {
		t.Fatalf("a detached link must be named: %v", err)
	}
}
