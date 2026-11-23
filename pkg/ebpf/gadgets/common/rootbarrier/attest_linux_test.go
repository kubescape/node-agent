// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package rootbarrier

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// A link that is being created or freed makes the walk fail with EAGAIN: the
// walk is retried, a bounded number of times. Other errors are not retried.
func TestAttachedHooksRetriesEAGAIN(t *testing.T) {
	defer func(w func(ebpf.MapID, *btf.Spec, []Hook) (map[Hook]bool, error), r int, d time.Duration) {
		walkHooks, walkRetries, walkRetryDelay = w, r, d
	}(walkHooks, walkRetries, walkRetryDelay)
	walkRetries, walkRetryDelay = 3, 0
	busy := fmt.Errorf("root barrier: listing BPF links: get link for ID 1: %w", unix.EAGAIN)

	calls := 0
	walkHooks = func(ebpf.MapID, *btf.Spec, []Hook) (map[Hook]bool, error) {
		calls++
		if calls < 3 {
			return nil, busy
		}
		return map[Hook]bool{Hooks[0]: true}, nil
	}
	got, err := attachedHooks(1, nil, Hooks)
	if err != nil || !got[Hooks[0]] || calls != 3 {
		t.Fatalf("transient EAGAIN: got %v, %v after %d walks", got, err, calls)
	}

	calls = 0
	walkHooks = func(ebpf.MapID, *btf.Spec, []Hook) (map[Hook]bool, error) { calls++; return nil, busy }
	if _, err := attachedHooks(1, nil, Hooks); !errors.Is(err, unix.EAGAIN) || calls != walkRetries+1 {
		t.Fatalf("persistent EAGAIN: got %v after %d walks, want EAGAIN after %d", err, calls, walkRetries+1)
	}

	calls = 0
	other := errors.New("root barrier: opening program 7: permission denied")
	walkHooks = func(ebpf.MapID, *btf.Spec, []Hook) (map[Hook]bool, error) { calls++; return nil, other }
	if _, err := attachedHooks(1, nil, Hooks); !errors.Is(err, other) || calls != 1 {
		t.Fatalf("other error: got %v after %d walks, want one walk", err, calls)
	}
}
