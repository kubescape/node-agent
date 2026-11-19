// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/rootbarrier"
)

func TestCheckLevel(t *testing.T) {
	root, old := t.TempDir(), cgroupRoot
	cgroupRoot = root
	t.Cleanup(func() { cgroupRoot = old })
	mk := func(rel string) uint64 {
		dir := filepath.Join(root, rel)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Stat(dir, &st); err != nil {
			t.Fatal(err)
		}
		return st.Ino
	}
	shallow := "/kubepods/pod1/c1"
	id := mk(shallow)
	deep := "/" + strings.Repeat("d/", coveredLevels) + "leaf"
	deepID := mk(deep)
	for name, tc := range map[string]struct {
		c  Cgroup
		ok bool
	}{
		"audit exact needs nothing":    {Cgroup{ID: 1}, true},
		"enforce with its path":        {Cgroup{ID: id, Path: shallow, Enforce: true}, true},
		"subtree with its path":        {Cgroup{ID: id, Path: shallow, Subtree: true}, true},
		"enforce without a path":       {Cgroup{ID: id, Enforce: true}, false},
		"subtree without a path":       {Cgroup{ID: id, Subtree: true}, false},
		"enforce too deep":             {Cgroup{ID: deepID, Path: deep, Enforce: true}, false},
		"enforce with another cgroup":  {Cgroup{ID: id + 1000, Path: shallow, Enforce: true}, false},
		"enforce with a relative path": {Cgroup{ID: id, Path: "/kubepods/../kubepods/pod1/c1", Enforce: true}, false},
		// The program's parent walk skips an exact audit-only binding at
		// any depth, so its level does not matter.
		"audit exact deeper than the walk": {Cgroup{ID: deepID, Path: deep}, true},
	} {
		if err := checkLevel(tc.c); (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// fakeBarrier replaces the barrier checks of the owner for one test.
type fakeBarrier struct {
	verifies, linkChecks atomic.Int32
	verifyErr, linkErr   atomic.Value // error, or errNone
	// gate, when set, blocks each verification until it is closed;
	// attestGate does the same for each link walk.
	gate, attestGate chan struct{}
}

var errNone = errors.New("none")

func load(v *atomic.Value) error {
	if err, _ := v.Load().(error); err != nil && err != errNone {
		return err
	}
	return nil
}

func newFakeBarrier(t *testing.T) *fakeBarrier {
	f := &fakeBarrier{}
	f.verifyErr.Store(errNone)
	f.linkErr.Store(errNone)
	oldVerify, oldIDs, oldAttest := verifyMaps, programIDs, attest
	t.Cleanup(func() { verifyMaps, programIDs, attest = oldVerify, oldIDs, oldAttest })
	verifyMaps = func(*ebpf.Map, *ebpf.Map, []rootbarrier.Hook) error {
		f.verifies.Add(1)
		if f.gate != nil {
			<-f.gate
		}
		return load(&f.verifyErr)
	}
	programIDs = func(_ *ebpf.Map, hooks []rootbarrier.Hook) ([]rootbarrier.Hook, error) {
		return rootbarrier.WithProgram(hooks, "path_chroot", "rb_chroot"), nil
	}
	attest = func(_ *ebpf.Map, hooks []rootbarrier.Hook) error {
		f.linkChecks.Add(1)
		if f.attestGate != nil {
			<-f.attestGate
		}
		if len(hooks) == 0 {
			return errors.New("no hooks")
		}
		return load(&f.linkErr)
	}
	return f
}

// Health retries a failed verification like Cover: one at a time, at most
// every verifyRetry. Once it passes, Health checks the links by program ID at
// most every attestInterval, and a missing link refuses enforcing bindings
// again.
func TestHealthRetriesAndChecksLinks(t *testing.T) {
	f := newFakeBarrier(t)
	failed := errors.New("root barrier: no live LSM link for rb_chroot->path_chroot")
	o := &Owner{ready: true, barrierErr: failed, lastVerify: time.Now()}

	// Within verifyRetry of the last verification: no retry.
	if err := o.Health(); !errors.Is(err, failed) || f.verifies.Load() != 0 {
		t.Fatalf("gated Health: %v after %d verifications", err, f.verifies.Load())
	}
	if err := o.Cover(Cgroup{ID: 7, Enforce: true}); err == nil || !errors.Is(err, failed) || f.verifies.Load() != 0 {
		t.Fatalf("gated Cover: %v after %d verifications", err, f.verifies.Load())
	}

	// After verifyRetry, concurrent Health calls run one verification.
	o.lastVerify = time.Now().Add(-verifyRetry)
	f.gate = make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = o.Health() }()
	}
	for f.verifies.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(f.gate)
	wg.Wait()
	f.gate = nil
	if n := f.verifies.Load(); n != 1 {
		t.Fatalf("concurrent Health ran %d verifications, want 1", n)
	}
	if err := o.Health(); err != nil {
		t.Fatalf("Health after a passing verification: %v", err)
	}
	if f.linkChecks.Load() == 0 {
		t.Fatal("Health did not check the links")
	}

	// Review 5 M3: status reads within attestInterval return the last
	// result with no link walk; after it, one walk runs. A passing check
	// never verifies again.
	checks := f.linkChecks.Load()
	for i := 0; i < 3; i++ {
		if err := o.Health(); err != nil {
			t.Fatal(err)
		}
	}
	if f.linkChecks.Load() != checks || f.verifies.Load() != 1 {
		t.Fatalf("link checks %d (want %d), verifications %d (want 1)", f.linkChecks.Load(), checks, f.verifies.Load())
	}
	o.lastAttest = time.Now().Add(-attestInterval)
	for i := 0; i < 3; i++ {
		if err := o.Health(); err != nil {
			t.Fatal(err)
		}
	}
	if f.linkChecks.Load() != checks+1 || f.verifies.Load() != 1 {
		t.Fatalf("link checks %d (want %d), verifications %d (want 1)", f.linkChecks.Load(), checks+1, f.verifies.Load())
	}

	// A detached link: Health names it at the next walk, and enforcing
	// bindings are refused until a retried verification passes.
	detached := errors.New("root barrier: no live LSM link for rb_chroot->path_chroot (program 1)")
	f.linkErr.Store(detached)
	f.verifyErr.Store(detached)
	o.lastVerify = time.Now()
	o.lastAttest = time.Now().Add(-attestInterval)
	if err := o.Health(); !errors.Is(err, detached) {
		t.Fatalf("Health with a detached link: %v", err)
	}
	if err := o.Cover(Cgroup{ID: 7, Enforce: true}); err == nil || !strings.Contains(err.Error(), "rb_chroot->path_chroot") {
		t.Fatalf("an enforcing binding with a detached link: %v", err)
	}
	f.linkErr.Store(errNone)
	if err := o.Health(); !errors.Is(err, detached) {
		t.Fatalf("Health must stay failed until a verification passes: %v", err)
	}
	f.verifyErr.Store(errNone)
	o.lastVerify = time.Now().Add(-verifyRetry)
	if err := o.Health(); err != nil {
		t.Fatalf("Health after the link is back and a verification passed: %v", err)
	}

	o.Stop(nil)
	if err := o.Health(); !errors.Is(err, errNotReady) {
		t.Fatalf("Health after Stop: %v", err)
	}
}

// Review 6: while the first link walk runs, Health returns "not yet
// attested", never a nil error; after it completes, its result.
func TestHealthBeforeFirstAttestation(t *testing.T) {
	f := newFakeBarrier(t)
	o := &Owner{ready: true, hooks: []rootbarrier.Hook{{LSM: "path_chroot"}}}
	f.attestGate = make(chan struct{})
	done := make(chan error)
	go func() { done <- o.Health() }()
	for f.linkChecks.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	if err := o.Health(); !errors.Is(err, errNotAttested) {
		t.Fatalf("Health during the first walk: %v, want not yet attested", err)
	}
	close(f.attestGate)
	if err := <-done; err != nil {
		t.Fatalf("the first walk: %v", err)
	}
	if err := o.Health(); err != nil {
		t.Fatalf("Health after the first walk: %v", err)
	}
}

// A walk that started before a passing verification checked the old hooks:
// its result is dropped, and the next Health walks the new hooks.
func TestHealthDropsWalkOfOldHooks(t *testing.T) {
	f := newFakeBarrier(t)
	o := &Owner{ready: true, hooks: []rootbarrier.Hook{{LSM: "path_chroot"}}}
	f.attestGate = make(chan struct{})
	done := make(chan error)
	go func() { done <- o.Health() }()
	for f.linkChecks.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	o.mu.Lock()
	o.attestGen++ // a verification passed while the walk ran
	o.mu.Unlock()
	close(f.attestGate)
	if err := <-done; !errors.Is(err, errNotAttested) {
		t.Fatalf("a walk of the old hooks: %v, want not yet attested", err)
	}
	if !o.lastAttest.IsZero() {
		t.Fatal("a walk of the old hooks must not count as an attestation")
	}
	f.attestGate = nil
	if err := o.Health(); err != nil || f.linkChecks.Load() != 2 {
		t.Fatalf("the next Health walks again: %v after %d walks", err, f.linkChecks.Load())
	}
}
