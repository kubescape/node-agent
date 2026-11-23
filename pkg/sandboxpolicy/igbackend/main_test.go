// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package igbackend

import (
	"context"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
	fileruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/runtime"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// resets records the prefixes the sections passed to the pin reset.
var resets struct {
	sync.Mutex
	prefixes []string
}

func recordReset(prefix string) error {
	resets.Lock()
	defer resets.Unlock()
	resets.prefixes = append(resets.prefixes, prefix)
	return nil
}

// TestMain keeps every test build off the host's pinned BPF state, the
// kernel-tag build too: the sections that the unit tests start on fake
// engines reset their pins before the first start, and a run as root would
// remove the real ones (go test runs packages in parallel, so a kernel test
// of another package would lose its pinned maps). The reset only records its
// prefix; a kernel test that needs it opts in (realPinReset).
func TestMain(m *testing.M) {
	removePinnedMaps = recordReset
	os.Exit(m.Run())
}

// realPinReset gives a kernel test the real reset until it ends.
func realPinReset(t *testing.T) {
	t.Helper()
	removePinnedMaps = enforcement.RemovePinnedMaps
	t.Cleanup(func() { removePinnedMaps = recordReset })
}

// Each section resets its own pins (its map prefix) before its first start.
func TestSectionsResetTheirOwnPins(t *testing.T) {
	saved := compileFileSlots
	defer func() { compileFileSlots = saved }()
	compileFileSlots = func(_ [][]filepolicy.Document, generation uint64) (filepolicy.Compiled, error) {
		return filepolicy.Compiled{Generation: generation}, nil
	}
	ctx := context.Background()
	for _, tc := range []struct {
		prefix string
		start  func() error
	}{
		{privruntime.MapPrefix, func() error {
			b, _ := NewPrivilege(&fakePrivilegeEngine{}, nil, "n")
			return b.Prepare(ctx, []sandboxpolicy.Plan{privPlan("r1", privPolicy("p1", "deny"))})
		}},
		{netruntime.MapPrefix, func() error {
			b, _ := NewNetwork(&fakeNetworkEngine{}, nil, "n")
			return b.Prepare(ctx, []sandboxpolicy.Plan{privPlan("r1", netPolicy("p1", "allow", denyTestNet))})
		}},
		{fileruntime.MapPrefix, func() error {
			b, _ := NewFile(&fakeFileEngine{}, nil, "n")
			return b.Prepare(ctx, []sandboxpolicy.Plan{privPlan("r1", filePolicy("p1", "deny"))})
		}},
	} {
		resets.Lock()
		resets.prefixes = nil
		resets.Unlock()
		if err := tc.start(); err != nil {
			t.Fatalf("%s: %v", tc.prefix, err)
		}
		resets.Lock()
		got := slices.Clone(resets.prefixes)
		resets.Unlock()
		if !slices.Equal(got, []string{tc.prefix}) {
			t.Fatalf("reset prefixes %v, want [%s]", got, tc.prefix)
		}
	}
}
