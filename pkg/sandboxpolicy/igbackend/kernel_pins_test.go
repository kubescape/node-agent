//go:build linux && sandboxpolicy_kernel

package igbackend

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	fileruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/runtime"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
)

// cleanStatePins starts a kernel test on empty section state and removes the
// state maps the gadgets pinned by name (sbx1_*) when it ends, so no state
// outlives the run.
func cleanStatePins(t *testing.T) {
	t.Helper()
	clean := func() {
		for _, prefix := range []string{privruntime.MapPrefix, netruntime.MapPrefix, fileruntime.MapPrefix} {
			if err := enforcement.RemovePinnedMaps(prefix); err != nil {
				t.Errorf("removing the %s state pins: %v", prefix, err)
			}
		}
	}
	clean()
	t.Cleanup(clean)
}
