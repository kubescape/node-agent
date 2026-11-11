package igbackend

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
)

// A gated slot (for file: an enforcing slot without an attested root
// barrier) is refused at Bind and reported by SlotHealth; other slots are not
// affected.
func TestNodeInstanceSlotGate(t *testing.T) {
	i := &nativeNodeInstance{section: "file", slotGate: func(slot uint32) error {
		if slot == 1 {
			return fmt.Errorf("root barrier: no live LSM link")
		}
		return nil
	}}
	// bindings is nil: a refused Bind must return before it is used.
	err := i.Bind(enforcement.Binding{Slot: 1})
	if err == nil || !strings.Contains(err.Error(), "file slot 1 refused: root barrier") {
		t.Fatalf("Bind of a gated slot: %v", err)
	}
	if err := i.SlotHealth(1); err == nil {
		t.Fatal("SlotHealth of a gated slot is nil")
	}
	if err := i.SlotHealth(0); err != nil {
		t.Fatalf("SlotHealth of an open slot: %v", err)
	}
}
