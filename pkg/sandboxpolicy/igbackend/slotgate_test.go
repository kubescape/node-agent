package igbackend

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
)

// A gated slot (for file: an enforcing slot without an attested root
// barrier) is refused at Bind and reported by SlotHealth; other slots are not
// affected. The gate gets the class of the binding: a PendingSlot binding
// carries its own (Binding.Strict), since Strict(PendingSlot) is the
// configured class of a slot that does not exist.
func TestNodeInstanceSlotGate(t *testing.T) {
	// Not started: Bind past the gate fails with "not running", which is
	// not a gate refusal. Slot 1 is Strict.
	bindings, err := enforcement.New(enforcement.Config{Name: "gate", Generation: 1, Slots: 2, PolicyMap: "policy",
		WritePolicy: func(enforcement.Map) error { return nil }, StrictSlot: func(slot uint32) bool { return slot == 1 }})
	if err != nil {
		t.Fatal(err)
	}
	var gotStrict []bool
	i := &nativeNodeInstance{section: "file", bindings: bindings, slotGate: func(_ uint32, strict bool) error {
		gotStrict = append(gotStrict, strict)
		if strict {
			return fmt.Errorf("root barrier: no live LSM link")
		}
		return nil
	}}
	pod := enforcement.ContainerIdentity{Runtime: "kubernetes-pod", ID: "uid-1", CgroupID: 7, CgroupPath: "/kubepods.slice/pod-uid-1"}
	tests := []struct {
		name    string
		binding enforcement.Binding
		strict  bool
	}{
		{name: "Strict slot", binding: enforcement.Binding{Container: pod, Slot: 1}, strict: true},
		{name: "Audit slot", binding: enforcement.Binding{Container: pod, Slot: 0}, strict: false},
		{name: "Strict pending", binding: enforcement.Binding{Container: pod, Slot: enforcement.PendingSlot, Strict: true}, strict: true},
		{name: "Audit pending", binding: enforcement.Binding{Container: pod, Slot: enforcement.PendingSlot}, strict: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStrict = nil
			err := i.Bind(tt.binding)
			if len(gotStrict) != 1 || gotStrict[0] != tt.strict {
				t.Fatalf("the gate got class %v, want [%v]", gotStrict, tt.strict)
			}
			refused := err != nil && strings.Contains(err.Error(), fmt.Sprintf("file slot %d refused: root barrier", tt.binding.Slot))
			if refused != tt.strict {
				t.Fatalf("Bind: refused %v, want %v (%v)", refused, tt.strict, err)
			}
		})
	}
	if err := i.SlotHealth(1); err == nil {
		t.Fatal("SlotHealth of a gated slot is nil")
	}
	if err := i.SlotHealth(0); err != nil {
		t.Fatalf("SlotHealth of an open slot: %v", err)
	}
}
