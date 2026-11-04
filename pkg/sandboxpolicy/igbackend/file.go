package igbackend

import (
	"context"
	"fmt"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
	fileruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// CheckFile returns an EnforcementUnavailableError unless the file section
// can be enforced: its programs are BPF LSM programs.
func CheckFile(hostRoot string) error { return checkBPFLSM(hostRoot, sandboxpolicy.SectionFile) }

// FileNode describes this node for the file translation: fromImage needs an
// overlay inode layout the gadget can read (fileruntime.FromImageUnavailable).
func FileNode() sandboxpolicy.FileNode {
	return sandboxpolicy.FileNode{FromImageUnavailable: fileruntime.FromImageUnavailable()}
}

// FileConfig is what one enforce_file instance starts with. It has the fields
// of the file runtime's Config.
type FileConfig struct {
	Policy          filepolicy.Compiled
	InitialBindings []enforcement.Binding
}

// FileEngine starts one node-wide enforce_file instance. Start returns only
// after native readiness, or after failed-candidate cleanup.
type FileEngine interface {
	Start(ctx context.Context, id string, config FileConfig) (NodeInstance, error)
}

// FileBackend owns ONE enforce_file instance per node (see nodeOwner). A slot
// is one combination of file policies.
type FileBackend struct {
	nodeOwner[filepolicy.Compiled]
}

var (
	_ sandboxpolicy.Backend            = (*FileBackend)(nil)
	_ sandboxpolicy.ProtectionAttester = (*FileBackend)(nil)
	_ sandboxpolicy.SlotPreparer       = (*FileBackend)(nil)
)

// compileFileSlots is the gadget compiler; a variable so tests can run the
// backend without it.
var compileFileSlots = filepolicy.CompileSlots

// NewFile creates the node backend. validator verifies the live container
// identity before a bind and holds it while bound; nil skips the check (tests).
func NewFile(engine FileEngine, validator Validator, prefix string) (*FileBackend, error) {
	if engine == nil {
		return nil, fmt.Errorf("file engine is required")
	}
	section := nodeSection[filepolicy.Compiled]{
		name:        sandboxpolicy.SectionFile,
		combination: FileCombination,
		compile: func(generation uint64, slots [][]sandboxpolicy.CompiledPolicy) (filepolicy.Compiled, error) {
			docs := make([][]filepolicy.Document, len(slots))
			for i, policies := range slots {
				for _, p := range policies {
					doc := p.File.Doc
					doc.Name = p.Identity.Namespace + "/" + p.Identity.Name
					docs[i] = append(docs[i], doc)
				}
			}
			return compileFileSlots(docs, generation)
		},
		start: func(ctx context.Context, id string, compiled filepolicy.Compiled, bindings []enforcement.Binding) (NodeInstance, error) {
			return engine.Start(ctx, id, FileConfig{Policy: compiled, InitialBindings: bindings})
		},
	}
	return &FileBackend{newNodeOwner(section, validator, prefix)}, nil
}

// FileCombination returns the file policies of a plan, sorted, and their key.
// Only the gadget document is part of the key.
func FileCombination(plan sandboxpolicy.Plan) (string, []sandboxpolicy.CompiledPolicy) {
	var policies []sandboxpolicy.CompiledPolicy
	for _, p := range plan.Policies {
		if p.File != nil {
			policies = append(policies, p)
		}
	}
	return combinationKey(policies, func(p sandboxpolicy.CompiledPolicy) any { return p.File.Doc })
}
