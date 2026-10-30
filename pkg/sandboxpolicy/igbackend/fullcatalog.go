package igbackend

import (
	"fmt"
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// FullVerdictCatalogCapacity bounds provenance retained per persistent owner,
// including its active generation and at most one pending publication. Late
// events for evicted generations are dropped, never decoded with newer rules.
const FullVerdictCatalogCapacity = 16

// FullVerdictCatalog is local provenance, not proof of kernel publication or
// health. It must not be copied after first use. One catalogue belongs to one
// exact binding and must outlive that owner's event subscription.
type FullVerdictCatalog struct {
	mu                    sync.RWMutex
	binding               sandboxpolicy.Binding
	last, active, pending uint64
	decoders              map[uint64]*FullVerdictDecoder
}

func NewFullVerdictCatalog(binding sandboxpolicy.Binding) *FullVerdictCatalog {
	return &FullVerdictCatalog{binding: binding, decoders: make(map[uint64]*FullVerdictDecoder)}
}

// Stage validates and snapshots provenance BEFORE calling the kernel publisher.
// Once admitted (no pending publication), an attempt number is consumed even if
// validation fails. Resumption uses the existing staged generation, not Stage.
// Staged events can be decoded because kernel commit may precede its Go receipt.
func (c *FullVerdictCatalog) Stage(generation uint64, plan sandboxpolicy.Plan, program *fullpolicy.KernelProgram) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != 0 {
		return fmt.Errorf("verdict generation %d still pending", c.pending)
	}
	if generation == 0 || generation <= c.last {
		return fmt.Errorf("verdict generation must increase beyond %d", c.last)
	}
	c.last = generation
	d, err := NewFullVerdictDecoder(c.binding, plan, program)
	if err != nil {
		return err
	}
	if d.generation != generation {
		return fmt.Errorf("verdict program generation does not match attempt")
	}
	if len(c.decoders) == FullVerdictCatalogCapacity {
		var oldest uint64
		for g := range c.decoders {
			if g != c.active && (oldest == 0 || g < oldest) {
				oldest = g
			}
		}
		delete(c.decoders, oldest)
	}
	c.decoders[generation] = d
	c.pending = generation
	return nil
}

// Commit records an irreversible kernel commit, even if publication finalization
// failed. It is idempotent for the active generation. Never Abort a committed
// publication: retain its provenance while resuming the same kernel generation.
func (c *FullVerdictCatalog) Commit(generation uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation != 0 && c.active == generation {
		return nil
	}
	if generation == 0 || c.pending != generation {
		return fmt.Errorf("verdict generation %d is not pending", generation)
	}
	c.active, c.pending = generation, 0
	return nil
}

// Abort removes only an uncommitted pending attempt after the kernel publisher
// confirms it did not commit. The attempt number is never reusable.
func (c *FullVerdictCatalog) Abort(generation uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation == 0 || c.pending != generation {
		return fmt.Errorf("verdict generation %d is not pending", generation)
	}
	delete(c.decoders, generation)
	c.pending = 0
	return nil
}

func (c *FullVerdictCatalog) Decode(raw RawFullVerdict) (sandboxpolicy.Verdict, error) {
	c.mu.RLock()
	d := c.decoders[raw.Generation]
	c.mu.RUnlock()
	if d == nil {
		return sandboxpolicy.Verdict{}, fmt.Errorf("unknown or evicted verdict generation %d", raw.Generation)
	}
	// Decoder snapshots are immutable; do not hold the catalogue lock while
	// decoding, and never run exporter callbacks under a publication lock.
	return d.Decode(raw)
}
