package state

import (
	"sync"

	"github.com/kubescape/node-agent/pkg/rulestate"
)

// AccessorContextKey is the eval-context key under which the caller injects the
// per-(rule, event) Accessor. It is the CEL variable name authors write as
// "state", and it is the ONLY state-related entry in the eval context.
const AccessorContextKey = "state"

// ReadTracker records which entries a predicate actually read, so the alert can
// carry them as correlation evidence. Only hits are recorded: a miss is not
// evidence of anything.
//
// MUST be reset between rules. node-agent reuses one eval context across all
// rules for an event, so without a reset rule N inherits rule N-1's hits and
// alerts cite entries they never read.
type ReadTracker struct {
	mu   sync.Mutex
	hits []*rulestate.Entry
}

func (t *ReadTracker) record(e *rulestate.Entry) {
	if e == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, h := range t.hits {
		if h == e {
			return // same entry read twice in one predicate
		}
	}
	t.hits = append(t.hits, e)
}

func (t *ReadTracker) Hits() []*rulestate.Entry {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]*rulestate.Entry(nil), t.hits...)
}

func (t *ReadTracker) Reset() {
	t.mu.Lock()
	t.hits = t.hits[:0]
	t.mu.Unlock()
}
