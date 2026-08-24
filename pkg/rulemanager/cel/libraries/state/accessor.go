package state

import (
	"fmt"
	"reflect"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulestate"
)

// AccessorType is the CEL type of the "state" variable.
var AccessorType = cel.ObjectType("rulestate.Accessor")

// Accessor is the receiver behind the CEL "state" variable: state.has(...) is a
// member call on it, not a global function.
//
// It exists because cel-go hands a function binding only its arguments -- never
// the activation -- so a global function named "state.has" could not discover
// which rule or which container it was evaluating for. Making "state" a variable
// puts that context in the receiver, where the binding can reach it.
//
// The consequence is the security property the design depends on: ruleID, the
// scope IDs and the ancestor list live in the receiver, and there is no CEL
// syntax for supplying or overriding them. A rule author therefore cannot name
// another rule's state or another container's scope -- those reads are not merely
// forbidden, they are inexpressible.
//
// One Accessor is valid for one (rule, event) pair. The rule loop rebuilds it per
// rule, because ruleID and the declared-name scopes change per rule.
type Accessor struct {
	store  *rulestate.Store
	ruleID string

	// scopeOf maps a state name to the scope the rule declared it in. Reads take
	// no scope argument: because state is rule-private, a name uniquely
	// determines its scope from the rule's own stateWrites.
	scopeOf map[string]armotypes.StateScope

	// scopeIDs holds this event's resolved ID for each scope.
	scopeIDs map[armotypes.StateScope]string

	// ancestors is called at most once per evaluation, lazily: most rules never
	// call has_ancestor, and walking the process tree is not free.
	ancestors     func() []uint32
	ancestorsMemo []uint32
	ancestorsDone bool

	tracker *ReadTracker
	adapter types.Adapter
}

// NewAccessor builds the receiver for one (rule, event) pair. ancestors is
// invoked lazily and at most once.
func NewAccessor(
	store *rulestate.Store,
	ruleID string,
	scopeOf map[string]armotypes.StateScope,
	scopeIDs map[armotypes.StateScope]string,
	ancestors func() []uint32,
	tracker *ReadTracker,
	adapter types.Adapter,
) *Accessor {
	if adapter == nil {
		adapter = types.DefaultTypeAdapter
	}
	return &Accessor{
		store:     store,
		ruleID:    ruleID,
		scopeOf:   scopeOf,
		scopeIDs:  scopeIDs,
		ancestors: ancestors,
		tracker:   tracker,
		adapter:   adapter,
	}
}

func (a *Accessor) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if typeDesc == reflect.TypeOf(a) {
		return a, nil
	}
	return nil, fmt.Errorf("state accessor cannot be converted to %v", typeDesc)
}

func (a *Accessor) ConvertToType(t ref.Type) ref.Val {
	if t == types.TypeType {
		return AccessorType
	}
	return types.NewErr("state accessor cannot be converted to %v", t)
}

func (a *Accessor) Equal(other ref.Val) ref.Val {
	o, ok := other.(*Accessor)
	return types.Bool(ok && o == a)
}

func (a *Accessor) Type() ref.Type { return AccessorType }
func (a *Accessor) Value() any     { return a }

// lookup resolves one entry. A name the rule never declared is a miss rather
// than an error: load-time validation is what rejects it, and failing the whole
// predicate here would take out an otherwise working rule.
func (a *Accessor) lookup(name, key string) (*rulestate.Entry, bool) {
	if a == nil || a.store == nil {
		return nil, false
	}
	scope, ok := a.scopeOf[name]
	if !ok {
		return nil, false
	}
	scopeID, ok := a.scopeIDs[scope]
	if !ok {
		return nil, false
	}
	e, ok := a.store.Get(a.ruleID, scopeID, name, key)
	if !ok {
		return nil, false
	}
	if a.tracker != nil {
		a.tracker.record(e)
	}
	return e, true
}

// lookupAncestor probes each ancestor PID in order and returns the first hit, so
// get_ancestor yields the NEAREST matching ancestor.
func (a *Accessor) lookupAncestor(name string) (*rulestate.Entry, bool) {
	if a == nil {
		return nil, false
	}
	for _, pid := range a.ancestorPIDs() {
		if e, ok := a.lookup(name, fmt.Sprint(pid)); ok {
			return e, true
		}
	}
	return nil, false
}

func (a *Accessor) ancestorPIDs() []uint32 {
	if a.ancestorsDone {
		return a.ancestorsMemo
	}
	a.ancestorsDone = true
	if a.ancestors != nil {
		a.ancestorsMemo = a.ancestors()
	}
	return a.ancestorsMemo
}

// entryToMap renders an entry for CEL. Engine-stamped provenance uses reserved
// "_" keys; author values from the rule's `value:` sit alongside at top level.
// Author keys beginning with "_" are rejected at rule load, so they cannot
// shadow provenance here.
func entryToMap(e *rulestate.Entry) map[string]any {
	m := map[string]any{
		"_ts":        e.Timestamp,
		"_eventType": string(e.EventType),
		"_container": e.ScopeID,
	}
	if e.Process != nil {
		m["_pid"] = e.Process.PID
		m["_ppid"] = e.Process.PPID
		m["_comm"] = e.Process.Comm
		m["_pcomm"] = e.Process.Pcomm
		m["_exe"] = e.Process.Path
		m["_cwd"] = e.Process.Cwd
	}
	for k, v := range e.Value {
		m[k] = v
	}
	return m
}

// emptyMap is what a miss yields. Never an error: a message expression must
// degrade rather than abort evaluation of the whole rule.
func (a *Accessor) emptyMap() ref.Val {
	return types.NewStringInterfaceMap(a.adapter, map[string]any{})
}

func (a *Accessor) entryVal(e *rulestate.Entry) ref.Val {
	return types.NewStringInterfaceMap(a.adapter, entryToMap(e))
}
