package igbackend

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// rateInstance is a fake instance whose reporting counters a test sets.
type rateInstance struct {
	*fakePrivilegeInstance
	counters *enforcement.SlotCounters
	node     *enforcement.NodeCounters
	err      *error
}

func (i rateInstance) Counters(uint32) (enforcement.SlotCounters, error) {
	return *i.counters, *i.err
}
func (i rateInstance) NodeCounters() (enforcement.NodeCounters, error) { return *i.node, *i.err }

// The fail-rate windows belong to the owner: a fault stays visible for 60 s
// across a new instance (the counters are pinned), a counter that moved
// backwards is unknown, and a read error is unknown, never zero.
func TestPolicyRatesAcrossInstances(t *testing.T) {
	ctx := context.Background()
	counters, node := &enforcement.SlotCounters{}, &enforcement.NodeCounters{}
	var readErr error
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	wrap := func() { b.instance = rateInstance{e.instances[len(e.instances)-1], counters, node, &readErr} }
	plan := privPlan("r1", privPolicy("p1", api.ActionDeny))
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{plan}); err != nil {
		t.Fatal(err)
	}
	wrap()
	now := time.Unix(1000, 0)
	tick := func(d time.Duration, faults, attempts uint64) {
		for end := now.Add(d); now.Before(end); {
			now = now.Add(5 * time.Second)
			counters.Faults += faults
			counters.Attempts += attempts
			b.SampleRates(now)
		}
	}
	tick(70*time.Second, 0, 100)
	if r, ok := b.PolicyRates("p1", now); !ok || r.Unknown != nil || r.Degraded || r.NotReady {
		t.Fatalf("clean: %+v %v", r, ok)
	}
	if _, ok := b.PolicyRates("other", now); ok {
		t.Fatal("a policy in no slot has no report")
	}
	counters.Faults++
	tick(5*time.Second, 0, 100)
	// A new instance on the same pinned counters: the fault stays.
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{plan, privPlan("r2", privPolicy("p2", api.ActionAllow))}); err != nil {
		t.Fatal(err)
	}
	wrap()
	tick(10*time.Second, 0, 100)
	if r, _ := b.PolicyRates("p1", now); !r.Degraded || r.Unknown != nil {
		t.Fatalf("a fault in the last 60 s stays Degraded after a reload: %+v", r)
	}
	tick(70*time.Second, 0, 1000)
	if r, _ := b.PolicyRates("p1", now); r.Degraded || r.NotReady {
		t.Fatalf("one fault in thousands, older than 60 s: %+v", r)
	}
	// Counters created again (lower than before): unknown, not zero.
	counters.Faults, counters.Attempts = 0, 0
	tick(5*time.Second, 0, 10)
	if r, _ := b.PolicyRates("p1", now); r.Unknown == nil {
		t.Fatalf("a counter that moved backwards must be unknown: %+v", r)
	}
	tick(65*time.Second, 0, 10)
	readErr = errUnreadableMap
	tick(5*time.Second, 0, 0)
	if r, _ := b.PolicyRates("p1", now); r.Unknown == nil {
		t.Fatalf("an unreadable counter must be unknown: %+v", r)
	}
}

var errUnreadableMap = errors.New("map lookup failed")

// Execs the operator-approved helper exemption left unjudged make the slots
// of helper-flagged pod bindings Degraded, never NotReady; node faults count
// only for Strict slots.
func TestPolicyRatesExemptionAndNodeFaults(t *testing.T) {
	ctx := context.Background()
	counters, node := &enforcement.SlotCounters{}, &enforcement.NodeCounters{}
	var readErr error
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	b.SetRuntimeHelperExemption(true)
	strict := privPlan("r1", privPolicy("p1", api.ActionDeny))
	audit := privPolicy("p2", api.ActionDeny)
	audit.Mode = api.ModeAudit
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{strict, privPlan("r2", audit)}); err != nil {
		t.Fatal(err)
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, strict)}); err != nil {
		t.Fatal(err)
	}
	b.instance = rateInstance{e.instances[len(e.instances)-1], counters, node, &readErr}
	now := time.Unix(1000, 0)
	tick := func(d time.Duration) {
		for end := now.Add(d); now.Before(end); {
			now = now.Add(5 * time.Second)
			counters.Attempts += 10
			b.SampleRates(now)
		}
	}
	tick(70 * time.Second)
	node.ExemptExecs = 50
	tick(10 * time.Second)
	if r, _ := b.PolicyRates("p1", now); !r.Degraded || r.NotReady || r.Unknown != nil {
		t.Fatalf("exempted execs on a helper-flagged slot: Degraded only: %+v", r)
	}
	if r, _ := b.PolicyRates("p2", now); r.Degraded {
		t.Fatalf("a slot with no helper-flagged pod binding is not degraded by exemptions: %+v", r)
	}
	tick(70 * time.Second)
	node.NodeFaults = 1
	tick(10 * time.Second)
	if r, _ := b.PolicyRates("p1", now); !r.Degraded {
		t.Fatalf("a node fault degrades a Strict slot: %+v", r)
	}
	if r, _ := b.PolicyRates("p2", now); r.Degraded {
		t.Fatalf("a node fault does not degrade an Audit slot: %+v", r)
	}
}
