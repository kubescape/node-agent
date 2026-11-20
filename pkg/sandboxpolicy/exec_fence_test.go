// Copyright 2026 The Kubescape authors
// SPDX-License-Identifier: Apache-2.0

package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type reconcileFenceProbe struct {
	backend        *fakeBackend
	prepared       []ExecFenceCandidate
	prepareError   error
	replaceError   error
	withdrawnError error
	inherited      bool
	moved          []string
	removed        []string
}

func (p *reconcileFenceProbe) Prepare(_ context.Context, all []ExecFenceCandidate) error {
	p.prepared = slices.Clone(all)
	return p.prepareError
}

func (p *reconcileFenceProbe) PrepareExplicitRemoval(_ context.Context, b Binding, retained Plan, noExec bool) error {
	key := bindingKey(b)
	for i := range p.prepared {
		if bindingKey(p.prepared[i].Binding) == key {
			p.prepared[i].Plan = retained
			p.prepared[i].NoExec = noExec
			p.prepared[i].Known = true
			if len(retained.Policies) == 0 {
				p.inherited = true
			}
			return nil
		}
	}
	return fmt.Errorf("explicit removal lacks exact retained fence binding")
}

func (p *reconcileFenceProbe) BeforeReplace(context.Context, Binding, string) error {
	return p.replaceError
}

func (p *reconcileFenceProbe) PrepareWithdrawal(context.Context, Binding) (bool, error) {
	return p.inherited, nil
}

func (p *reconcileFenceProbe) VerifyAndMove(_ context.Context, b Binding, revision string) error {
	if p.backend.plans[bindingKey(b)].Revision != revision || revision == "" {
		return fmt.Errorf("attempted release before exact backend commit")
	}
	for _, c := range p.prepared {
		if bindingKey(c.Binding) == bindingKey(b) && c.Known && c.Plan.Revision == revision {
			p.moved = append(p.moved, b.ContainerID)
			return nil
		}
	}
	return fmt.Errorf("attempted release outside known census")
}

func (p *reconcileFenceProbe) Withdrawn(_ context.Context, b Binding) error {
	if p.withdrawnError != nil {
		return p.withdrawnError
	}
	if _, live := p.backend.plans[bindingKey(b)]; live {
		return fmt.Errorf("attempted Off before native withdrawal commit")
	}
	p.removed = append(p.removed, b.ContainerID)
	return nil
}

func (*reconcileFenceProbe) Refence(context.Context, Binding) error    { return nil }
func (*reconcileFenceProbe) Deactivate(context.Context, Binding) error { return nil }

func TestExecFenceStagesCensusBeforeAnyProductMutation(t *testing.T) {
	ctx := context.Background()
	strict := policy("strict", "ns")
	strict.Spec.Mode, strict.Spec.Containers = api.ModeEnforce, []string{"app"}
	audit := policy("audit", "ns")
	audit.Spec.Mode, audit.Spec.Containers = api.ModeAudit, []string{"audit"}
	c, backend, _, _ := setup(t, strict, audit)
	probe := &reconcileFenceProbe{backend: backend, prepareError: errors.New("census not committed")}
	c.options.ExecFence = probe
	app, sibling, off := binding(), binding(), binding()
	sibling.ContainerID, sibling.ContainerName, sibling.CgroupID = "audit-id", "audit", 14
	off.ContainerID, off.ContainerName, off.CgroupID = "off-id", "unselected", 15
	read := func(context.Context, func(Binding) bool) ([]Binding, error) {
		return []Binding{app, sibling, off}, nil
	}
	if err := c.Refresh(ctx, read); !errors.Is(err, probe.prepareError) {
		t.Fatalf("expected census refusal: %v", err)
	}
	if backend.replacements != 0 || len(probe.moved) != 0 {
		t.Fatal("product mutated despite refused census")
	}
	probe.prepareError = nil
	if err := c.Refresh(ctx, read); err != nil {
		t.Fatal(err)
	}
	if len(probe.prepared) != 3 || len(probe.moved) != 2 || backend.replacements != 2 {
		t.Fatalf("expected complete census and separate handovers: %+v, moved=%v", probe.prepared, probe.moved)
	}
	for _, candidate := range probe.prepared {
		if !candidate.Scope || !candidate.MayStrict || !candidate.Known {
			t.Fatalf("mixed pod cannot use an Audit fallback or lose known sibling census: %+v", candidate)
		}
	}
}

func TestExecFenceDiscoveryLossIsNotOff(t *testing.T) {
	ctx := context.Background()
	policy := policy("selected", "ns")
	c, backend, _, cl := setup(t, policy)
	probe := &reconcileFenceProbe{backend: backend}
	c.options.ExecFence = probe
	b := binding()
	if err := c.Refresh(ctx, func(context.Context, func(Binding) bool) ([]Binding, error) { return []Binding{b}, nil }); err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(ctx, func(context.Context, func(Binding) bool) ([]Binding, error) { return []Binding{}, nil }); err != nil {
		t.Fatal(err)
	}
	if len(probe.removed) != 0 || backend.withdrawals != 1 {
		t.Fatalf("missing discovery was treated as policy withdrawal: %v", probe.removed)
	}
	if err := cl.Resource(PolicyGVR).Namespace("ns").Delete(ctx, "selected", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	probe.inherited = true
	if err := c.Refresh(ctx, func(context.Context, func(Binding) bool) ([]Binding, error) { return []Binding{b}, nil }); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(probe.removed, []string{b.ContainerID}) || backend.withdrawals != 2 {
		t.Fatalf("authoritative deletion did not publish Off: %v", probe.removed)
	}
}

func TestExecFenceRejectsCandidateBeforeNativePublication(t *testing.T) {
	c, backend, writer, _ := setup(t, policy("new-class", "ns"))
	probe := &reconcileFenceProbe{backend: backend, replaceError: errors.New("retained class differs")}
	c.options.ExecFence = probe
	err := c.Refresh(t.Context(), func(context.Context, func(Binding) bool) ([]Binding, error) {
		return []Binding{binding()}, nil
	})
	if !errors.Is(err, probe.replaceError) || backend.replacements != 0 || len(probe.moved) != 0 {
		t.Fatalf("candidate reached native publication or handoff: replacements=%d moved=%v err=%v", backend.replacements, probe.moved, err)
	}
	if got := writer.reports["new-class"].Status.Conditions[0]; got.Status != metav1.ConditionFalse {
		t.Fatalf("unpublished candidate reported Ready: %+v", got)
	}
}

func TestExecFenceRecognizesSelectedEmptyExecPolicy(t *testing.T) {
	p := policy("empty", "ns")
	p.Spec.Exec = nil
	c, backend, _, _ := setup(t, p)
	probe := &reconcileFenceProbe{backend: backend}
	c.options.ExecFence = probe
	if err := c.Refresh(t.Context(), func(context.Context, func(Binding) bool) ([]Binding, error) {
		return []Binding{binding()}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(probe.prepared) != 1 || !probe.prepared[0].NoExec || probe.prepared[0].Scope || backend.replacements != 1 {
		t.Fatalf("empty exec native policy was not preserved: census=%+v replacements=%d", probe.prepared, backend.replacements)
	}
}

func TestExecFenceStopReportOnlyClaimsAttestedArm(t *testing.T) {
	for _, fenced := range []bool{true, false} {
		t.Run(fmt.Sprint(fenced), func(t *testing.T) {
			ctx := context.Background()
			p := policy("selected", "ns")
			c, _, writer, _ := setup(t, p)
			if err := c.InitialSync(ctx); err != nil {
				t.Fatal(err)
			}
			if err := c.StopReportingFenced(ctx, fenced); err != nil {
				t.Fatal(err)
			}
			got := writer.reports[string(p.UID)].Status
			if got.AppliedGeneration != 0 || got.Conditions[0].Status != metav1.ConditionFalse {
				t.Fatalf("stop claimed product readiness: %+v", got)
			}
			if fenced {
				if got.Conditions[0].Reason != AgentStoppingReason || !strings.Contains(got.Conditions[0].Message, "fence is armed") {
					t.Fatalf("attested stop did not report fencing: %+v", got.Conditions[0])
				}
			} else if got.Conditions[0].Reason != AgentStoppingUnconfirmedReason {
				t.Fatalf("unattested stop claimed fencing: %+v", got.Conditions[0])
			}
		})
	}
}
