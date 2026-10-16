package rulecreator_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/kubescape/node-agent/pkg/rulemanager/prefilter"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

func TestCreateAllRulesCallerOwnsOuterSlice(t *testing.T) {
	c := &rulecreator.RuleCreatorImpl{Rules: []typesv1.Rule{{ID: "first"}, {ID: "second"}, {ID: "third"}}}
	a := c.CreateAllRules()
	filtered := a[:0]
	for _, r := range a {
		if r.ID != "first" {
			filtered = append(filtered, r)
		}
	}
	filtered[0].ID = "changed"
	b := c.CreateAllRules()
	for i, id := range []string{"first", "second", "third"} {
		if b[i].ID != id || c.Rules[i].ID != id {
			t.Fatalf("caller mutation changed creator/later result at %d", i)
		}
	}
}
func TestCreateAllRulesEmptyRemainsNil(t *testing.T) {
	for _, rules := range [][]typesv1.Rule{nil, {}} {
		c := &rulecreator.RuleCreatorImpl{Rules: rules}
		if c.CreateAllRules() != nil {
			t.Fatal("empty result must remain nil")
		}
	}
}
func TestCreateAllRulesReflectsSync(t *testing.T) {
	c := &rulecreator.RuleCreatorImpl{Rules: []typesv1.Rule{{ID: "removed"}, {ID: "updated", Name: "old"}}}
	old := c.CreateAllRules()
	c.SyncRules([]typesv1.Rule{{ID: "updated", Name: "new"}, {ID: "added"}})
	got := c.CreateAllRules()
	if len(got) != 2 {
		t.Fatal(len(got))
	}
	seen := map[string]string{}
	for _, r := range got {
		seen[r.ID] = r.Name
	}
	if seen["updated"] != "new" {
		t.Fatal(seen)
	}
	if _, ok := seen["added"]; !ok {
		t.Fatal(seen)
	}
	if _, ok := seen["removed"]; ok {
		t.Fatal(seen)
	}
	if old[0].ID != "removed" || old[1].Name != "old" {
		t.Fatal("sync changed prior outer result")
	}
}
func TestCreateAllRulesConcurrentSync(t *testing.T) {
	c := &rulecreator.RuleCreatorImpl{}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 100 {
			c.SyncRules([]typesv1.Rule{{ID: "rule", State: map[string]any{"ports": []uint16{443}}}})
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			for _, r := range c.CreateAllRules() {
				if r.ID != "rule" {
					t.Error(r.ID)
				}
			}
		}
	}()
	wg.Wait()
}

var sink []typesv1.Rule

func BenchmarkCreateAllRules(b *testing.B) {
	for _, n := range []int{128, 512, 1024} {
		for _, state := range []string{"nil", "filter", "nonfilter"} {
			b.Run(fmt.Sprintf("rules=%d/state=%s", n, state), func(b *testing.B) {
				c := &rulecreator.RuleCreatorImpl{Rules: make([]typesv1.Rule, n)}
				for i := range c.Rules {
					c.Rules[i].ID = fmt.Sprint(i)
					switch state {
					case "filter":
						c.Rules[i].State = map[string]any{"ports": []uint16{443}}
					case "nonfilter":
						c.Rules[i].State = map[string]any{"custom_state": "value"}
					}
				}
				c.CreateAllRules()
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					sink = c.CreateAllRules()
				}
			})
		}
	}
}

func TestCreateAllRulesPrefilterOnFirstCall(t *testing.T) {
	existing := &prefilter.Params{Ports: []uint16{8443}}
	c := &rulecreator.RuleCreatorImpl{Rules: []typesv1.Rule{
		{ID: "initialize", State: map[string]any{"ports": []uint16{443}}},
		{ID: "preserve", State: map[string]any{"ports": []uint16{443}}, Prefilter: existing},
		{ID: "nonfilter", State: map[string]any{"custom_state": "value"}},
	}}
	got := c.CreateAllRules()
	if got[0].Prefilter == nil || len(got[0].Prefilter.Ports) != 1 || got[0].Prefilter.Ports[0] != 443 {
		t.Fatal("first result lost initialized prefilter")
	}
	if got[0].Prefilter != c.Rules[0].Prefilter {
		t.Fatal("returned prefilter differs from initialized creator value")
	}
	if got[1].Prefilter != existing {
		t.Fatal("preinitialized prefilter was overwritten")
	}
	if got[2].Prefilter != nil {
		t.Fatal("nonfilter state should remain without a prefilter")
	}
}
