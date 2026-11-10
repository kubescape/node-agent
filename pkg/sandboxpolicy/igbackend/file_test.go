package igbackend

import (
	"context"
	"errors"
	"testing"

	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

type fakeFileEngine struct {
	instances []*fakePrivilegeInstance
	configs   []FileConfig
}

func (e *fakeFileEngine) Start(_ context.Context, _ string, c FileConfig) (NodeInstance, error) {
	i := &fakePrivilegeInstance{bound: map[uint64]uint32{}}
	for _, b := range c.InitialBindings {
		i.bound[b.Container.CgroupID] = b.Slot
	}
	e.instances = append(e.instances, i)
	e.configs = append(e.configs, c)
	return i, nil
}

func filePolicy(uid, def string) sandboxpolicy.CompiledPolicy {
	defaults := map[string]filepolicy.Default{}
	for _, k := range filepolicy.AccessKinds {
		defaults[k] = filepolicy.Default{Action: def}
	}
	doc := filepolicy.Document{Version: 1, Policy: filepolicy.Policy{Mode: "enforce", File: filepolicy.Section{Defaults: defaults}}}
	return sandboxpolicy.CompiledPolicy{Identity: sandboxpolicy.PolicyIdentity{UID: types.UID(uid), Namespace: "ns", Name: uid}, Mode: api.ModeEnforce, File: &sandboxpolicy.FilePlan{Doc: doc}}
}

func TestFileNodeInstanceSlots(t *testing.T) {
	// The gadget compiler is tested in its own package; record its input.
	var compiled [][]filepolicy.Document
	saved := compileFileSlots
	defer func() { compileFileSlots = saved }()
	compileFileSlots = func(slots [][]filepolicy.Document, generation uint64) (filepolicy.Compiled, error) {
		compiled = slots
		return filepolicy.Compiled{Generation: generation}, nil
	}
	e := &fakeFileEngine{}
	b, err := NewFile(e, nil, "n")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i, plan := range []sandboxpolicy.Plan{privPlan("r1", filePolicy("p1", "allow")), privPlan("r2", filePolicy("p1", "allow"), filePolicy("p2", "deny"))} {
		if r, err := b.Replace(ctx, privBinding(uint64(i+1)), plan); err != nil || !r.Committed {
			t.Fatalf("bind %d: %+v %v", i, r, err)
		}
	}
	last := e.instances[len(e.instances)-1]
	if last.bound[1] == last.bound[2] {
		t.Fatal("two combinations must have two slots")
	}
	// The second combination is compiled alone and published in place.
	if len(e.instances) != 1 || len(compiled) != 1 || len(compiled[0]) != 2 || compiled[0][0].Name != "ns/p1" || compiled[0][1].Name != "ns/p2" {
		t.Fatalf("documents %+v instances=%d", compiled, len(e.instances))
	}
	if _, err := NewFile(nil, nil, "n"); err == nil {
		t.Fatal("an engine is required")
	}
}

func TestFileCombinationKeysOnTheDocument(t *testing.T) {
	a, b := filePolicy("p1", "allow"), filePolicy("p1", "allow")
	b.File.Report.NotEnforced = []string{"rule x: fsType is not enforced"}
	b.Revision = "other"
	ka, pa := FileCombination(privPlan("r", a, privPolicy("p2", api.ActionAllow)))
	kb, _ := FileCombination(privPlan("r", b))
	if ka != kb || len(pa) != 1 {
		t.Fatalf("keys %q %q, policies %d", ka, kb, len(pa))
	}
	if kc, _ := FileCombination(privPlan("r", filePolicy("p1", "deny"))); kc == ka {
		t.Fatal("a document change must change the key")
	}
}

func TestCheckFile(t *testing.T) {
	var u *sandboxpolicy.EnforcementUnavailableError
	if err := CheckFile(t.TempDir()); !errors.As(err, &u) || u.Section != sandboxpolicy.SectionFile || u.Reason != "BPFLSMInactive" {
		t.Fatalf("err %v", err)
	}
}

// File binds pod cgroups like privilege: the pod binding skips the arming
// (runc init and OCI hooks can be in the pod cgroup), and a new combination,
// published in place, leaves it as it is.
func TestFilePodBindings(t *testing.T) {
	saved := compileFileSlots
	defer func() { compileFileSlots = saved }()
	compileFileSlots = func(_ [][]filepolicy.Document, generation uint64) (filepolicy.Compiled, error) {
		return filepolicy.Compiled{Generation: generation}, nil
	}
	e := &fakeFileEngine{}
	b, _ := NewFile(e, nil, "n")
	ctx := context.Background()
	p1 := privPlan("r1", filePolicy("p1", "deny"))
	p2 := privPlan("r2", filePolicy("p2", "allow"))
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1}); err != nil {
		t.Fatal(err)
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, p1)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.instances[len(e.instances)-1].bound[100]; !ok {
		t.Fatalf("pod not bound: %+v", e.instances[len(e.instances)-1].bound)
	}
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1, p2}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.instances[0].bound[100]; !ok || len(e.instances) != 1 || len(e.instances[0].published) != 1 {
		t.Fatalf("the pod binding must stay in the running instance: %+v", e.instances[0].bound)
	}
	if p := b.nativePod(testPodBinding("a", 100, p1), 0); !p.SkipArming || p.Container.Runtime != podRuntime {
		t.Fatalf("pod binding %+v", p)
	}
	if err := b.BindPods(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.instances[len(e.instances)-1].bound[100]; ok {
		t.Fatal("pod binding must be removed")
	}
}
