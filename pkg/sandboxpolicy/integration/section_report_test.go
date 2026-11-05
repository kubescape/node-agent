package integration

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
)

type fakeSectionOwner struct{ generation uint64 }

func (o fakeSectionOwner) SlotPolicies(generation uint64, slot uint32) ([]sandboxpolicy.CompiledPolicy, bool) {
	if generation != o.generation || slot != 0 {
		return nil, false
	}
	return []sandboxpolicy.CompiledPolicy{{Revision: "rev"}}, true
}
func (fakeSectionOwner) VerdictStats() igbackend.VerdictStats { return igbackend.VerdictStats{Unavailable: 1} }

func TestSectionVerdictLookups(t *testing.T) {
	s := &Service{
		cgroups:       map[uint64]sandboxpolicy.Binding{10: {ContainerID: "c", CgroupID: 10}},
		podCgroups:    map[uint64]sandboxpolicy.Binding{20: {PodUID: "pod", CgroupID: 20}},
		sectionOwners: map[string]sectionOwner{sandboxpolicy.SectionFile: fakeSectionOwner{generation: 3}},
	}
	if b, ok := s.resolveCgroup(10); !ok || b.ContainerID != "c" {
		t.Fatalf("container cgroup: %+v %v", b, ok)
	}
	if b, ok := s.resolveCgroup(20); !ok || b.PodUID != "pod" || b.ContainerID != "" {
		t.Fatalf("pod cgroup: %+v %v", b, ok)
	}
	if _, ok := s.resolveCgroup(30); ok {
		t.Fatal("unknown cgroup")
	}
	if p, ok := s.slotPolicies(sandboxpolicy.SectionFile, 3, 0); !ok || p[0].Revision != "rev" {
		t.Fatalf("file owner: %+v %v", p, ok)
	}
	if _, ok := s.slotPolicies(sandboxpolicy.SectionNetwork, 3, 0); ok {
		t.Fatal("a section with no backend has no policies")
	}
	if stats := s.SectionVerdictStats(); len(stats) != 1 || stats[sandboxpolicy.SectionFile].Unavailable != 1 {
		t.Fatalf("stats %+v", stats)
	}
}
