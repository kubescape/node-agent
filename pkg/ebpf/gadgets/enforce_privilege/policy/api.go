package privpolicy

import (
	"fmt"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// FromAPI converts a SandboxPolicy privilege section into a validated Document.
// Actor and path predicates are not supported yet and are rejected.
func FromAPI(name string, mode api.PolicyMode, section api.PrivilegeSection) (Document, error) {
	doc := Document{Name: name, Version: 1, Policy: Policy{Mode: string(mode), Privilege: Section{Default: string(section.Default)}}}
	for _, r := range section.Rules {
		t := r.Target
		if r.Actor != nil || len(t.Path) > 0 || len(t.PathClass) > 0 || t.FromImage != nil || len(t.FSType) > 0 {
			return doc, fmt.Errorf("rule %q: actor and path targets are unsupported in the privilege section", r.Name)
		}
		doc.Policy.Privilege.Rules = append(doc.Policy.Privilege.Rules, Rule{
			Name: r.Name, Action: string(r.Action), Mode: string(r.Mode), Origin: r.Origin,
			Target: Target{Syscall: t.Syscall, Flags: t.Flags, Capability: t.Capability, MountFSType: t.MountFSType},
		})
	}
	return doc, doc.Validate()
}
