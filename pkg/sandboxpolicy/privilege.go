package sandboxpolicy

import (
	"fmt"

	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// PrivilegeDocument translates the privilege section of one SandboxPolicy into
// the privilege gadget's own policy document. name qualifies rule names in
// events. Actor and path predicates are not supported by the gadget yet and
// are rejected.
func PrivilegeDocument(name string, mode api.PolicyMode, section api.PrivilegeSection) (privpolicy.Document, error) {
	doc := privpolicy.Document{Name: name, Version: 1, Policy: privpolicy.Policy{Mode: string(mode), Privilege: privpolicy.Section{Default: string(section.Default)}}}
	for _, r := range section.Rules {
		t := r.Target
		if r.Actor != nil || len(t.Path) > 0 || len(t.PathClass) > 0 || t.FromImage != nil || len(t.FSType) > 0 {
			return doc, fmt.Errorf("rule %q: actor and path targets are unsupported in the privilege section", r.Name)
		}
		doc.Policy.Privilege.Rules = append(doc.Policy.Privilege.Rules, privpolicy.Rule{
			Name: r.Name, Action: string(r.Action), Mode: string(r.Mode), Origin: r.Origin,
			Target: privpolicy.Target{Syscall: t.Syscall, Flags: t.Flags, Capability: t.Capability, MountFSType: t.MountFSType},
		})
	}
	return doc, doc.Validate()
}
