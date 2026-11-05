package sandboxpolicy

import (
	"fmt"

	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// PrivilegeDocument translates the privilege section of one SandboxPolicy into
// the privilege gadget's own policy document. name qualifies rule names in
// events. Actor, pathClass and except are not supported by the gadget yet and
// are rejected. An explicit empty origin and a missing one both give no origin.
//
// Several policies on one container merge per the shared merge contract
// (pkg/ebpf/gadgets/common/merge/CONTRACT.md). It differs from the CRD design
// text (sandbox-policy-crd.md, "Multiple policies matching one pod merge"): an
// audit deny rule never weakens another policy's enforce default deny.
func PrivilegeDocument(name string, mode api.PolicyMode, section api.PrivilegeSection) (privpolicy.Document, error) {
	doc := privpolicy.Document{Name: name, Version: 1, Policy: privpolicy.Policy{Mode: string(mode), Privilege: privpolicy.Section{Default: string(section.Default)}}}
	for _, r := range section.Rules {
		t := r.Target
		if r.Actor != nil || len(t.PathClass) > 0 {
			return doc, fmt.Errorf("rule %q: actor and pathClass targets are unsupported in the privilege section", r.Name)
		}
		if len(r.Except) > 0 {
			return doc, fmt.Errorf("rule %q: exceptions are unsupported in the privilege section", r.Name)
		}
		origin := ""
		if r.Origin != nil {
			origin = *r.Origin
		}
		doc.Policy.Privilege.Rules = append(doc.Policy.Privilege.Rules, privpolicy.Rule{
			Name: r.Name, Action: string(r.Action), Mode: string(r.Mode), Origin: origin,
			Target: privpolicy.Target{Syscall: t.Syscall, Flags: t.Flags, Capability: t.Capability, MountFSType: t.MountFSType},
		})
	}
	return doc, doc.Validate()
}
