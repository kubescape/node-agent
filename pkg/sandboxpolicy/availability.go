package sandboxpolicy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// EnforcementUnavailableError means a policy section cannot be enforced on this
// node. Reason becomes the Ready condition reason in the node status.
type EnforcementUnavailableError struct {
	Section, Reason, Detail string
}

func (e *EnforcementUnavailableError) Error() string {
	return fmt.Sprintf("%s enforcement is unavailable on this node: %s", e.Section, e.Detail)
}

// SectionAvailability is implemented by a backend that knows whether a policy
// section (SectionPrivilege, SectionNetwork) can be enforced on this node.
type SectionAvailability interface {
	SectionUnavailable(section string) error
}

// sectionUnavailable returns why a section cannot be enforced, or nil. It is
// called with c.mu held.
func (c *Controller) sectionUnavailable(section string) error {
	if a, ok := c.backend.(SectionAvailability); ok {
		return a.SectionUnavailable(section)
	}
	return nil
}

// kernelRuntime runs Options.KernelRuntime for a loaded section, or returns
// nil. It is called with c.mu held.
func (c *Controller) kernelRuntime(section string) error {
	if c.options.KernelRuntime == nil {
		return nil
	}
	return c.options.KernelRuntime(section)
}

// hooksUnproven formats Options.HooksUnproven for the loaded sections:
// always and node are "section: hook (why), ..." lists joined by "; ", and
// nodeReason is <Section>HooksUnproven of the first section with a node
// entry. It is called with c.mu held.
func (c *Controller) hooksUnproven(sections []string) (always, node, nodeReason string) {
	if c.options.HooksUnproven == nil {
		return "", "", ""
	}
	format := func(section string, hooks map[string]string) string {
		names := make([]string, 0, len(hooks))
		for h := range hooks {
			names = append(names, h)
		}
		sort.Strings(names)
		for i, h := range names {
			names[i] = h + " (" + hooks[h] + ")"
		}
		return section + ": " + strings.Join(names, ", ")
	}
	var a, n []string
	for _, section := range sections {
		u := c.options.HooksUnproven(section)
		if len(u.Always) > 0 {
			a = append(a, format(section, u.Always))
		}
		if len(u.Node) > 0 {
			if nodeReason == "" {
				nodeReason = strings.ToUpper(section[:1]) + section[1:] + "HooksUnproven"
			}
			n = append(n, format(section, u.Node))
		}
	}
	return strings.Join(a, "; "), strings.Join(n, "; "), nodeReason
}

// BindingRefusedError is a binding that a section refuses for a cause of
// the container, not of the node (Reason names it, for example IoUringHeld).
// The binding is retried at the next refresh.
type BindingRefusedError struct {
	Section, Reason, Detail string
}

func (e *BindingRefusedError) Error() string {
	return fmt.Sprintf("%s binding refused: %s", e.Section, e.Detail)
}

// unavailableReason returns the reason and message of a node-wide cause
// (EnforcementUnavailableError) or of a refused binding (BindingRefusedError).
func unavailableReason(err error) (string, string, bool) {
	var u *EnforcementUnavailableError
	if errors.As(err, &u) {
		return u.Reason, u.Error(), true
	}
	var r *BindingRefusedError
	if errors.As(err, &r) {
		return r.Reason, r.Error(), true
	}
	return "", "", false
}
