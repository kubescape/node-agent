package sandboxpolicy

import (
	"errors"
	"fmt"
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

func unavailableReason(err error) (string, string, bool) {
	var u *EnforcementUnavailableError
	if !errors.As(err, &u) {
		return "", "", false
	}
	return u.Reason, u.Error(), true
}
