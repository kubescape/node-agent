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

// PrivilegeAvailability is implemented by a backend that knows whether the
// privilege section can be enforced on this node.
type PrivilegeAvailability interface {
	PrivilegeUnavailable() error
}

// privilegeUnavailable returns why the privilege section cannot be enforced,
// or nil. It is called with c.mu held.
func (c *Controller) privilegeUnavailable() error {
	if a, ok := c.backend.(PrivilegeAvailability); ok {
		return a.PrivilegeUnavailable()
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
