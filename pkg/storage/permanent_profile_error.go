package storage

import "errors"

// PermanentProfileError marks an explicit storage rejection that retrying the
// same profile cannot fix. It does not mean the profile completed learning or
// exceeded its size limit. Unknown and transient errors should not opt in.
type PermanentProfileError interface {
	error
	Permanent() bool
}

// IsPermanentProfileError recognizes a permanent rejection through error wraps.
func IsPermanentProfileError(err error) bool {
	permanent, ok := errors.AsType[PermanentProfileError](err)
	return ok && permanent.Permanent()
}
