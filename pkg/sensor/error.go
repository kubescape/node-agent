package sensor

import (
	"fmt"
)

// SenseError is informative sensor error
type SenseError struct {
	err      error  // The wrapped error
	Massage  string `json:"error"` // The error message
	Function string `json:"-"`     // The function where the error occurred
	Code     int    `json:"-"`     // The error code (for HTTP response codes)
}

// Error implements error interface
func (err *SenseError) Error() string {
	internalErr := ""
	if err.err != nil {
		internalErr = err.err.Error()
	}
	return fmt.Sprintf("%s %s", err.Massage, internalErr)
}

// Unwrap implementation for errors.Unwrap
func (err *SenseError) Unwrap() error { return err.err }

// Is implementation for errors.Is
func (err *SenseError) Is(target error) bool {
	sensErrTarget, ok := target.(*SenseError)
	if !ok {
		return false
	}
	return err.Massage == sensErrTarget.Massage && err.Code == sensErrTarget.Code
}
