package validator

import (
	"testing"
)

func TestValidator(t *testing.T) {
	minKernelVersion = "0.1"
	err := checkKernelVersion()
	if err != nil {
		t.Fatalf("checkKernelVersion failed withh error %v", err)
	}
}
