package tracers

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
	"github.com/stretchr/testify/assert"
)

// TestDecodeSyscallsSkipsUnrecognizedNumbers verifies that syscall numbers this build
// cannot resolve to a name are dropped rather than recorded under a placeholder name.
// A placeholder propagates into the application profile and from there into generated
// seccomp profiles, where it is not a valid syscall name.
func TestDecodeSyscallsSkipsUnrecognizedNumbers(t *testing.T) {
	// Find a syscall number that this build cannot resolve, to stand in for a
	// number coming from a newer kernel than the one this binary knows about.
	unknownNumber := -1
	for i := len(make([]byte, 512)) - 1; i >= 0; i-- {
		if _, exist := syscalls.GetSyscallNameByNumber(i); !exist {
			unknownNumber = i
			break
		}
	}
	if unknownNumber == -1 {
		t.Skip("every syscall number in range is resolvable in this build")
	}

	// Pick a known syscall number so the test also proves valid entries survive.
	knownNumber, knownName := -1, ""
	for i := 0; i < unknownNumber; i++ {
		if name, exist := syscalls.GetSyscallNameByNumber(i); exist {
			knownNumber, knownName = i, name
			break
		}
	}
	if knownNumber == -1 {
		t.Skip("no resolvable syscall number available in this build")
	}

	buffer := make([]byte, unknownNumber+1)
	buffer[knownNumber] = 1
	buffer[unknownNumber] = 1

	got := decodeSyscalls(buffer)

	assert.Contains(t, got, knownName, "resolvable syscalls must still be recorded")
	assert.NotContains(t, got, "unknown", "unresolvable syscall numbers must not be recorded as a placeholder name")
	assert.Len(t, got, 1, "only the resolvable syscall should be returned")
}
