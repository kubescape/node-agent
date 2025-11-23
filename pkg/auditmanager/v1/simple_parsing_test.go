package v1

import (
	"fmt"
	"testing"

	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSimpleAuditMessageParsing tests parsing of raw audit messages without the full audit manager
func TestSimpleAuditMessageParsing(t *testing.T) {
	// Test cases with different raw audit messages
	testCases := []struct {
		name            string
		rawMessage      string
		expectedSuccess bool
		expectedSyscall string
		expectedKeys    []string
		expectedAUID    uint32
		expectedUID     uint32
		expectedEUID    uint32
		expectedExit    string
	}{
		{
			name:            "Successful sethostname syscall",
			rawMessage:      "audit(1759225399.402:2608888): arch=c000003e syscall=170 success=yes exit=0 a0=560387cbd2a0 a1=14 a2=14 a3=fffffffffffff000 items=0 ppid=280777 pid=280786 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm=\"hostname\" exe=\"/usr/bin/hostname\" subj=unconfined key=\"hostname-changes\"",
			expectedSuccess: true,
			expectedSyscall: "sethostname",
			expectedKeys:    []string{"hostname-changes"},
			expectedAUID:    0,
			expectedUID:     0,
			expectedEUID:    0,
			expectedExit:    "0",
		},
		{
			name:            "Failed sethostname syscall",
			rawMessage:      "audit(1759226300.525:2609261): arch=c000003e syscall=170 success=no exit=-1 a0=56261c2622a0 a1=14 a2=14 a3=fffffffffffff000 items=0 ppid=281500 pid=281527 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=4294967295 comm=\"hostname\" exe=\"/usr/bin/hostname\" subj=unconfined key=\"hostname-changes\"",
			expectedSuccess: false,
			expectedSyscall: "sethostname",
			expectedKeys:    []string{"hostname-changes"},
			expectedAUID:    1000,
			expectedUID:     1000,
			expectedEUID:    1000,
			expectedExit:    "EPERM",
		},
		{
			name:            "File access event",
			rawMessage:      "audit(1759226300.525:2609262): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff12345678 a2=0 items=1 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=12345 comm=\"cat\" exe=\"/bin/cat\" subj=unconfined key=\"file-access\"",
			expectedSuccess: true,
			expectedSyscall: "openat",
			expectedKeys:    []string{"file-access"},
			expectedAUID:    1000,
			expectedUID:     1000,
			expectedEUID:    1000,
			expectedExit:    "3",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse the raw message - need to specify message type
			msg, err := auparse.Parse(auparse.AUDIT_SYSCALL, tc.rawMessage)
			require.NoError(t, err, "Failed to parse raw audit message")

			// Extract data from the message
			data, err := msg.Data()
			require.NoError(t, err, "Failed to extract data from audit message")

			// Test the key extraction logic
			keys := extractKeysFromMsg(msg)
			assert.Equal(t, tc.expectedKeys, keys, "Keys should match")

			// Test the success field parsing
			_, ok := data["result"]
			if !ok {
				assert.True(t, ok, "result field should be present in audit message data")
			}
			success := parseSuccessField(data)
			assert.Equal(t, tc.expectedSuccess, success, "Success field should match")

			// Test the syscall field parsing
			syscall := parseSyscallField(data)
			assert.Equal(t, tc.expectedSyscall, syscall, "Syscall field should match")

			// Test the AUID parsing
			auid := parseUIDField(data, "auid")
			assert.Equal(t, tc.expectedAUID, auid, "AUID should match")

			// Test the UID parsing
			uid := parseUIDField(data, "uid")
			assert.Equal(t, tc.expectedUID, uid, "UID should match")

			// Test the EUID parsing
			euid := parseUIDField(data, "euid")
			assert.Equal(t, tc.expectedEUID, euid, "EUID should match")

			// Test the exit code parsing
			exit := parseExitField(data)
			assert.Equal(t, tc.expectedExit, exit, "Exit code should match")

			// Print the parsed data for debugging
			t.Logf("Parsed data: Success=%v, Syscall=%s, AUID=%d, EUID=%d, Exit=%s, Keys=%v",
				success, syscall, auid, euid, exit, keys)

			// Print the raw data for debugging
			t.Logf("Raw data: %+v", data)
		})
	}
}

// Helper functions to test the parsing logic

func extractKeysFromMsg(msg *auparse.AuditMessage) []string {
	tags, err := msg.Tags()
	if err != nil {
		return []string{}
	}
	return tags
}

func parseSuccessField(data map[string]string) bool {

	if resultStr, exists := data["result"]; exists {
		return resultStr == "success"
	}
	return true // Default to success if not specified
}

func parseSyscallField(data map[string]string) string {
	if syscall, exists := data["syscall"]; exists {
		return syscall
	}
	return ""
}

func parseUIDField(data map[string]string, field string) uint32 {
	if uidStr, exists := data[field]; exists {
		// Parse as uint32
		var uid uint32
		if _, err := fmt.Sscanf(uidStr, "%d", &uid); err == nil {
			return uid
		}
	}
	return 0
}

func parseExitField(data map[string]string) string {
	if exitStr, exists := data["exit"]; exists {
		return exitStr
	}
	return ""
}
