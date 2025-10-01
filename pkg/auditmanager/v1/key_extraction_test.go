package v1

import (
	"testing"

	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractKeysFromMessageSequence(t *testing.T) {
	// Create a mock audit manager for testing
	am := &AuditManagerV1{}

	tests := []struct {
		name        string
		rawMessages []string
		expectedKey string
		description string
	}{
		{
			name: "password_file_access_key",
			rawMessages: []string{
				`audit(1759147830.285:2599216): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7f885070f320 a2=80000 a3=0 items=1 ppid=259844 pid=259958 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm="bash" exe="/usr/bin/bash" subj=unconfined key="password_file_access"`,
				`audit(1759147830.285:2599216): cwd="/root"`,
				`audit(1759147830.285:2599216): item=0 name="/etc/passwd" inode=917754 dev=00:150 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`,
			},
			expectedKey: "password_file_access",
			description: "Should extract key from SYSCALL message with quoted key",
		},
		{
			name: "null_key",
			rawMessages: []string{
				`audit(1759147877.609:2599305): arch=c000003e syscall=54 success=yes exit=0 a0=4 a1=0 a2=40 a3=55f29df2db70 items=0 ppid=1820 pid=260121 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 fsgid=0 tty=(none) ses=4294967295 comm="iptables" exe="/usr/sbin/xtables-legacy-multi" subj=unconfined key=(null)`,
			},
			expectedKey: "",
			description: "Should return empty string for null key",
		},
		{
			name: "unquoted_key",
			rawMessages: []string{
				`audit(1759147877.609:2599305): arch=c000003e syscall=54 success=yes exit=0 a0=4 a1=0 a2=40 a3=55f29df2db70 items=0 ppid=1820 pid=260121 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="iptables" exe="/usr/sbin/xtables-legacy-multi" subj=unconfined key=some_key`,
			},
			expectedKey: "some_key",
			description: "Should extract unquoted key",
		},
		{
			name: "no_key_field",
			rawMessages: []string{
				`audit(1759147877.609:2599305): arch=c000003e syscall=54 success=yes exit=0 a0=4 a1=0 a2=40 a3=55f29df2db70 items=0 ppid=1820 pid=260121 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="iptables" exe="/usr/sbin/xtables-legacy-multi" subj=unconfined`,
			},
			expectedKey: "",
			description: "Should return empty string when no key field exists",
		},
		{
			name: "multiple_messages_key_in_path",
			rawMessages: []string{
				`audit(1759147830.285:2599216): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7f885070f320 a2=80000 a3=0 items=1 ppid=259844 pid=259958 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm="bash" exe="/usr/bin/bash" subj=unconfined`,
				`audit(1759147830.285:2599216): item=0 name="/etc/passwd" inode=917754 dev=00:150 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0 key="file_watch_key"`,
			},
			expectedKey: "file_watch_key",
			description: "Should extract key from PATH message when SYSCALL has no key",
		},
		{
			name: "xattr_operations_key",
			rawMessages: []string{
				`audit(1759147830.285:2599216): arch=c000003e syscall=190 success=yes exit=0 a0=7fffffff a1=7f885070f320 a2=15 a3=0 items=0 ppid=259844 pid=259958 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm="setfattr" exe="/usr/bin/setfattr" subj=unconfined key="xattr_operations"`,
			},
			expectedKey: "xattr_operations",
			description: "Should extract key from xattr syscall message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse raw messages into AuditMessage structs
			var msgs []*auparse.AuditMessage
			for i, rawMsg := range tt.rawMessages {
				var msgType auparse.AuditMessageType
				if i == 0 {
					msgType = 1300 // SYSCALL for first message
				} else {
					msgType = 1302 // PATH for subsequent messages
				}
				msg, err := auparse.Parse(msgType, rawMsg)
				require.NoError(t, err, "Failed to parse raw message: %s", rawMsg)
				msgs = append(msgs, msg)
			}

			// Test the key extraction
			result := am.extractKeysFromMessageSequence(msgs)

			assert.Equal(t, tt.expectedKey, result, tt.description)
		})
	}
}

// TestExtractKeyFromRawMessage is deprecated - we now use the proper Tags() method
// This test is kept for reference but should not be used

// Benchmark test to ensure performance is acceptable
func BenchmarkExtractKeysFromMessageSequence(b *testing.B) {
	am := &AuditManagerV1{}

	// Create test messages
	rawMessages := []string{
		`audit(1759147830.285:2599216): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7f885070f320 a2=80000 a3=0 items=1 ppid=259844 pid=259958 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm="bash" exe="/usr/bin/bash" subj=unconfined key="password_file_access"`,
		`audit(1759147830.285:2599216): cwd="/root"`,
		`audit(1759147830.285:2599216): item=0 name="/etc/passwd" inode=917754 dev=00:150 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`,
	}

	var msgs []*auparse.AuditMessage
	for _, rawMsg := range rawMessages {
		msg, _ := auparse.Parse(1300, rawMsg)
		msgs = append(msgs, msg)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		am.extractKeysFromMessageSequence(msgs)
	}
}

// Test to verify the bug we're trying to fix
func TestKeyExtractionBug(t *testing.T) {
	am := &AuditManagerV1{}

	// This is the exact raw message from the logs that was failing
	rawMessage := `audit(1759147830.285:2599216): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7f885070f320 a2=80000 a3=0 items=1 ppid=259844 pid=259958 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm="bash" exe="/usr/bin/bash" subj=unconfined key="password_file_access"`

	// Parse the message
	msg, err := auparse.Parse(1300, rawMessage)
	require.NoError(t, err)

	// Test that Data() method doesn't extract the key (the bug)
	data, err := msg.Data()
	require.NoError(t, err)

	// This should fail - the bug we're trying to fix
	_, exists := data["key"]
	assert.False(t, exists, "msg.Data() should NOT contain the key field - this is the bug we're fixing")

	// The Tags() method is the proper way to extract keys

	// Test that Tags() method works (this is the proper way!)
	tags, err := msg.Tags()
	require.NoError(t, err)
	t.Logf("Tags from msg.Tags(): %v", tags)

	if len(tags) > 0 {
		assert.Equal(t, "password_file_access", tags[0], "Tags() method should extract the key")
	}

	// Test that our sequence extraction works with the fallback
	msgs := []*auparse.AuditMessage{msg}
	result := am.extractKeysFromMessageSequence(msgs)
	assert.Equal(t, "password_file_access", result, "Sequence extraction with fallback should work")
}

// Test to understand how Tags() method works
func TestTagsMethod(t *testing.T) {
	tests := []struct {
		name        string
		rawMessage  string
		expectedKey string
		description string
	}{
		{
			name:        "simple_key",
			rawMessage:  `audit(1759147830.285:2599216): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7f885070f320 a2=80000 a3=0 items=1 ppid=259844 pid=259958 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm="bash" exe="/usr/bin/bash" subj=unconfined key="password_file_access"`,
			expectedKey: "password_file_access",
			description: "Should extract simple quoted key",
		},
		{
			name:        "null_key",
			rawMessage:  `audit(1759147877.609:2599305): arch=c000003e syscall=54 success=yes exit=0 a0=4 a1=0 a2=40 a3=55f29df2db70 items=0 ppid=1820 pid=260121 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="iptables" exe="/usr/sbin/xtables-legacy-multi" subj=unconfined key=(null)`,
			expectedKey: "",
			description: "Should handle null key",
		},
		{
			name:        "no_key",
			rawMessage:  `audit(1759147877.609:2599305): arch=c000003e syscall=54 success=yes exit=0 a0=4 a1=0 a2=40 a3=55f29df2db70 items=0 ppid=1820 pid=260121 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="iptables" exe="/usr/sbin/xtables-legacy-multi" subj=unconfined`,
			expectedKey: "",
			description: "Should handle no key field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := auparse.Parse(1300, tt.rawMessage)
			require.NoError(t, err)

			// Call Data() first to trigger parsing
			_, err = msg.Data()
			require.NoError(t, err)

			// Now check Tags()
			tags, err := msg.Tags()
			require.NoError(t, err)

			t.Logf("Raw message: %s", tt.rawMessage)
			t.Logf("Tags: %v", tags)

			if tt.expectedKey == "" {
				assert.Empty(t, tags, tt.description)
			} else {
				require.NotEmpty(t, tags, "Should have at least one tag")
				assert.Equal(t, tt.expectedKey, tags[0], tt.description)
			}
		})
	}
}
