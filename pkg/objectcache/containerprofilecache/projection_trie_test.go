package containerprofilecache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrie_PrefixMatch(t *testing.T) {
	tr := newTrie([]string{"/bin/", "/usr/"})

	assert.True(t, tr.HasMatch("/bin/sh"), "expected /bin/sh to match prefix /bin/")
	assert.True(t, tr.HasMatch("/usr/local/bin/curl"), "expected /usr/local/bin/curl to match prefix /usr/")
	assert.False(t, tr.HasMatch("/etc/passwd"), "expected /etc/passwd not to match any prefix")
	assert.False(t, tr.HasMatch("/bi"), "expected /bi (shorter than pattern) not to match")
}

func TestTrie_EmptyPatternMatchesAll(t *testing.T) {
	tr := newTrie([]string{""})

	assert.True(t, tr.HasMatch("anything"), "empty pattern should match any string")
	assert.True(t, tr.HasMatch(""), "empty pattern should match empty string")
	assert.True(t, tr.HasMatch("/etc/passwd"), "empty pattern should match /etc/passwd")
}

func TestTrie_SuffixMatch(t *testing.T) {
	tr := newSuffixTrie([]string{".log"})

	assert.True(t, tr.HasMatchSuffix("/var/log/app.log"), "expected .log suffix match")
	assert.True(t, tr.HasMatchSuffix("app.log"), "expected bare .log suffix match")
	assert.False(t, tr.HasMatchSuffix("/etc/passwd"), "expected no suffix match for /etc/passwd")
	assert.False(t, tr.HasMatchSuffix("/var/log"), "expected /var/log not to match .log suffix")
}

func TestTrie_SuffixMatch_MultipleSuffixes(t *testing.T) {
	tr := newSuffixTrie([]string{".log", ".conf"})

	assert.True(t, tr.HasMatchSuffix("/etc/app.conf"), "expected .conf suffix match")
	assert.True(t, tr.HasMatchSuffix("/var/log/app.log"), "expected .log suffix match")
	assert.False(t, tr.HasMatchSuffix("/etc/passwd"), "expected no match for /etc/passwd")
}

func TestContainsMatch(t *testing.T) {
	assert.True(t, containsMatch([]string{"http"}, "is_http_request"), "http should be a substring of is_http_request")
	assert.True(t, containsMatch([]string{"xyz", "http"}, "is_http_request"), "should match when any pattern is found")
	assert.False(t, containsMatch([]string{"xyz"}, "hello"), "xyz is not a substring of hello")
	assert.False(t, containsMatch([]string{}, "hello"), "empty patterns should not match")
	assert.False(t, containsMatch([]string{"abc"}, ""), "no pattern should match empty string unless empty pattern")
}

func TestTrie_PrefixMatch_ExactString(t *testing.T) {
	// A pattern that exactly equals the query string should also match (prefix of itself).
	tr := newTrie([]string{"/bin/sh"})

	assert.True(t, tr.HasMatch("/bin/sh"), "pattern equal to query should match")
	// /bin/sh IS a prefix of /bin/sh/extra, so this should also match.
	assert.True(t, tr.HasMatch("/bin/sh/extra"), "/bin/sh is a prefix of /bin/sh/extra, so it should match")

	// A string shorter than the pattern should not match.
	tr2 := newTrie([]string{"/bin/"})
	assert.False(t, tr2.HasMatch("/bi"), "shorter string with no terminal should not match")
}

func TestTrie_MultiplePatterns(t *testing.T) {
	tr := newTrie([]string{"/bin/", "/etc/", "/usr/"})

	assert.True(t, tr.HasMatch("/bin/bash"))
	assert.True(t, tr.HasMatch("/etc/passwd"))
	assert.True(t, tr.HasMatch("/usr/bin/python"))
	assert.False(t, tr.HasMatch("/var/log/syslog"))
	assert.False(t, tr.HasMatch("/proc/1/maps"))
}

func TestTrie_UnicodePatterns(t *testing.T) {
	// DynamicIdentifier is U+22EF "⋯". Verify the trie handles multi-byte runes correctly.
	pattern := "/data/⋯/config"
	tr := newTrie([]string{pattern})

	assert.True(t, tr.HasMatch(pattern), "exact unicode pattern should match itself as prefix")
	assert.True(t, tr.HasMatch(pattern+"/extra"), "pattern should match longer strings with unicode")
	assert.False(t, tr.HasMatch("/data/x/config"), "different segment should not match")
}
