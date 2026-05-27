package applicationprofile

import (
	"strconv"
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
)

// BenchmarkWasPathOpenedWithSuffix_AllMode exercises the pass-through
// (Opens.All == true) suffix path under three representative profile
// shapes:
//
//   - values_only:        50 concrete entries, no Patterns
//   - patterns_concrete:  50 concrete entries + 10 Patterns whose tail
//                         is literal (the typical /var/log/⋯/foo.log shape)
//   - patterns_wildcard:  50 concrete entries + 10 Patterns ending in a
//                         wildcard segment (the permissive-arm shape)
//
// Captures Matthias's upstream PR #811 contract numbers for the PR
// description.
func BenchmarkWasPathOpenedWithSuffix_AllMode(b *testing.B) {
	shapes := []struct {
		name     string
		values   int
		patterns []string
	}{
		{"values_only", 50, nil},
		{"patterns_concrete", 50, []string{
			"/var/log/⋯/access.log", "/var/log/⋯/error.log", "/opt/⋯/server.log",
			"/etc/⋯/audit.log", "/var/run/⋯/state.log", "/srv/⋯/app.log",
			"/var/cache/⋯/tmp.log", "/usr/share/⋯/data.log", "/home/⋯/user.log",
			"/proc/⋯/status.log",
		}},
		{"patterns_wildcard", 50, []string{
			"/var/log/pods/*", "/var/log/containers/*", "/etc/cron.d/*",
			"/opt/⋯", "/srv/*", "/var/run/*",
			"/usr/local/⋯", "/home/⋯", "/tmp/⋯", "/run/⋯",
		}},
	}
	for _, sh := range shapes {
		b.Run(sh.name, func(b *testing.B) {
			values := make(map[string]struct{}, sh.values)
			for i := 0; i < sh.values; i++ {
				values["/usr/lib/x86_64-linux-gnu/libcrypto.so."+strconv.Itoa(i)] = struct{}{}
			}
			pcp := &objectcache.ProjectedContainerProfile{
				Opens: objectcache.ProjectedField{
					All:      true,
					Values:   values,
					Patterns: sh.patterns,
				},
			}
			lib := &apLibrary{objectCache: &mockObjectCacheForPattern{pcp: pcp}}
			suffix := types.String(".log")
			cid := types.String("bench-cid")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = lib.wasPathOpenedWithSuffix(cid, suffix)
			}
		})
	}
}

// BenchmarkWasPathOpenedWithPrefix_AllMode mirrors the suffix bench
// for the prefix path.
func BenchmarkWasPathOpenedWithPrefix_AllMode(b *testing.B) {
	shapes := []struct {
		name     string
		values   int
		patterns []string
	}{
		{"values_only", 50, nil},
		{"patterns_concrete", 50, []string{
			"/var/log/⋯/access.log", "/var/log/⋯/error.log", "/opt/⋯/server.log",
			"/etc/⋯/audit.log", "/var/run/⋯/state.log",
		}},
		{"patterns_wildcard", 50, []string{
			"*/run", "*/log", "*/cache",
			"⋯", "*",
		}},
	}
	for _, sh := range shapes {
		b.Run(sh.name, func(b *testing.B) {
			values := make(map[string]struct{}, sh.values)
			for i := 0; i < sh.values; i++ {
				values["/usr/lib/x86_64-linux-gnu/libcrypto.so."+strconv.Itoa(i)] = struct{}{}
			}
			pcp := &objectcache.ProjectedContainerProfile{
				Opens: objectcache.ProjectedField{
					All:      true,
					Values:   values,
					Patterns: sh.patterns,
				},
			}
			lib := &apLibrary{objectCache: &mockObjectCacheForPattern{pcp: pcp}}
			prefix := types.String("/var/")
			cid := types.String("bench-cid")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = lib.wasPathOpenedWithPrefix(cid, prefix)
			}
		})
	}
}

// BenchmarkPatternConcreteSuffix isolates the helper to confirm zero
// allocation regardless of pattern shape.
func BenchmarkPatternConcreteSuffix(b *testing.B) {
	cases := []string{
		"/var/log/⋯/foo.log",
		"/var/log/pods/*",
		"/var/log/foo.log",
		"*",
		"/var/⋯/log/⋯/foo.log",
	}
	for _, c := range cases {
		b.Run(c, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = patternConcreteSuffix(c)
			}
		})
	}
}
