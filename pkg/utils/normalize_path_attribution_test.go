package utils

import (
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/stretchr/testify/require"
)

// This file is the regression net for #874 ("catch when /proc prefixes go
// missing and assert cause"), the follow-up to #721 and to the allowlist
// widening in #872.
//
// The point is not only to catch a missing /proc prefix, but to say *which
// layer* dropped it. Two very different defects reach the profile looking
// alike once they are written out as an `opens` stanza:
//
//   1. normalization layer — the tracer delivered a structurally intact
//      /proc/<pid>/<entry> path that merely lost its /proc root. The original
//      is reconstructable from the string alone, so a miss here is a gap in
//      headlessProcRegex (node-agent's fault, fixable in this repo).
//
//   2. tracer layer — the open event's `fpath` field was empty, so
//      DatasourceEvent.GetPath / GetFullPath fell back to `fname`, which
//      carries a basename. Nothing in this repo can reconstruct the directory:
//      the information never arrived.
//
// Telling them apart matters because NormalizePath actively destroys the
// evidence for case (2) — see TestOpenPathFabricatesRootFromBasename.

// pathDefectLayer is the layer a malformed tracer path is attributable to.
type pathDefectLayer int

const (
	// layerNone: a well-formed path, nothing to attribute.
	layerNone pathDefectLayer = iota
	// layerNormalization: recoverable in this repo by re-rooting under /proc.
	layerNormalization
	// layerTracer: unrecoverable here — the full path never reached us.
	layerTracer
)

func (l pathDefectLayer) String() string {
	switch l {
	case layerNormalization:
		return "normalization"
	case layerTracer:
		return "tracer"
	default:
		return "none"
	}
}

// classifyRawTracerPath attributes a *raw* tracer path — the value read from
// the `fpath`/`fname`/`exepath` field, before NormalizePath runs — to the layer
// responsible for any defect in it.
//
// It must be fed the raw field value. Running it on NormalizePath's output is
// meaningless, because NormalizePath rewrites a bare basename into something
// indistinguishable from a genuine root-level file.
func classifyRawTracerPath(raw string) pathDefectLayer {
	// Nothing delivered at all, or runc's "." / "/." placeholder from #721.
	if raw == "" || raw == "." || raw == "/." {
		return layerTracer
	}
	// No separator anywhere: this is a basename, so `fpath` was empty and the
	// `fname` fallback supplied it. The directory is simply not in the event.
	if !strings.Contains(raw, "/") {
		return layerTracer
	}
	// Shaped like a /proc/<pid>/<entry> path that lost its root, with <entry>
	// a name /proc/<pid> actually has. Structurally intact, so recovering it
	// is normalization's job.
	if headlessProcRegex.MatchString(raw) || isHeadlessProcShaped(raw) {
		return layerNormalization
	}
	return layerNone
}

// isHeadlessProcShaped reports whether raw looks like /proc/<pid>/<entry> with
// the /proc root stripped.
//
// A leading numeric segment is necessary but NOT sufficient: /2024/logs and
// /1/data/dump.rdb are ordinary directories that happen to start with digits,
// and misreading them as PIDs is precisely the false positive the explicit
// allowlist in path.go exists to avoid. The second segment must therefore also
// be a name /proc/<pid> actually exposes.
//
// This is deliberately broader than headlessProcRegex on the entry axis: it
// recognises entries the allowlist does not yet cover, which is exactly the
// drift #872 had to patch by hand after #721.
func isHeadlessProcShaped(raw string) bool {
	if !strings.HasPrefix(raw, "/") {
		return false
	}
	rest := raw[1:]
	slash := strings.Index(rest, "/")
	if slash <= 0 {
		return false
	}
	for _, r := range rest[:slash] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return knownProcEntryNames[procEntryName(rest[slash+1:])]
}

// procEntryName returns the first path segment of a /proc/<pid> entry, so that
// "task/46/fd" and "ns/user" reduce to "task" and "ns".
func procEntryName(entry string) string {
	if i := strings.Index(entry, "/"); i >= 0 {
		return entry[:i]
	}
	return entry
}

// procEntriesReRooted are the /proc/<pid>/<entry> names headlessProcRegex
// currently covers. Every one of them must survive a round trip back under
// /proc. If someone narrows the regex, this fails.
var procEntriesReRooted = []string{
	"task/46/fd", "fd/3", "setgroups", "gid_map", "uid_map", "status",
	"stat", "cgroup", "mountinfo", "maps", "environ", "comm", "cmdline",
	"ns/user",
}

// procEntriesStillLeaking are /proc/<pid>/<entry> names that are *not* in the
// allowlist today, so they still reach the profile without their /proc root.
//
// They are pinned here on purpose. The allowlist in path.go is an explicit
// enumeration by design (a bare `^/\d+` catch-all would misread a genuine
// top-level numeric directory as a PID), and an enumeration drifts — that
// drift is what #721 regressed into and what #872 patched by hand. Pinning the
// uncovered set makes the gap visible in CI instead of in a customer's
// ContainerProfile, and forces anyone extending the regex to move the entry
// into procEntriesReRooted in the same commit.
var procEntriesStillLeaking = []string{
	"root", "exe", "cwd", "projid_map", "oom_score_adj", "attr/current",
	"limits", "loginuid", "net/dev", "sched", "mounts", "personality",
	"timerslack_ns", "statm", "wchan",
}

// knownProcEntryNames is the set of first segments from both coverage lists.
// Deriving it keeps one source of truth: adding an entry to either list above
// teaches the classifier about it at the same time.
var knownProcEntryNames = func() map[string]bool {
	m := make(map[string]bool, len(procEntriesReRooted)+len(procEntriesStillLeaking))
	for _, e := range procEntriesReRooted {
		m[procEntryName(e)] = true
	}
	for _, e := range procEntriesStillLeaking {
		m[procEntryName(e)] = true
	}
	return m
}()

// TestNormalizePath_ProcPrefixCoverage pins both sides of the allowlist: what
// is re-rooted today, and what still escapes. Either set changing is a signal.
func TestNormalizePath_ProcPrefixCoverage(t *testing.T) {
	t.Run("covered entries are re-rooted", func(t *testing.T) {
		for _, entry := range procEntriesReRooted {
			headless := "/1234/" + entry
			want := "/proc/1234/" + entry
			if got := NormalizePath(headless); got != want {
				t.Errorf("NormalizePath(%q) = %q, want %q — a /proc prefix that used to be restored is now being dropped",
					headless, got, want)
			}
		}
	})

	t.Run("uncovered entries still leak", func(t *testing.T) {
		for _, entry := range procEntriesStillLeaking {
			headless := "/1234/" + entry
			got := NormalizePath(headless)
			if got == "/proc/"+headless[1:] {
				t.Errorf("NormalizePath(%q) now re-roots to %q: the allowlist grew but %q was left in procEntriesStillLeaking — move it to procEntriesReRooted",
					headless, got, entry)
				continue
			}
			// Still leaking. Confirm it is a normalization-layer gap and not
			// something the tracer mangled, so the fix has a known address.
			if layer := classifyRawTracerPath(headless); layer != layerNormalization {
				t.Errorf("classifyRawTracerPath(%q) = %v, want normalization", headless, layer)
			}
		}
	})
}

// TestNormalizePath_NumericDirIsNotAPID guards the false-positive direction: a
// real top-level numeric directory must never be mistaken for a PID, neither by
// NormalizePath (which would shove it under /proc) nor by the classifier (which
// would blame the wrong layer and send someone editing the regex).
func TestNormalizePath_NumericDirIsNotAPID(t *testing.T) {
	for _, p := range []string{"/2024/logs", "/1/data/dump.rdb", "/42/config.yaml"} {
		if got := NormalizePath(p); got != p {
			t.Errorf("NormalizePath(%q) = %q, want it untouched — a genuine numeric directory was misread as a PID", p, got)
		}
		if layer := classifyRawTracerPath(p); layer != layerNone {
			t.Errorf("classifyRawTracerPath(%q) = %v, want none — a genuine numeric directory is not a normalization defect", p, layer)
		}
	}
}

// newOpenEvent builds a synthetic "open" datasource event.
//
// Both `fpath` and `fname` are always declared, in a fixed order, because the
// real open gadget always exposes both (see the expected-field list in
// pkg/containerwatcher/v2/tracers/open_test.go) and signals "no full path" with
// an *empty* fpath rather than an absent one — which is what GetFullPath tests
// for. Keeping the layout identical across every open event this file builds
// also matters mechanically: getFieldAccessor caches accessors in the
// package-global fieldCaches keyed by EventType, not by datasource, so two open
// datasources with different layouts would decode each other's data at the
// wrong offset.
func newOpenEvent(t *testing.T, fpath, fname string, fullPathTracing bool) *DatasourceEvent {
	t.Helper()

	ds, err := datasource.New(datasource.TypeSingle, "open")
	require.NoError(t, err)

	fpathAcc, err := ds.AddField("fpath", api.Kind_String)
	require.NoError(t, err)
	fnameAcc, err := ds.AddField("fname", api.Kind_String)
	require.NoError(t, err)

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	t.Cleanup(func() { ds.Release(data) })

	require.NoError(t, fpathAcc.PutString(data, fpath))
	require.NoError(t, fnameAcc.PutString(data, fname))

	return &DatasourceEvent{
		Data:            data,
		Datasource:      ds,
		EventType:       OpenEventType,
		FullPathTracing: fullPathTracing,
	}
}

// newExecPathEvent builds a synthetic "exec" datasource event carrying an
// exepath plus a comm basename. The comm field is what makes the asymmetry test
// meaningful: a basename is present in the event, and GetExePath must still not
// reach for it. Layout is fixed for the same fieldCaches reason as above.
func newExecPathEvent(t *testing.T, exepath, comm string) *DatasourceEvent {
	t.Helper()

	ds, err := datasource.New(datasource.TypeSingle, "exec-path")
	require.NoError(t, err)

	exepathAcc, err := ds.AddField("exepath", api.Kind_String)
	require.NoError(t, err)
	commAcc, err := ds.AddField("comm", api.Kind_String)
	require.NoError(t, err)

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	t.Cleanup(func() { ds.Release(data) })

	require.NoError(t, exepathAcc.PutString(data, exepath))
	require.NoError(t, commAcc.PutString(data, comm))

	return &DatasourceEvent{
		Data:       data,
		Datasource: ds,
		EventType:  ExecveEventType,
	}
}

// TestOpenPathFabricatesRootFromBasename pins the mechanism behind the
// scrambled entries reported in #874 (`/ocal.sh`, `/cal.sh`, `/cksource)`
// appearing in a redis workload's opens, where the real liveness probe is
// named `...-local.sh`).
//
// When `fpath` is empty, GetFullPath falls back to the `fname` field, which
// carries a basename only; with FullPathTracing off, GetPath reads `fname`
// directly. NormalizePath then prepends "/", promoting that basename to a
// root-level absolute path that never existed on disk. If the basename was
// itself truncated upstream, the result is a plausible-looking but entirely
// fictional path — and it is written into the profile, where it later drives
// false positives in opens.
//
// This asserts current behaviour, not desired behaviour: the fix belongs at the
// fallback in datasource_event.go, not inside NormalizePath.
func TestOpenPathFabricatesRootFromBasename(t *testing.T) {
	basenames := []string{"local.sh", "ocal.sh", "cal.sh", "cksource)"}

	for _, name := range basenames {
		t.Run(name, func(t *testing.T) {
			// The raw field value is attributable; that is the only point at
			// which attribution is still possible.
			require.Equal(t, layerTracer, classifyRawTracerPath(name),
				"a bare basename in fname means fpath was empty")

			// FullPathTracing on: GetFullPath falls back from empty fpath to fname.
			tracing := newOpenEvent(t, "", name, true)
			require.Equal(t, "/"+name, tracing.GetFullPath(),
				"empty fpath must fall back to fname, which NormalizePath then roots")
			require.Equal(t, "/"+name, tracing.GetPath())

			// FullPathTracing off: GetPath reads fname directly, same fabrication.
			noTracing := newOpenEvent(t, "", name, false)
			require.Equal(t, "/"+name, noTracing.GetPath(),
				"with FullPathTracing off the open path is always the fname basename")

			// The damage: the value handed downstream is indistinguishable from
			// a genuine root-level file, so attribution is no longer possible.
			// Anything classifying paths must run on the raw field, upstream.
			require.Equal(t, layerNone, classifyRawTracerPath(tracing.GetPath()),
				"the fabricated path looks clean, which is the whole problem")
		})
	}
}

// TestOpenPathUsesFpathWhenPresent is the control for the test above: when the
// tracer does deliver a full path, no fabrication happens and fname is ignored.
// Without this, the fallback assertions would pass even if GetFullPath had
// stopped reading fpath altogether.
func TestOpenPathUsesFpathWhenPresent(t *testing.T) {
	e := newOpenEvent(t, "/data/scripts/redis-local.sh", "redis-local.sh", true)
	require.Equal(t, "/data/scripts/redis-local.sh", e.GetFullPath())
	require.Equal(t, "/data/scripts/redis-local.sh", e.GetPath())
	require.Equal(t, layerNone, classifyRawTracerPath(e.GetPath()))
}

// TestOpenExecPathAsymmetry records why #874 shows up in `opens` but not in
// `execs`, which is the part that looked surprising when it was reported.
//
// The asymmetry is in the field-fallback contract, not in NormalizePath:
// GetPath/GetFullPath fall back to the `fname` basename, GetExePath has no
// fallback at all. So only the open path can ever hand NormalizePath a string
// with no directory in it.
func TestOpenExecPathAsymmetry(t *testing.T) {
	t.Run("open falls back to a basename and fabricates a root", func(t *testing.T) {
		e := newOpenEvent(t, "", "redis-server", true)
		require.Equal(t, "/redis-server", e.GetPath(),
			"open has an fname fallback, so a basename becomes a fabricated absolute path")
	})

	t.Run("exec has no basename fallback", func(t *testing.T) {
		// A basename IS present in the event as comm, and GetExePath must still
		// not reach for it: an empty exepath yields an empty path, never a
		// fabricated one. This is the property that keeps execs clean.
		e := newExecPathEvent(t, "", "redis-server")
		require.Equal(t, "", e.GetExePath(),
			"exec must not fall back to a basename the way open does")
	})

	t.Run("exec paths arrive absolute and pass through untouched", func(t *testing.T) {
		for _, p := range []string{"/usr/local/bin/redis-server", "/bin/sh", "/usr/bin/runc"} {
			e := newExecPathEvent(t, p, "redis-server")
			require.Equal(t, p, e.GetExePath())
			require.Equal(t, layerNone, classifyRawTracerPath(p))
		}
	})
}

// TestClassifyRawTracerPath_KnownSamples runs the paths actually observed in
// #721 and #874 through the classifier, so each reported symptom has a
// recorded, asserted cause.
func TestClassifyRawTracerPath_KnownSamples(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want pathDefectLayer
	}{
		{
			name: "#721 headless proc task path",
			raw:  "/46/task/46/fd",
			want: layerNormalization,
		},
		{
			name: "#721 runc dot path",
			raw:  ".",
			want: layerTracer,
		},
		{
			name: "#721 runc slash-dot path",
			raw:  "/.",
			want: layerTracer,
		},
		{
			name: "#721 empty path from runc:[2:INIT]",
			raw:  "",
			want: layerTracer,
		},
		{
			name: "#872 headless user-namespace setup entry",
			raw:  "/17/setgroups",
			want: layerNormalization,
		},
		{
			name: "#874 truncated redis liveness probe basename",
			raw:  "ocal.sh",
			want: layerTracer,
		},
		{
			name: "#874 truncated clocksource basename",
			raw:  "cksource)",
			want: layerTracer,
		},
		{
			name: "headless proc entry outside the allowlist",
			raw:  "/17/projid_map",
			want: layerNormalization,
		},
		{
			// A numeric leading segment alone must not imply a PID, or the
			// classifier would send someone to widen the regex and break
			// genuine numeric directories.
			name: "numeric log directory is not a PID",
			raw:  "/2024/logs",
			want: layerNone,
		},
		{
			name: "numeric data directory is not a PID",
			raw:  "/1/data/dump.rdb",
			want: layerNone,
		},
		{
			name: "numeric directory with a file is not a PID",
			raw:  "/42/config.yaml",
			want: layerNone,
		},
		{
			name: "well-formed absolute path",
			raw:  "/data/appendonlydir/appendonly.aof.1.base.rdb",
			want: layerNone,
		},
		{
			name: "well-formed proc path",
			raw:  "/proc/46/fd/3",
			want: layerNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyRawTracerPath(tt.raw); got != tt.want {
				t.Errorf("classifyRawTracerPath(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}
