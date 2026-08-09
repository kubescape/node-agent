package utils

import (
	"strings"
	"testing"
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
//   2. tracer layer — the tracer delivered only a *basename*, because the
//      open event's `fpath` field was empty and DatasourceEvent.GetPath /
//      GetFullPath fall back to `fname`. Nothing in this repo can reconstruct
//      the directory: the information never arrived.
//
// Telling them apart matters because NormalizePath actively destroys the
// evidence for case (2) — see TestNormalizePath_FabricatesRootFromBasename.

// pathDefectLayer is the layer a malformed tracer path is attributable to.
type pathDefectLayer int

const (
	// layerNone: a well-formed absolute path, nothing to attribute.
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
// that is indistinguishable from a genuine root-level file.
func classifyRawTracerPath(raw string) pathDefectLayer {
	// Nothing delivered at all, or runc's "." / "/." placeholder from #721.
	if raw == "" || raw == "." || raw == "/." {
		return layerTracer
	}
	// No separator anywhere: this is a basename, so `fpath` was empty and the
	// `fname` fallback supplied it. The directory is simply not in the event.
	if !strings.Contains(strings.TrimPrefix(raw, "/"), "/") && !strings.HasPrefix(raw, "/") {
		return layerTracer
	}
	// Shaped like a /proc/<pid>/... path that lost its root. Structurally
	// intact, so recovering it is normalization's job.
	if headlessProcRegex.MatchString(raw) || isHeadlessProcShaped(raw) {
		return layerNormalization
	}
	return layerNone
}

// isHeadlessProcShaped reports whether raw looks like /proc/<pid>/<something>
// with the /proc root stripped, independent of the headlessProcRegex
// allowlist. This is deliberately broader than headlessProcRegex: it is used
// to detect entries the allowlist does *not* yet cover, which is exactly the
// drift #872 had to patch after #721.
func isHeadlessProcShaped(raw string) bool {
	if !strings.HasPrefix(raw, "/") {
		return false
	}
	rest := raw[1:]
	slash := strings.Index(rest, "/")
	if slash <= 0 {
		return false
	}
	first := rest[:slash]
	for _, r := range first {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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

// TestNormalizePath_NumericDirIsNotAPID guards the false-positive direction:
// a real top-level numeric directory must never be mistaken for a PID and
// shoved under /proc. This is the constraint that keeps the allowlist explicit.
func TestNormalizePath_NumericDirIsNotAPID(t *testing.T) {
	for _, p := range []string{"/2024/logs", "/1/data/dump.rdb", "/42/config.yaml"} {
		if got := NormalizePath(p); got != p {
			t.Errorf("NormalizePath(%q) = %q, want it untouched — a genuine numeric directory was misread as a PID", p, got)
		}
	}
}

// TestNormalizePath_FabricatesRootFromBasename pins the mechanism behind the
// scrambled entries reported in #874 (`/ocal.sh`, `/cal.sh`, `/cksource)`
// appearing in a redis workload's opens, where the real liveness probe is
// named `...-local.sh`).
//
// When `fpath` is empty, DatasourceEvent.GetPath falls back to the `fname`
// field, which carries a basename only. NormalizePath then prepends "/",
// promoting that basename to a root-level absolute path that never existed on
// disk. If the basename was itself truncated upstream, the result is a
// plausible-looking but entirely fictional path — and it is written into the
// profile, where it later drives false positives in opens.
//
// This is asserted as current behavior, not as desired behavior: the fix
// belongs at the fallback in datasource_event.go, not inside NormalizePath.
func TestNormalizePath_FabricatesRootFromBasename(t *testing.T) {
	basenames := []string{"local.sh", "ocal.sh", "cal.sh", "cksource)"}

	for _, name := range basenames {
		if layer := classifyRawTracerPath(name); layer != layerTracer {
			t.Errorf("classifyRawTracerPath(%q) = %v, want tracer — a bare basename means fpath was empty", name, layer)
		}

		got := NormalizePath(name)
		if got != "/"+name {
			t.Errorf("NormalizePath(%q) = %q, want %q", name, got, "/"+name)
		}

		// The damage: after normalization the fabricated path is
		// indistinguishable from a genuine root-level file, so attribution is
		// no longer possible. Anything classifying paths must run on the raw
		// field, upstream of this call.
		if layer := classifyRawTracerPath(got); layer != layerNone {
			t.Errorf("classifyRawTracerPath(%q) = %v, want none — the fabricated path should look clean, which is the whole problem", got, layer)
		}
	}
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

// TestOpenExecPathAsymmetry records why #874 shows up in `opens` but not in
// `execs`, which is the part that looked surprising when it was reported.
//
// Exec paths come from the `exepath` field, which the kernel always fills with
// a fully-resolved absolute path; DatasourceEvent.GetExePath has no fallback,
// so NormalizePath is a no-op on it. Open paths come from `fpath` with an
// `fname` fallback, and `fname` is a basename — so only the open path can ever
// hand NormalizePath a string with no directory in it.
//
// The asymmetry is therefore in the field-fallback contract, not in
// NormalizePath: given the same shapes, NormalizePath treats both identically.
func TestOpenExecPathAsymmetry(t *testing.T) {
	// exepath shape: always absolute, so normalization cannot fabricate.
	execShapes := []string{"/usr/local/bin/redis-server", "/bin/sh", "/usr/bin/runc"}
	for _, p := range execShapes {
		if got := NormalizePath(p); got != p {
			t.Errorf("NormalizePath(%q) = %q, want it untouched", p, got)
		}
		if layer := classifyRawTracerPath(p); layer != layerNone {
			t.Errorf("classifyRawTracerPath(%q) = %v, want none", p, layer)
		}
	}

	// fname shape: a basename reaches NormalizePath only on the open path,
	// and only there does it get a fabricated root.
	openFallbackShapes := []string{"redis-server", "sh", "runc"}
	for _, p := range openFallbackShapes {
		if got := NormalizePath(p); got != "/"+p {
			t.Errorf("NormalizePath(%q) = %q, want %q", p, got, "/"+p)
		}
		if layer := classifyRawTracerPath(p); layer != layerTracer {
			t.Errorf("classifyRawTracerPath(%q) = %v, want tracer", p, layer)
		}
	}
}
