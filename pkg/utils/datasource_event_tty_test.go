package utils

import (
	"os"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/kubescape/go-logger"
	"github.com/stretchr/testify/require"
)

// ttyFields describes which tty-related fields a synthetic datasource exposes.
type ttyFields struct {
	tty      *int32
	ttyMajor *uint32
	ttyMinor *uint32
}

// newExecEvent builds a synthetic "exec" datasource containing only the tty
// fields that are non-nil in f, plus a filler "comm" field so the datasource is
// not degenerate. It returns a DatasourceEvent ready for the getters under test.
//
// The filler is decorative: the CEL "comm" field actually reads the datasource
// field "proc.comm", so GetComm() on this event returns "". Do not assert on it.
//
// Each call creates a fresh DataSource, which matters: the presence cache is
// keyed by datasource instance, so cases cannot poison each other.
func newExecEvent(t *testing.T, f ttyFields) *DatasourceEvent {
	t.Helper()

	ds, err := datasource.New(datasource.TypeSingle, "exec")
	require.NoError(t, err)

	commAcc, err := ds.AddField("comm", api.Kind_String)
	require.NoError(t, err)

	var ttyAcc, majorAcc, minorAcc datasource.FieldAccessor
	if f.tty != nil {
		ttyAcc, err = ds.AddField("tty", api.Kind_Int32)
		require.NoError(t, err)
	}
	if f.ttyMajor != nil {
		majorAcc, err = ds.AddField("tty_major", api.Kind_Uint32)
		require.NoError(t, err)
	}
	if f.ttyMinor != nil {
		minorAcc, err = ds.AddField("tty_minor", api.Kind_Uint32)
		require.NoError(t, err)
	}

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	t.Cleanup(func() { ds.Release(data) })

	require.NoError(t, commAcc.PutString(data, "bash"))
	if f.tty != nil {
		require.NoError(t, ttyAcc.PutInt32(data, *f.tty))
	}
	if f.ttyMajor != nil {
		require.NoError(t, majorAcc.PutUint32(data, *f.ttyMajor))
	}
	if f.ttyMinor != nil {
		require.NoError(t, minorAcc.PutUint32(data, *f.ttyMinor))
	}

	return &DatasourceEvent{
		Data:       data,
		Datasource: ds,
		EventType:  ExecveEventType,
	}
}

func i32(v int32) *int32   { return &v }
func u32(v uint32) *uint32 { return &v }

func TestDatasourceEventFieldPresent(t *testing.T) {
	// Phase-1 gadget shape: only "tty" is emitted.
	phase1 := newExecEvent(t, ttyFields{tty: i32(0)})
	require.True(t, phase1.FieldPresent("tty"))
	require.False(t, phase1.FieldPresent("tty_major"))
	require.False(t, phase1.FieldPresent("tty_minor"))

	// Repeat lookups must be stable (exercises the cached-miss path).
	require.False(t, phase1.FieldPresent("tty_major"))

	// Phase-2 gadget shape: all three emitted.
	phase2 := newExecEvent(t, ttyFields{tty: i32(0), ttyMajor: u32(136), ttyMinor: u32(0)})
	require.True(t, phase2.FieldPresent("tty"))
	require.True(t, phase2.FieldPresent("tty_major"))
	require.True(t, phase2.FieldPresent("tty_minor"))

	// A datasource with no tty fields at all.
	none := newExecEvent(t, ttyFields{})
	require.False(t, none.FieldPresent("tty"))
	require.False(t, none.FieldPresent("tty_major"))

	// Defensive: a nil datasource must not panic.
	empty := &DatasourceEvent{EventType: ExecveEventType}
	require.False(t, empty.FieldPresent("tty"))

	// Defensive: a nil receiver must not panic either.
	var nilEvent *DatasourceEvent
	require.False(t, nilEvent.FieldPresent("tty"))
}

func TestStructEventFieldPresent(t *testing.T) {
	set := &StructEvent{EventType: ExecveEventType, TTY: i32(3), TTYMajor: u32(136), TTYMinor: u32(3)}
	require.True(t, set.FieldPresent("tty"))
	require.True(t, set.FieldPresent("tty_major"))
	require.True(t, set.FieldPresent("tty_minor"))

	unset := &StructEvent{EventType: ExecveEventType}
	require.False(t, unset.FieldPresent("tty"))
	require.False(t, unset.FieldPresent("tty_major"))
	require.False(t, unset.FieldPresent("tty_minor"))

	// Names without a wired presence tester report false.
	require.False(t, set.FieldPresent("comm"))
}

func TestDatasourceEventTTYGetters(t *testing.T) {
	t.Run("phase1 with a terminal", func(t *testing.T) {
		// Gadget emits only the driver-local index. Index 3 proves a terminal.
		e := newExecEvent(t, ttyFields{tty: i32(3)})
		require.Equal(t, int32(3), e.GetTTY())
		require.True(t, e.GetHasTTY())
		// Device number is unavailable on this gadget.
		require.Equal(t, uint32(0), e.GetTTYMajor())
		require.Equal(t, uint32(0), e.GetTTYMinor())
	})

	t.Run("phase1 index zero reads as no terminal", func(t *testing.T) {
		// Knowingly wrong for pts/0; accepted phase-1 semantics.
		e := newExecEvent(t, ttyFields{tty: i32(0)})
		require.Equal(t, int32(0), e.GetTTY())
		require.False(t, e.GetHasTTY())
	})

	t.Run("phase2 pts0 is recognised", func(t *testing.T) {
		// The case phase 1 gets wrong: major 136 minor 0 is /dev/pts/0.
		e := newExecEvent(t, ttyFields{tty: i32(0), ttyMajor: u32(136), ttyMinor: u32(0)})
		require.Equal(t, uint32(136), e.GetTTYMajor())
		require.Equal(t, uint32(0), e.GetTTYMinor())
		require.True(t, e.GetHasTTY(), "major 136 is a pty, so a terminal exists")
	})

	t.Run("phase2 no terminal", func(t *testing.T) {
		e := newExecEvent(t, ttyFields{tty: i32(0), ttyMajor: u32(0), ttyMinor: u32(0)})
		require.False(t, e.GetHasTTY())
	})

	t.Run("phase2 major wins over index", func(t *testing.T) {
		// Proves the fallback order: tty_major is authoritative when present.
		e := newExecEvent(t, ttyFields{tty: i32(0), ttyMajor: u32(4), ttyMinor: u32(1)})
		require.True(t, e.GetHasTTY())
	})

	t.Run("phase2 major zero wins over nonzero index", func(t *testing.T) {
		// Discriminates preference-order from OR semantics: tty_major is
		// authoritative when present, so major 0 means no controlling terminal
		// even though the stale index is nonzero. An OR implementation would
		// wrongly return true here.
		e := newExecEvent(t, ttyFields{tty: i32(5), ttyMajor: u32(0), ttyMinor: u32(0)})
		require.False(t, e.GetHasTTY(), "tty_major present and 0 must win over a nonzero tty index")
	})

	t.Run("no tty fields at all", func(t *testing.T) {
		e := newExecEvent(t, ttyFields{})
		require.Equal(t, int32(0), e.GetTTY())
		require.Equal(t, uint32(0), e.GetTTYMajor())
		require.False(t, e.GetHasTTY())
	})
}

func TestStructEventTTYGetters(t *testing.T) {
	phase1 := &StructEvent{EventType: ExecveEventType, TTY: i32(3)}
	require.Equal(t, int32(3), phase1.GetTTY())
	require.True(t, phase1.GetHasTTY())

	phase1Zero := &StructEvent{EventType: ExecveEventType, TTY: i32(0)}
	require.False(t, phase1Zero.GetHasTTY())

	phase2 := &StructEvent{EventType: ExecveEventType, TTY: i32(0), TTYMajor: u32(136), TTYMinor: u32(0)}
	require.Equal(t, uint32(136), phase2.GetTTYMajor())
	require.True(t, phase2.GetHasTTY())

	majorZeroWins := &StructEvent{EventType: ExecveEventType, TTY: i32(5), TTYMajor: u32(0), TTYMinor: u32(0)}
	require.False(t, majorZeroWins.GetHasTTY(), "TTYMajor present and 0 must win over a nonzero TTY index")

	unset := &StructEvent{EventType: ExecveEventType}
	require.Equal(t, int32(0), unset.GetTTY())
	require.False(t, unset.GetHasTTY())
}

// logSize returns the number of bytes written to the capture file so far.
func logSize(t *testing.T, f *os.File) int64 {
	t.Helper()
	st, err := os.Stat(f.Name())
	require.NoError(t, err)
	return st.Size()
}

// resetLog truncates the capture file back to empty.
func resetLog(t *testing.T, f *os.File) {
	t.Helper()
	require.NoError(t, f.Truncate(0))
	_, err := f.Seek(0, 0)
	require.NoError(t, err)
}

// TestTTYGettersDoNotLog asserts that reading tty fields the running gadget does
// not emit produces no log output. tty_major is absent on every exec event until
// the gadget ships it, so a single Warning on that path becomes thousands of
// lines per second on a busy node.
//
// Does not call t.Parallel(): it mutates the global logger.
func TestTTYGettersDoNotLog(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "log")
	require.NoError(t, err)
	defer f.Close()

	// The pretty logger honours SetWriter; the zap logger does not, and plain
	// (non-Ctx) warnings bypass the OTEL bridge entirely.
	prevName := logger.L().LoggerName()
	logger.InitLogger("pretty")
	prev := logger.L().GetWriter()
	logger.L().SetWriter(f)
	defer func() {
		logger.L().SetWriter(prev)
		logger.InitLogger(prevName)
	}()

	// Phase-1 shape: tty_major and tty_minor are absent.
	e := newExecEvent(t, ttyFields{tty: i32(0)})

	// Control 1: capture must be live, or everything below passes vacuously.
	logger.L().Warning("capture control")
	require.NotZero(t, logSize(t, f), "log capture is not working, so this test would prove nothing")
	resetLog(t, f)

	// The property under test.
	for i := 0; i < 100; i++ {
		e.GetHasTTY()
		e.GetTTY()
		e.GetTTYMajor()
		e.GetTTYMinor()
		e.FieldPresent("tty_major")
	}
	require.Zero(t, logSize(t, f), "tty getters must not log for absent fields")

	// Control 2: an unguarded lookup of an absent field DOES log, proving the
	// assertion above would fail if a getter dropped its FieldPresent guard.
	//
	// Deliberately NOT "tty_major": getFieldAccessor caches found fields in the
	// package-global fieldCaches, keyed by EventType rather than by datasource.
	// Earlier tests in this package construct a phase-2 datasource that HAS
	// tty_major, which caches an accessor under ExecveEventType and silences the
	// warning for every later lookup of that name. A name nothing else looks up
	// is immune to that, and misses are never cached, so it logs every time.
	_ = e.getFieldAccessor("zz_absent_log_control")
	require.NotZero(t, logSize(t, f), "unguarded getFieldAccessor should log; if it does not, the assertion above has no teeth")
}

// TestTTYGettersUseTheirOwnDatasource is a regression test for accessor reuse
// across datasources.
//
// fieldCaches is keyed by EventType, not by datasource, so two datasources that
// share an event type share one accessor cache. A FieldAccessor decodes at a
// fixed offset in the layout of the datasource that produced it, so reading one
// datasource's data through another's accessor yields the wrong value or panics
// inside Inspektor Gadget's fieldAccessor.Get.
//
// Checking presence first does not prevent this: presence only rules out the
// case where this datasource lacks the field. When both expose it -- as here --
// presence passes and the stale accessor is still the other datasource's. The
// TTY getters therefore resolve accessors per datasource.
//
// The two datasources below deliberately place "tty" at different offsets, and
// the wide one is read first so it is the entry that lands in the shared cache.
func TestTTYGettersUseTheirOwnDatasource(t *testing.T) {
	newAt := func(t *testing.T, name string, pads int, tty int32) *DatasourceEvent {
		t.Helper()

		ds, err := datasource.New(datasource.TypeSingle, name)
		require.NoError(t, err)

		commAcc, err := ds.AddField("comm", api.Kind_String)
		require.NoError(t, err)
		padAccs := make([]datasource.FieldAccessor, pads)
		for i := 0; i < pads; i++ {
			padAccs[i], err = ds.AddField("pad"+string(rune('a'+i)), api.Kind_Uint64)
			require.NoError(t, err)
		}
		ttyAcc, err := ds.AddField("tty", api.Kind_Int32)
		require.NoError(t, err)

		data, err := ds.NewPacketSingle()
		require.NoError(t, err)
		t.Cleanup(func() { ds.Release(data) })

		require.NoError(t, commAcc.PutString(data, "bash"))
		for _, acc := range padAccs {
			require.NoError(t, acc.PutUint64(data, 0xDEADBEEF))
		}
		require.NoError(t, ttyAcc.PutInt32(data, tty))

		// Same EventType for both, which is what makes them share fieldCaches.
		return &DatasourceEvent{Data: data, Datasource: ds, EventType: ExecveEventType}
	}

	wide := newAt(t, "exec-wide", 3, 7)
	narrow := newAt(t, "exec-narrow", 0, 3)

	// Read the wide one first so its accessor is the cached one for "tty".
	require.Equal(t, int32(7), wide.GetTTY())
	require.True(t, wide.GetHasTTY())

	// The narrow datasource must read its own value, not the wide one's.
	require.Equal(t, int32(3), narrow.GetTTY(),
		"narrow datasource must decode its own tty, not through the wide datasource's cached accessor")
	require.True(t, narrow.GetHasTTY())

	// And a third, narrow datasource whose tty is genuinely 0 must not inherit
	// the cached nonzero reading.
	zero := newAt(t, "exec-zero", 0, 0)
	require.Equal(t, int32(0), zero.GetTTY())
	require.False(t, zero.GetHasTTY(), "tty == 0 must read as no terminal regardless of other datasources")
}
