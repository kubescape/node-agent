package igbackend

import (
	"testing"
	"time"
)

// N republishes into the same slots keep the publication tables bounded: a
// replaced publication's table is dropped once its grace has passed.
func TestPublicationTablesStayBounded(t *testing.T) {
	now := time.Unix(1000, 0)
	i := &nativeNodeInstance{section: "network", revision: 1, now: func() time.Time { return now }}
	i.remember(1, nil, nil, nil, 0)
	count := func() (n int) {
		i.tables.Range(func(any, any) bool { n++; return true })
		return n
	}
	for g := uint64(2); g < 202; g++ {
		slot := uint32(g % 2)
		i.remember(g, nil, nil, nil, slot)
		i.published(slot, g)
		now = now.Add(time.Second)
		i.collectTables()
	}
	// Two slots in use, the start's table, and the publications of the
	// last tableGrace still in their grace.
	if n, max := count(), 3+int(tableGrace/time.Second)+1; n > max {
		t.Fatalf("%d tables after 200 republishes, want at most %d", n, max)
	}
	now = now.Add(tableGrace)
	i.collectTables()
	if n := count(); n != 3 {
		t.Fatalf("after the grace: %d tables, want the start and the two live slots", n)
	}
	// A verdict still in flight finds the replaced table during the grace.
	i.remember(500, nil, nil, nil, 0)
	i.published(0, 500)
	if _, ok := i.tables.Load(uint64(200)); !ok {
		t.Fatal("a replaced table must stay for its grace")
	}
	// The start's table is never retired.
	if _, ok := i.tables.Load(uint64(1)); !ok {
		t.Fatal("the instance start's table must stay")
	}
}
