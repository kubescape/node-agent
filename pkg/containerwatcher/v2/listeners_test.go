package containerwatcher

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const procNetTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:20FB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 639490 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000A2A0120:20FB 0000000000000000FFFF00000A2A017D:8B34 01 00000000:00000000 00:00000000 00000000     0        0 641200 1 0000000000000000 20 4 30 10 -1
`

const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:07E3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 639484 1 0000000000000000 100 0 0 10 0
   1: 00000000:2330 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 700001 1 0000000000000000 100 0 0 10 0
`

func TestParseListeningPorts(t *testing.T) {
	ports := map[uint16]struct{}{}
	parseListeningPorts(strings.NewReader(procNetTCP6), ports)
	parseListeningPorts(strings.NewReader(procNetTCP), ports)
	require.Equal(t, map[uint16]struct{}{8443: {}, 2019: {}, 9008: {}}, ports, "LISTEN sockets only, v4 and v6 alike; established connections on the same port are not listeners")
}

func TestListenerCache_TTLAndUnknown(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	reads := 0
	currentPorts := map[uint16]struct{}{8443: {}}
	c := &listenerCache{byContainer: map[string]listenerSnapshot{}, now: func() time.Time { return now }, read: func(pid uint32) (map[uint16]struct{}, error) {
		reads++
		if pid == 404 {
			return nil, errors.New("no such process")
		}
		return currentPorts, nil
	}}
	listening, known := c.listening("cont-1", 7, 8443)
	require.True(t, known)
	require.True(t, listening)
	require.Equal(t, 1, reads)

	// Second query for the same listening port within TTL uses the cached positive result and does not re-read.
	listening, known = c.listening("cont-1", 7, 8443)
	require.True(t, known)
	require.True(t, listening)
	require.Equal(t, 1, reads, "positive verdict within TTL uses cache without re-reading")

	// A query for an unrecorded port within negativeSnapshotTTL reuses the fresh negative verdict without re-reading.
	listening, known = c.listening("cont-1", 7, 9999)
	require.True(t, known)
	require.False(t, listening)
	require.Equal(t, 1, reads, "fresh negative verdict within negativeSnapshotTTL uses cache without re-reading")

	// Once negativeSnapshotTTL elapses, miss revalidates procfs to discover newly opened ports.
	now = now.Add(negativeSnapshotTTL + time.Millisecond)
	currentPorts = map[uint16]struct{}{8443: {}, 8444: {}}
	listening, known = c.listening("cont-1", 7, 8444)
	require.True(t, known)
	require.True(t, listening)
	require.Equal(t, 2, reads, "stale negative verdict revalidates procfs and discovers newly opened port")

	// Query for a closed port after negativeSnapshotTTL confirms not listening.
	now = now.Add(negativeSnapshotTTL + time.Millisecond)
	listening, known = c.listening("cont-1", 7, 9999)
	require.True(t, known)
	require.False(t, listening)
	require.Equal(t, 3, reads, "stale negative verdict revalidates procfs and yields false")

	// After the TTL expires, the cache is refreshed even for previously listening ports.
	now = now.Add(listenerSnapshotTTL + time.Second)
	listening, known = c.listening("cont-1", 7, 8443)
	require.True(t, known)
	require.True(t, listening)
	require.Equal(t, 4, reads, "after the TTL the snapshot is refreshed")

	// A process whose procfs cannot be read yields no verdict (known=false).
	_, known = c.listening("cont-404", 404, 8443)
	require.False(t, known, "a process whose procfs cannot be read yields no verdict, and the event is kept")
}

func TestListenerCache_Forget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	reads := 0
	c := &listenerCache{byContainer: map[string]listenerSnapshot{}, now: func() time.Time { return now }, read: func(pid uint32) (map[uint16]struct{}, error) {
		reads++
		return map[uint16]struct{}{8443: {}}, nil
	}}
	listening, known := c.listening("cont-1", 7, 8443)
	require.True(t, known && listening)
	require.Equal(t, 1, reads)

	c.forget("cont-1")
	listening, known = c.listening("cont-1", 7, 8443)
	require.True(t, known && listening)
	require.Equal(t, 2, reads, "forget evicted cached entry for containerID")
}

func TestListenerCache_PIDReuseIsolated(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	reads := 0
	portsByPid := map[uint32]map[uint16]struct{}{
		100: {8443: {}},
	}
	c := &listenerCache{byContainer: map[string]listenerSnapshot{}, now: func() time.Time { return now }, read: func(pid uint32) (map[uint16]struct{}, error) {
		reads++
		return portsByPid[pid], nil
	}}

	// Old container "old-c" uses PID 100 with listener on 8443
	listening, known := c.listening("old-c", 100, 8443)
	require.True(t, known && listening)
	require.Equal(t, 1, reads)

	// Now PID 100 is reused for a brand new container "new-c" that listens only on 9000
	portsByPid[100] = map[uint16]struct{}{9000: {}}

	// "new-c" querying 8443 must not inherit "old-c"'s snapshot
	listening, known = c.listening("new-c", 100, 8443)
	require.True(t, known)
	require.False(t, listening, "new container must not inherit listening state of previous container with same PID")
	require.Equal(t, 2, reads, "new container triggered its own fresh procfs read")

	// "new-c" querying its actual port 9000 must succeed
	listening, known = c.listening("new-c", 100, 9000)
	require.True(t, known && listening)
	require.Equal(t, 2, reads)
}

func TestListenerCache_CoalescesConcurrentReads(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var reads int64
	started := make(chan struct{})
	gate := make(chan struct{})

	c := &listenerCache{byContainer: map[string]listenerSnapshot{}, now: func() time.Time { return now }, read: func(pid uint32) (map[uint16]struct{}, error) {
		if atomic.AddInt64(&reads, 1) == 1 {
			close(started)
		}
		<-gate
		return map[uint16]struct{}{8080: {}}, nil
	}}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			listening, known := c.listening("cont-shared", 10, 8080)
			require.True(t, known && listening)
		}()
	}

	<-started
	close(gate)
	wg.Wait()

	require.Equal(t, int64(1), atomic.LoadInt64(&reads), "concurrent queries for the same container coalesce into a single read")
}
