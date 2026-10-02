package containerwatcher

import (
	"errors"
	"strings"
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
	c := &listenerCache{byPid: map[uint32]listenerSnapshot{}, now: func() time.Time { return now }, read: func(pid uint32) (map[uint16]struct{}, error) {
		reads++
		if pid == 404 {
			return nil, errors.New("no such process")
		}
		return currentPorts, nil
	}}
	listening, known := c.listening(7, 8443)
	require.True(t, known)
	require.True(t, listening)
	require.Equal(t, 1, reads)

	// Second query for the same listening port within TTL uses the cached positive result and does not re-read.
	listening, known = c.listening(7, 8443)
	require.True(t, known)
	require.True(t, listening)
	require.Equal(t, 1, reads, "positive verdict within TTL uses cache without re-reading")

	// Query for an unrecorded port revalidates procfs to avoid dropping newly opened ports.
	currentPorts = map[uint16]struct{}{8443: {}, 8444: {}}
	listening, known = c.listening(7, 8444)
	require.True(t, known)
	require.True(t, listening)
	require.Equal(t, 2, reads, "miss within TTL revalidates procfs and discovers newly opened port")

	// Query for a closed port revalidates procfs and confirms not listening.
	listening, known = c.listening(7, 9999)
	require.True(t, known)
	require.False(t, listening)
	require.Equal(t, 3, reads, "miss for closed port revalidates procfs and yields false")

	// After the TTL expires, the cache is refreshed even for previously listening ports.
	now = now.Add(listenerSnapshotTTL + time.Second)
	listening, known = c.listening(7, 8443)
	require.True(t, known)
	require.True(t, listening)
	require.Equal(t, 4, reads, "after the TTL the snapshot is refreshed")

	// A process whose procfs cannot be read yields no verdict (known=false).
	_, known = c.listening(404, 8443)
	require.False(t, known, "a process whose procfs cannot be read yields no verdict, and the event is kept")
}

func TestListenerCache_Forget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	reads := 0
	c := &listenerCache{byPid: map[uint32]listenerSnapshot{}, now: func() time.Time { return now }, read: func(pid uint32) (map[uint16]struct{}, error) {
		reads++
		return map[uint16]struct{}{8443: {}}, nil
	}}
	listening, known := c.listening(7, 8443)
	require.True(t, known && listening)
	require.Equal(t, 1, reads)

	c.forget(7)
	listening, known = c.listening(7, 8443)
	require.True(t, known && listening)
	require.Equal(t, 2, reads, "forget evicted cached entry for pid")
}
