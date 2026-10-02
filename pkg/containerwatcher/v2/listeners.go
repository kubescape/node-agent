package containerwatcher

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
)

const listenerSnapshotTTL = 5 * time.Second

type listenerSnapshot struct {
	ports map[uint16]struct{}
	at    time.Time
}

type listenerCache struct {
	mu    sync.Mutex
	byPid map[uint32]listenerSnapshot
	now   func() time.Time
	read  func(pid uint32) (map[uint16]struct{}, error)
}

func newListenerCache() *listenerCache {
	return &listenerCache{byPid: map[uint32]listenerSnapshot{}, now: time.Now, read: listeningTCPPorts}
}

func (c *listenerCache) listening(pid uint32, port uint16) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	snap, ok := c.byPid[pid]
	if ok && c.now().Sub(snap.at) <= listenerSnapshotTTL {
		if _, listening := snap.ports[port]; listening {
			return true, true
		}
		// Revalidate cached misses before dropping: the application may have
		// opened the listening socket after snap.at.
	}
	ports, err := c.read(pid)
	if err != nil {
		return false, false
	}
	snap = listenerSnapshot{ports: ports, at: c.now()}
	c.byPid[pid] = snap
	_, listening := snap.ports[port]
	return listening, true
}

func (c *listenerCache) forget(pid uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byPid, pid)
}

func listeningTCPPorts(pid uint32) (map[uint16]struct{}, error) {
	ports := map[uint16]struct{}{}
	var firstErr error
	opened := 0
	for _, path := range []string{fmt.Sprintf("/proc/%d/net/tcp", pid), fmt.Sprintf("/proc/%d/net/tcp6", pid)} {
		f, err := os.Open(path)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		opened++
		parseListeningPorts(f, ports)
		f.Close()
	}
	if opened == 0 && firstErr != nil {
		return nil, firstErr
	}
	return ports, nil
}

func parseListeningPorts(r interface{ Read([]byte) (int, error) }, ports map[uint16]struct{}) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		i := strings.LastIndexByte(fields[1], ':')
		if i < 0 {
			continue
		}
		p, err := strconv.ParseUint(fields[1][i+1:], 16, 16)
		if err != nil {
			continue
		}
		ports[uint16(p)] = struct{}{}
	}
}

func (ehf *EventHandlerFactory) unsolicitedIngress(enrichedEvent *events.EnrichedEvent, container *containercollection.Container) bool {
	if ehf.listeners == nil || enrichedEvent.Event.GetEventType() != utils.NetworkEventType {
		return false
	}
	ne, ok := enrichedEvent.Event.(utils.NetworkEvent)
	if !ok || ne.GetPktType() != utils.HostPktType || ne.GetProto() != "TCP" || ne.GetPID() != 0 {
		return false
	}
	pid := container.ContainerPid()
	if pid == 0 {
		return false
	}
	listening, known := ehf.listeners.listening(pid, ne.GetDstPort())
	return known && !listening
}
