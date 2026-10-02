package containerwatcher

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	"golang.org/x/sync/singleflight"
)

const (
	listenerSnapshotTTL = 5 * time.Second
	negativeSnapshotTTL = 500 * time.Millisecond
	errorSnapshotTTL    = 500 * time.Millisecond
)

type containerEntry struct {
	pid        uint32
	ports      map[uint16]struct{}
	err        error
	at         time.Time
	generation uint64
	inFlight   int
	forgotten  bool
}

type listenerCache struct {
	mu          sync.Mutex
	byContainer map[string]*containerEntry
	genSeq      uint64
	sf          singleflight.Group
	now         func() time.Time
	read        func(pid uint32) (map[uint16]struct{}, error)
	onQuery     func()
}

func newListenerCache() *listenerCache {
	return &listenerCache{
		byContainer: map[string]*containerEntry{},
		genSeq:      1,
		now:         time.Now,
		read:        listeningTCPPorts,
	}
}

func (c *listenerCache) listening(containerID string, pid uint32, port uint16) (bool, bool) {
	if c.onQuery != nil {
		c.onQuery()
	}
	now := c.now()

	c.mu.Lock()
	if c.byContainer == nil {
		c.byContainer = map[string]*containerEntry{}
	}
	entry := c.byContainer[containerID]
	if entry != nil && (entry.forgotten || entry.pid != pid) {
		entry.forgotten = true
		c.genSeq++
		entry.generation = c.genSeq
		if entry.inFlight == 0 {
			delete(c.byContainer, containerID)
		}
		entry = nil
	}
	if entry != nil {
		age := now.Sub(entry.at)
		if entry.err != nil {
			if age <= errorSnapshotTTL {
				c.mu.Unlock()
				return false, false
			}
		} else if age <= listenerSnapshotTTL {
			if _, listening := entry.ports[port]; listening {
				c.mu.Unlock()
				return true, true
			}
			// If the snapshot is fresh, a negative verdict is valid and
			// avoids hammering procfs during scan bursts.
			if age <= negativeSnapshotTTL {
				c.mu.Unlock()
				return false, true
			}
		}
	}

	if entry == nil {
		c.genSeq++
		entry = &containerEntry{pid: pid, generation: c.genSeq}
		c.byContainer[containerID] = entry
	}
	entry.inFlight++
	gen := entry.generation
	c.mu.Unlock()

	// Snapshot is missing, expired, PID changed, or a stale negative/error verdict:
	// read procfs outside the mutex, coalescing concurrent reads per container, PID, and generation.
	flightKey := fmt.Sprintf("%s:%d:%d", containerID, pid, gen)
	res, err, _ := c.sf.Do(flightKey, func() (any, error) {
		return c.read(pid)
	})

	var ports map[uint16]struct{}
	if err == nil {
		if p, ok := res.(map[uint16]struct{}); ok {
			ports = p
		}
	}

	c.mu.Lock()
	entry.inFlight--
	if !entry.forgotten && entry.generation == gen && entry.pid == pid {
		entry.ports = ports
		entry.err = err
		entry.at = c.now()
	}
	if entry.forgotten && entry.inFlight == 0 {
		if c.byContainer[containerID] == entry {
			delete(c.byContainer, containerID)
		}
	}
	c.mu.Unlock()

	if err != nil || ports == nil {
		// When procfs cannot be read, return unknown so the event is kept.
		return false, false
	}

	_, listening := ports[port]
	return listening, true
}

func (c *listenerCache) forget(containerID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byContainer == nil {
		return
	}
	entry, ok := c.byContainer[containerID]
	if !ok {
		return
	}
	entry.forgotten = true
	c.genSeq++
	entry.generation = c.genSeq
	if entry.inFlight == 0 {
		delete(c.byContainer, containerID)
	}
}

func listeningTCPPorts(pid uint32) (map[uint16]struct{}, error) {
	ports := map[uint16]struct{}{}
	var firstErr error
	opened := 0
	for _, path := range []string{fmt.Sprintf("/proc/%d/net/tcp", pid), fmt.Sprintf("/proc/%d/net/tcp6", pid)} {
		f, err := os.Open(path)
		if err != nil {
			if strings.HasSuffix(path, "tcp6") && os.IsNotExist(err) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		opened++
		scanErr := parseListeningPorts(f, ports)
		f.Close()
		if scanErr != nil && firstErr == nil {
			firstErr = scanErr
		}
	}
	if opened == 0 || firstErr != nil {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("no tcp procfs tables could be opened for pid %d", pid)
	}
	return ports, nil
}

func parseListeningPorts(r io.Reader, ports map[uint16]struct{}) error {
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
	return sc.Err()
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
	containerID := container.Runtime.ContainerID
	if containerID == "" {
		return false
	}
	listening, known := ehf.listeners.listening(containerID, pid, ne.GetDstPort())
	return known && !listening
}
