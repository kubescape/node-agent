package feeder

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/prometheus/procfs"
)

// ticksPerSecond is USER_HZ, the unit of /proc/<pid>/stat field 22. Hardcoded to
// match prometheus/procfs's own userHZ constant and the wire contract's
// documentation that start times are exact multiples of 10 ms.
const ticksPerSecond = 100

// nsPerTick converts /proc/<pid>/stat field 22 (clock ticks since boot) to
// boot-relative nanoseconds. Exact: 1e9 / 100 = 10,000,000.
const nsPerTick = uint64(1_000_000_000 / ticksPerSecond)

// ProcfsFeeder implements ProcessEventFeeder by reading process information from /proc filesystem.
type ProcfsFeeder struct {
	subscribers        []chan<- conversion.ProcessEvent
	mutex              sync.RWMutex
	ctx                context.Context
	cancel             context.CancelFunc
	interval           time.Duration
	pidScanInterval    time.Duration
	procfsPath         string
	procfs             procfs.FS
	processTreeManager processtree.ProcessTreeManager
	// bootTime is /proc/stat's btime, read once at Start. Used only to derive the
	// display-only wall-clock start time; it has whole-second resolution, which is
	// why boot-relative nanoseconds remain the sole process-identity source.
	bootTime           time.Time
	running            bool
	wg                 sync.WaitGroup
}

// procInfo is a helper struct to pass results from worker goroutines.
type procInfo struct {
	event conversion.ProcessEvent
	err   error
}

// NewProcfsFeeder creates a new procfs feeder.
func NewProcfsFeeder(fullScanInterval time.Duration, pidScanInterval time.Duration, processTreeManager processtree.ProcessTreeManager) *ProcfsFeeder {
	return &ProcfsFeeder{
		interval:           fullScanInterval,
		pidScanInterval:    pidScanInterval,
		procfsPath:         "/proc",
		processTreeManager: processTreeManager,
	}
}

// Start begins the procfs feeder loop.
func (pf *ProcfsFeeder) Start(ctx context.Context) error {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	// Use pf.running as the guard to check if the feeder is running.
	if pf.running {
		return fmt.Errorf("procfs feeder already started")
	}

	// Initialize procfs
	fs, err := procfs.NewFS(pf.procfsPath)
	if err != nil {
		return fmt.Errorf("failed to initialize procfs: %w", err)
	}
	pf.procfs = fs

	if stat, err := fs.Stat(); err == nil {
		pf.bootTime = time.Unix(int64(stat.BootTime), 0)
	} else {
		// Wall-clock start times will stay zero; boot-relative identity is unaffected.
		fmt.Fprintf(os.Stderr, "procfs feeder: failed to read btime, StartTimeWall disabled: %v\n", err)
	}

	// Create a cancellable context for graceful shutdown
	pf.ctx, pf.cancel = context.WithCancel(ctx)
	pf.running = true

	pf.wg.Add(1)
	go pf.feedLoop(pf.ctx)

	return nil
}

// Stop stops the procfs feeder.
func (pf *ProcfsFeeder) Stop() error {
	pf.mutex.Lock()
	if !pf.running {
		pf.mutex.Unlock()
		return nil
	}
	cancel := pf.cancel
	pf.mutex.Unlock()

	if cancel != nil {
		cancel()
	}
	pf.wg.Wait()

	pf.mutex.Lock()
	pf.running = false
	pf.cancel = nil
	pf.mutex.Unlock()

	return nil
}

// Subscribe adds a channel to receive process events.
func (pf *ProcfsFeeder) Subscribe(ch chan<- conversion.ProcessEvent) {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	pf.subscribers = append(pf.subscribers, ch)
}

// Unsubscribe removes a channel from the subscribers list.
func (pf *ProcfsFeeder) Unsubscribe(ch chan<- conversion.ProcessEvent) {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	for i, sub := range pf.subscribers {
		if sub == ch {
			pf.subscribers = append(pf.subscribers[:i], pf.subscribers[i+1:]...)
			break
		}
	}
}

// feedLoop is the main loop that reads procfs and feeds events.
func (pf *ProcfsFeeder) feedLoop(ctx context.Context) {
	defer pf.wg.Done()

	ticker := time.NewTicker(pf.interval)
	exitTicker := time.NewTicker(pf.pidScanInterval)
	defer ticker.Stop()
	defer exitTicker.Stop()

	// Initial scan with backpressure to guarantee lossless delivery to subscribers
	pf.scanProcfsWithBackpressure(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pf.scanProcfs()
		case <-exitTicker.C:
			pids := pf.getPids()
			go pf.sendExitEvents(pids)
		}
	}
}

func (pf *ProcfsFeeder) scanProcfs() {
	pf.scanProcfsInternal(nil)
}

func (pf *ProcfsFeeder) scanProcfsWithBackpressure(ctx context.Context) {
	pf.scanProcfsInternal(ctx)
}

func (pf *ProcfsFeeder) scanProcfsInternal(blockingCtx context.Context) {
	pids := pf.getPids()
	if len(pids) == 0 {
		return
	}

	numWorkers := runtime.NumCPU()
	pidChan := make(chan uint32, len(pids))
	resultsChan := make(chan procInfo, len(pids))
	var wg sync.WaitGroup

	for range numWorkers {
		wg.Go(func() {
			for pid := range pidChan {
				event, err := pf.readProcessInfo(pid)
				resultsChan <- procInfo{event: event, err: err}
			}
		})
	}

	for _, pid := range pids {
		pidChan <- pid
	}
	close(pidChan)

	wg.Wait()
	close(resultsChan)

	// Step 3: Collect results and build a map for efficient parent lookup.
	procMap := make(map[uint32]conversion.ProcessEvent, len(pids))
	for res := range resultsChan {
		if res.err == nil {
			procMap[res.event.PID] = res.event
		}
	}

	// Step 4: Link parent info and broadcast. This is fast as it's all in-memory.
	for _, event := range procMap {
		if parentProc, ok := procMap[event.PPID]; ok {
			eventWithPcomm := event
			eventWithPcomm.Pcomm = parentProc.Comm
			pf.broadcastEventWithBackpressure(blockingCtx, eventWithPcomm)
		} else {
			pf.broadcastEventWithBackpressure(blockingCtx, event)
		}
	}
}

func (pf *ProcfsFeeder) sendExitEvents(pids []uint32) {
	now := time.Now().UTC()
	pidSet := make(map[uint32]struct{}, len(pids))
	for _, pid := range pids {
		pidSet[pid] = struct{}{}
	}
	currentPids := pf.processTreeManager.GetPidList()
	for _, pid := range currentPids {
		if _, ok := pidSet[pid]; !ok {
			// send exit event
			exitEvent := conversion.ProcessEvent{
				Type:      conversion.ExitEvent,
				Timestamp: now,
				PID:       pid,
				Comm:      "exit",
			}
			pf.broadcastEvent(exitEvent)
		}
	}
}

func (pf *ProcfsFeeder) getPids() []uint32 {
	entries, err := os.ReadDir(pf.procfsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading procfs directory: %v\n", err)
		return nil
	}

	pids := make([]uint32, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Names that are purely numeric are PIDs
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		pids = append(pids, uint32(pid))
	}
	return pids
}

func (pf *ProcfsFeeder) readProcessInfo(pid uint32) (conversion.ProcessEvent, error) {
	event := conversion.ProcessEvent{
		Type:      conversion.ProcfsEvent,
		Timestamp: time.Now().UTC(),
		PID:       pid,
	}

	proc, err := pf.procfs.Proc(int(pid))
	if err != nil {
		return event, err
	}

	stat, err := proc.Stat()
	if err != nil {
		return event, err
	}

	event.PPID = uint32(stat.PPID)
	event.Comm = stat.Comm

	// Field 22: process creation time in clock ticks since boot. Convert to
	// boot-relative nanoseconds (the identity unit on the wire) and, separately,
	// to a display-only wall-clock time via btime.
	event.StartTimeNs = stat.Starttime * nsPerTick
	if !pf.bootTime.IsZero() && event.StartTimeNs != 0 {
		event.StartTimeWall = pf.bootTime.Add(time.Duration(event.StartTimeNs))
	}

	if status, err := proc.NewStatus(); err == nil {
		uid := uint32(status.UIDs[1])
		gid := uint32(status.GIDs[1])
		event.Uid = &uid
		event.Gid = &gid
	}

	if cmdline, err := proc.CmdLine(); err == nil {
		if len(cmdline) == 0 {
			event.Cmdline = stat.Comm
		} else {
			event.Cmdline = strings.Join(cmdline, " ")
			event.Argv = append([]string(nil), cmdline...)
		}
	}

	if cwd, err := proc.Cwd(); err == nil {
		event.Cwd = cwd
	}

	if exe, err := proc.Executable(); err == nil {
		event.Path = exe
	}

	namespaces, err := proc.Namespaces()
	if err == nil {
		event.ContainerMntNs = uint64(namespaces["mnt"].Inode)
		event.ContainerNetNs = uint64(namespaces["net"].Inode)
	}

	return event, nil
}

// getProcessComm gets the command name for a given PID.
func (pf *ProcfsFeeder) getProcessComm(pid uint32) (string, error) {
	proc, err := pf.procfs.Proc(int(pid))
	if err != nil {
		return "", err
	}
	return proc.Comm()
}

// broadcastEvent sends an event to all subscribers using non-blocking send.
func (pf *ProcfsFeeder) broadcastEvent(event conversion.ProcessEvent) {
	pf.broadcastEventWithBackpressure(nil, event)
}

// broadcastEventWithBackpressure sends an event to all subscribers, waiting on
// channel capacity when blockingCtx is non-nil to provide lossless delivery.
func (pf *ProcfsFeeder) broadcastEventWithBackpressure(blockingCtx context.Context, event conversion.ProcessEvent) {
	pf.mutex.RLock()
	if len(pf.subscribers) == 0 {
		pf.mutex.RUnlock()
		return
	}
	subscribers := append([]chan<- conversion.ProcessEvent(nil), pf.subscribers...)
	pf.mutex.RUnlock()

	for _, ch := range subscribers {
		if blockingCtx != nil {
			select {
			case ch <- event:
			case <-blockingCtx.Done():
				return
			}
		} else {
			select {
			case ch <- event:
			default:
			}
		}
	}
}

// ProcessSpecificPID processes a specific PID and feeds it as an event.
func (pf *ProcfsFeeder) ProcessSpecificPID(pid uint32) error {
	event, err := pf.readProcessInfo(pid)
	if err != nil {
		return err
	}

	if event.PPID > 0 {
		if parentComm, err := pf.getProcessComm(event.PPID); err == nil {
			event.Pcomm = parentComm
		}
	}

	pf.broadcastEvent(event)
	return nil
}
