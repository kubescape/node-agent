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

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/prometheus/procfs"
)

// ProcfsFeeder implements ProcessEventFeeder by reading process information from /proc filesystem.
type ProcfsFeeder struct {
	subscribers        []chan<- conversion.ProcessEvent
	mutex              sync.RWMutex
	ctx                context.Context
	cancel             context.CancelFunc
	interval           time.Duration
	procfsPath         string
	procfs             procfs.FS
	processTreeManager processtree.ProcessTreeManager
}

// procInfo is a helper struct to pass results from worker goroutines.
type procInfo struct {
	event conversion.ProcessEvent
	err   error
}

// NewProcfsFeeder creates a new procfs feeder.
func NewProcfsFeeder(interval time.Duration, processTreeManager processtree.ProcessTreeManager) *ProcfsFeeder {
	return &ProcfsFeeder{
		interval:           interval,
		procfsPath:         "/proc",
		processTreeManager: processTreeManager,
	}
}

// Start begins the procfs feeder loop.
func (pf *ProcfsFeeder) Start(ctx context.Context) error {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	// Use pf.cancel as the guard to check if the feeder is running.
	if pf.cancel != nil {
		return fmt.Errorf("procfs feeder already started")
	}

	// Initialize procfs
	fs, err := procfs.NewFS(pf.procfsPath)
	if err != nil {
		return fmt.Errorf("failed to initialize procfs: %w", err)
	}
	pf.procfs = fs

	// Create a cancellable context for graceful shutdown
	pf.ctx, pf.cancel = context.WithCancel(ctx)

	go pf.feedLoop()

	return nil
}

// Stop stops the procfs feeder.
func (pf *ProcfsFeeder) Stop() error {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	if pf.cancel != nil {
		pf.cancel()
		// Setting cancel to nil indicates the feeder is stopped and can be started again.
		pf.cancel = nil
		// DO NOT set pf.ctx to nil here. The feedLoop goroutine needs it
		// to gracefully shut down when it reads from ctx.Done().
	}

	return nil
}

// Subscribe adds a channel to receive process events.
func (pf *ProcfsFeeder) Subscribe(ch chan<- conversion.ProcessEvent) {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	pf.subscribers = append(pf.subscribers, ch)
}

// feedLoop is the main loop that reads procfs and feeds events.
func (pf *ProcfsFeeder) feedLoop() {
	// Capture context locally. This is safe now because pf.ctx is never set to nil
	// during the feeder's lifecycle.
	ctx := pf.ctx

	ticker := time.NewTicker(pf.interval)
	defer ticker.Stop()

	// Initial scan
	pf.scanProcfs()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pf.scanProcfs()
		}
	}
}

func (pf *ProcfsFeeder) scanProcfs() {
	entries, err := os.ReadDir(pf.procfsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading procfs directory: %v\n", err)
		return
	}

	pids := make([]uint32, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		pids = append(pids, uint32(pid))
	}

	numWorkers := runtime.NumCPU()
	pidChan := make(chan uint32, len(pids))
	resultsChan := make(chan procInfo, len(pids))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pid := range pidChan {
				event, err := pf.readProcessInfo(pid)
				resultsChan <- procInfo{event: event, err: err}
			}
		}()
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

	// Step 4: Send exit events for processes that are no longer in /proc.
	pf.sendExitEvents(procMap)

	// Step 5: Link parent info and broadcast. This is fast as it's all in-memory.
	for _, event := range procMap {
		if parentProc, ok := procMap[event.PPID]; ok {
			eventWithPcomm := event
			eventWithPcomm.Pcomm = parentProc.Comm
			pf.broadcastEvent(eventWithPcomm)
		} else {
			pf.broadcastEvent(event)
		}
	}
}

func (pf *ProcfsFeeder) sendExitEvents(procMap map[uint32]conversion.ProcessEvent) {
	logger.L().Debug("AFEK - sendExitEvents")
	currentPids := pf.processTreeManager.GetPidList()
	for _, pid := range currentPids {
		if _, ok := procMap[pid]; !ok {
			// send exit event
			logger.L().Debug("AFEK - sendExitEvents", helpers.String("pid", fmt.Sprintf("%d", pid)))
			exitEvent := conversion.ProcessEvent{
				Type:      conversion.ExitEvent,
				Timestamp: time.Now().UTC(),
				PID:       pid,
			}
			pf.broadcastEvent(exitEvent)
		}
	}
}

// readProcessInfo reads process information from procfs for a given PID.
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
		}
	}

	if cwd, err := proc.Cwd(); err == nil {
		event.Cwd = cwd
	}

	if exe, err := proc.Executable(); err == nil {
		event.Path = exe
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

// broadcastEvent sends an event to all subscribers.
func (pf *ProcfsFeeder) broadcastEvent(event conversion.ProcessEvent) {
	pf.mutex.RLock()
	defer pf.mutex.RUnlock()

	for _, ch := range pf.subscribers {
		select {
		case ch <- event:
		default:
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
