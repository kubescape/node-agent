package feeder

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/procfs"
)

// ProcfsFeeder implements ProcessEventFeeder by reading process information from /proc filesystem
type ProcfsFeeder struct {
	subscribers []chan<- ProcessEvent
	mutex       sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	interval    time.Duration
	procfsPath  string
	procfs      procfs.FS
}

// NewProcfsFeeder creates a new procfs feeder
func NewProcfsFeeder(interval time.Duration) *ProcfsFeeder {
	return &ProcfsFeeder{
		interval:   interval,
		procfsPath: "/proc",
	}
}

// Start begins the procfs feeder loop
func (pf *ProcfsFeeder) Start(ctx context.Context) error {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	if pf.ctx != nil {
		return fmt.Errorf("procfs feeder already started")
	}

	// Initialize procfs
	fs, err := procfs.NewFS(pf.procfsPath)
	if err != nil {
		return fmt.Errorf("failed to initialize procfs: %v", err)
	}
	pf.procfs = fs

	// Create a cancellable context for graceful shutdown
	pf.ctx, pf.cancel = context.WithCancel(ctx)

	go pf.feedLoop()

	return nil
}

// Stop stops the procfs feeder
func (pf *ProcfsFeeder) Stop() error {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	if pf.cancel != nil {
		pf.cancel()
	}

	return nil
}

// Subscribe adds a channel to receive process events
func (pf *ProcfsFeeder) Subscribe(ch chan<- ProcessEvent) {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	pf.subscribers = append(pf.subscribers, ch)
}

// feedLoop is the main loop that reads procfs and feeds events
func (pf *ProcfsFeeder) feedLoop() {
	// Capture context locally to avoid race conditions
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

// scanProcfs scans the /proc directory for processes
func (pf *ProcfsFeeder) scanProcfs() {
	entries, err := os.ReadDir(pf.procfsPath)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		pf.processProcfsEntry(uint32(pid))
	}
}

// processProcfsEntry processes a single procfs entry for a given PID
func (pf *ProcfsFeeder) processProcfsEntry(pid uint32) {
	event, err := pf.readProcessInfo(pid)
	if err != nil {
		return
	}

	pf.broadcastEvent(event)
}

// readProcessInfo reads process information from procfs for a given PID
func (pf *ProcfsFeeder) readProcessInfo(pid uint32) (ProcessEvent, error) {
	event := ProcessEvent{
		Type:      ProcfsEvent,
		Timestamp: time.Now(),
		PID:       pid,
	}

	// Get process using procfs
	proc, err := pf.procfs.Proc(int(pid))
	if err != nil {
		return event, err
	}

	// Get process stat
	stat, err := proc.Stat()
	if err != nil {
		return event, err
	}

	// Fill basic information from stat
	event.PPID = uint32(stat.PPID)
	event.Comm = stat.Comm

	// Get process status for UID/GID
	if status, err := proc.NewStatus(); err == nil {
		// UIDs and GIDs have a fixed length of 4 elements
		uid := uint32(status.UIDs[1]) // Effective UID
		gid := uint32(status.GIDs[1]) // Effective GID
		event.Uid = &uid
		event.Gid = &gid
	}

	// Get command line
	if cmdline, err := proc.CmdLine(); err == nil {
		if len(cmdline) == 0 {
			event.Cmdline = stat.Comm
		} else {
			event.Cmdline = strings.Join(cmdline, " ")
		}
	}

	// Get current working directory
	if cwd, err := proc.Cwd(); err == nil {
		event.Cwd = cwd
	}

	// Get executable path
	if exe, err := proc.Executable(); err == nil {
		event.Path = exe
	}

	// Get parent process name if available
	if event.PPID > 0 {
		parentComm, err := pf.getProcessComm(event.PPID)
		if err == nil {
			event.Pcomm = parentComm
		}
	}

	return event, nil
}

// getProcessComm gets the command name for a given PID
func (pf *ProcfsFeeder) getProcessComm(pid uint32) (string, error) {
	proc, err := pf.procfs.Proc(int(pid))
	if err != nil {
		return "", err
	}

	comm, err := proc.Comm()
	if err != nil {
		return "", err
	}

	return comm, nil
}

// broadcastEvent sends an event to all subscribers
func (pf *ProcfsFeeder) broadcastEvent(event ProcessEvent) {
	pf.mutex.RLock()
	defer pf.mutex.RUnlock()

	for _, ch := range pf.subscribers {
		select {
		case ch <- event:
		default:
			// Channel is full, skip this event
		}
	}
}

// ProcessSpecificPID processes a specific PID and feeds it as an event
func (pf *ProcfsFeeder) ProcessSpecificPID(pid uint32) error {
	event, err := pf.readProcessInfo(pid)
	if err != nil {
		return err
	}

	pf.broadcastEvent(event)
	return nil
}
