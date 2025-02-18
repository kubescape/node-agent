package ptracewatcher

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	traceopentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/node-agent/pkg/hosthashsensor/v1"
	"github.com/kubescape/node-agent/pkg/hostrulemanager"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/processmanager"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/panjf2000/ants/v2"
)

type IPtraceWatcher interface {
	Start(args []string) error
	Stop() error
}

type ProcessInfo struct {
	PID     int
	PPID    int
	Comm    string
	Exe     string
	Cmdline []string
}

type SyscallEventListener interface {
	OnOpen(processInfo ProcessInfo, filename string, flags int, mode int)
	OnExecve(processInfo ProcessInfo, filename string, argv []string, envp []string)
	OnSymlink(processInfo ProcessInfo, oldpath string, newpath string)
}

type PtraceWatcher struct {
	cfg              config.Config
	metrics          metricsmanager.MetricsManager
	processManager   processmanager.ProcessManagerClient
	hostHashSensor   hosthashsensor.HostHashSensorServiceInterface
	hostRuleManager  hostrulemanager.HostRuleManagerClient
	processTracer    *ProcessTracer
	reportWorkerPool *ants.Pool
}

// TracedProcess represents a process being traced
type TracedProcess struct {
	pid     int
	name    string
	parent  *TracedProcess
	threads map[int]syscall.PtraceRegs
}

// ProcessTracer handles the tracing of processes
type ProcessTracer struct {
	processes map[int]*TracedProcess
	listeners []SyscallEventListener
}

func NewProcessTracer(listeners []SyscallEventListener) *ProcessTracer {
	return &ProcessTracer{
		processes: make(map[int]*TracedProcess),
		listeners: listeners,
	}
}

func (pt *ProcessTracer) addProcess(pid int, name string, parent *TracedProcess) {
	pt.processes[pid] = &TracedProcess{
		pid:     pid,
		name:    name,
		parent:  parent,
		threads: make(map[int]syscall.PtraceRegs),
	}
}

func (pt *ProcessTracer) removeProcess(pid int) {
	delete(pt.processes, pid)
}

func (pt *ProcessTracer) trace(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	runtime.LockOSThread()
	if err := cmd.Start(); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("failed to start process: %v", err)
	}

	logger.L().Debug("ProcessTracer - trace - started process", helpers.String("pid", fmt.Sprintf("%d", cmd.Process.Pid)), helpers.String("path", cmd.Path))

	pt.addProcess(cmd.Process.Pid, cmd.Path, nil)

	runtime.UnlockOSThread()

	return pt.handleProcessEvents()
}

func (pt *ProcessTracer) handleProcessEvents() error {
	var status syscall.WaitStatus
	for len(pt.processes) > 0 {
		// Get both process ID and thread ID from wait4
		pid, err := syscall.Wait4(-1, &status, syscall.WALL, nil)
		if err != nil {
			return fmt.Errorf("wait4 failed: %v", err)
		}

		proc, exists := pt.processes[pid]
		if !exists {
			logger.L().Debug("ProcessTracer - handleProcessEvents - process not found", helpers.String("pid", fmt.Sprintf("%d", pid)))
			continue
		}

		if status.Exited() {
			fmt.Fprintf(os.Stderr, "Process %d (%s) exited with status %d\n",
				pid, proc.name, status.ExitStatus())
			pt.removeProcess(pid)
			continue
		}

		if status.Stopped() {
			signal := status.StopSignal()

			if signal == syscall.SIGTRAP {
				// Handle system call
				regs := &syscall.PtraceRegs{}
				err := syscall.PtraceGetRegs(pid, regs)
				if err == nil {
					// On x86_64, the system call number is in ORIG_RAX
					syscallNum := regs.Orig_rax

					// Handle open syscall
					if syscallNum == syscall.SYS_OPEN {
						filename := readString(pid, uintptr(regs.Rdi))
						flags := int(regs.Rsi)
						mode := int(regs.Rdx)
						for _, listener := range pt.listeners {
							listener.OnOpen(ProcessInfo{
								PID:     pid,
								PPID:    proc.parent.pid,
								Comm:    proc.name,
								Exe:     proc.name,
								Cmdline: []string{proc.name},
							}, filename, flags, mode)
						}
					} else if syscallNum == syscall.SYS_OPENAT {
						filename := readString(pid, uintptr(regs.Rsi))
						flags := int(regs.Rdx)
						mode := int(regs.Rcx)
						ppid := 0
						if proc.parent != nil {
							ppid = proc.parent.pid
						}
						for _, listener := range pt.listeners {
							listener.OnOpen(ProcessInfo{
								PID:     pid,
								PPID:    ppid,
								Comm:    proc.name,
								Exe:     proc.name,
								Cmdline: []string{proc.name},
							}, filename, flags, mode)
						}
					} else if syscallNum == syscall.SYS_EXECVE {
						filename := readString(pid, uintptr(regs.Rdi))
						argv := readStringList(pid, uintptr(regs.Rsi))
						envp := readStringList(pid, uintptr(regs.Rdx))
						for _, listener := range pt.listeners {
							ppid := 0
							if proc.parent != nil {
								ppid = proc.parent.pid
							}
							listener.OnExecve(ProcessInfo{
								PID:     pid,
								PPID:    ppid,
								Comm:    proc.name,
								Exe:     proc.name,
								Cmdline: argv,
							}, filename, argv, envp)
						}
					} else if syscallNum == syscall.SYS_SYMLINK {
						oldpath := readString(pid, uintptr(regs.Rdi))
						newpath := readString(pid, uintptr(regs.Rsi))
						ppid := 0
						if proc.parent != nil {
							ppid = proc.parent.pid
						}
						for _, listener := range pt.listeners {
							listener.OnSymlink(ProcessInfo{
								PID:     pid,
								PPID:    ppid,
								Comm:    proc.name,
								Exe:     proc.name,
								Cmdline: []string{proc.name},
							}, oldpath, newpath)
						}
					} else if syscallNum == syscall.SYS_SYMLINKAT {
						oldpath := readString(pid, uintptr(regs.Rdi))
						newpath := readString(pid, uintptr(regs.Rdx))
						ppid := 0
						if proc.parent != nil {
							ppid = proc.parent.pid
						}
						for _, listener := range pt.listeners {
							listener.OnSymlink(ProcessInfo{
								PID:     pid,
								PPID:    ppid,
								Comm:    proc.name,
								Exe:     proc.name,
								Cmdline: []string{proc.name},
							}, oldpath, newpath)
						}
					}

					// Handle fork/clone syscalls
					if syscallNum == syscall.SYS_CLONE || syscallNum == syscall.SYS_FORK || syscallNum == syscall.SYS_VFORK {
						childPid := int(regs.Rax)
						if childPid > 0 {
							pt.addProcess(childPid, proc.name, proc)
							fmt.Fprintf(os.Stderr, "New process spawned: %d (parent: %d)\n",
								childPid, pid)
						}
					}
				} else {
					fmt.Fprintf(os.Stderr, "failed to get registers in pid %d: %v\n", pid, err)
				}
			}

			if err := syscall.PtraceSyscall(pid, 0); err != nil {
				fmt.Fprintf(os.Stderr, "ptrace syscall failed: %v - pid: %d\n", err, pid)
			}
		}
	}

	return nil
}

// readString reads a null-terminated string from the traced process's memory
func readString(pid int, addr uintptr) string {
	var bytes []byte
	for {
		word := make([]byte, 8)
		_, err := syscall.PtracePeekData(pid, addr, word)
		if err != nil {
			return string(bytes)
		}

		for _, b := range word {
			if b == 0 {
				return string(bytes)
			}
			bytes = append(bytes, b)
		}
		addr += 8
	}
}

func readStringList(pid int, addr uintptr) []string {
	var retStrings []string
	for {
		s := readString(pid, addr)
		if s == "" {
			break
		}
		retStrings = append(retStrings, s)
		addr += 8
	}
	return retStrings
}

func CreatePtraceWatcher(cfg config.Config, metrics metricsmanager.MetricsManager,
	processManager processmanager.ProcessManagerClient, hostHashSensor hosthashsensor.HostHashSensorServiceInterface, hostRuleManager hostrulemanager.HostRuleManagerClient) (IPtraceWatcher, error) {
	// Save cfg, metrics, processManager, hostHashSensor, hostRuleManager
	pool, err := ants.NewPool(2)
	if err != nil {
		return nil, err
	}
	ptraceWatcher := &PtraceWatcher{
		cfg:              cfg,
		metrics:          metrics,
		processManager:   processManager,
		hostHashSensor:   hostHashSensor,
		hostRuleManager:  hostRuleManager,
		reportWorkerPool: pool,
	}
	return ptraceWatcher, nil
}

func (p *PtraceWatcher) Start(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: %s command [args...] ", os.Args[0])
	}

	if runtime.GOOS != "linux" {
		return fmt.Errorf("this program only works on Linux")
	}

	p.processTracer = NewProcessTracer([]SyscallEventListener{p})

	cmdName := args[0]
	cmdArgs := args[1:]

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return p.processTracer.trace(cmd)
}

func (p *PtraceWatcher) Stop() error {
	return nil
}

func (p *PtraceWatcher) OnOpen(processInfo ProcessInfo, filename string, flags int, mode int) {
	event := &events.OpenEvent{

		Event: traceopentype.Event{
			Pid:   uint32(processInfo.PID),
			Comm:  processInfo.Comm,
			Path:  filename,
			Flags: []string{fmt.Sprintf("%d", flags)},
			Mode:  fmt.Sprintf("%d", mode),
		},
	}
	p.reportWorkerPool.Submit(func() {
		p.hostRuleManager.ReportEvent(utils.OpenEventType, event)
	})
}

func (p *PtraceWatcher) OnExecve(processInfo ProcessInfo, filename string, argv []string, envp []string) {
	event := &events.ExecEvent{
		Event: tracerexectype.Event{
			Pid:  uint32(processInfo.PID),
			Ppid: uint32(processInfo.PPID),
			Comm: processInfo.Comm,
			Args: argv,
		},
	}
	p.reportWorkerPool.Submit(func() {
		p.hostRuleManager.ReportEvent(utils.ExecveEventType, event)
	})
}

func (p *PtraceWatcher) OnSymlink(processInfo ProcessInfo, oldpath string, newpath string) {
	event := &tracersymlinktype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Pid:     uint32(processInfo.PID),
		Comm:    processInfo.Comm,
		OldPath: oldpath,
		NewPath: newpath,
	}
	p.reportWorkerPool.Submit(func() {
		p.hostRuleManager.ReportEvent(utils.SymlinkEventType, event)
	})
}
