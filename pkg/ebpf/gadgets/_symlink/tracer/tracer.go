//go:build !withoutebpf

package tracer

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/_symlink/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -strip /usr/bin/llvm-strip-18  -cc /usr/bin/clang -cflags "-g -O2 -Wall -D __TARGET_ARCH_x86" -type event symlink bpf/symlink.bpf.c -- -I./bpf/

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config *Config
	//enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs symlinkObjects

	symlinkLink   link.Link
	symlinkatLink link.Link
	reader        *perf.Reader

	// recordPool will pool perf.Record objects to avoid allocations.
	recordPool sync.Pool
}

func NewTracer(config *Config, //enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config: config,
		//enricher:      enricher,
		eventCallback: eventCallback,
	}

	t.recordPool.New = func() any {
		return new(perf.Record)
	}

	if err := t.install(); err != nil {
		t.close()
		return nil, err
	}

	go t.run()

	return t, nil
}

// Stop stops the tracer
// TODO: Remove after refactoring
func (t *Tracer) Stop() {
	t.close()
}

func (t *Tracer) close() {
	if runtime.GOARCH != "arm64" {
		t.symlinkLink = gadgets.CloseLink(t.symlinkLink)
	}
	t.symlinkatLink = gadgets.CloseLink(t.symlinkatLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	var err error
	//spec, err := loadSymlink()
	//if err != nil {
	//	return fmt.Errorf("loading ebpf program: %w", err)
	//}

	//if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, nil, &t.objs); err != nil {
	//	return fmt.Errorf("loading ebpf spec: %w", err)
	//}

	if runtime.GOARCH != "arm64" {
		t.symlinkLink, err = link.Tracepoint("syscalls", "sys_enter_symlink", t.objs.TracepointSysSymlink, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint: %w", err)
		}
	}

	t.symlinkatLink, err = link.Tracepoint("syscalls", "sys_enter_symlinkat", t.objs.TracepointSysSymlinkat, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}

	t.reader, err = perf.NewReader(t.objs.symlinkMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf ring buffer: %w", err)
	}

	return nil
}

func (t *Tracer) run() {
	for {
		record := t.recordPool.Get().(*perf.Record)
		err := t.reader.ReadInto(record)
		if err != nil {
			t.recordPool.Put(record)
			if errors.Is(err, perf.ErrClosed) {
				// nothing to do, we're done
				return
			}

			//msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			//t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if record.LostSamples > 0 {
			//msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			//t.eventCallback(types.Base(eventtypes.Warn(msg)))
			t.recordPool.Put(record)
			continue
		}

		bpfEvent := (*symlinkEvent)(unsafe.Pointer(&record.RawSample[0]))

		// Check if we have seen enough events for this mntns
		event := types.Event{
			//Event: eventtypes.Event{
			//	Type:      eventtypes.NORMAL,
			//	Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			//},
			//WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
			Pid:        bpfEvent.Pid,
			Tid:        bpfEvent.Tid,
			PPid:       bpfEvent.Ppid,
			Uid:        bpfEvent.Uid,
			Gid:        bpfEvent.Gid,
			UpperLayer: bpfEvent.UpperLayer,
			Comm:       gadgets.FromCString(bpfEvent.Comm[:]),
			ExePath:    gadgets.FromCString(bpfEvent.Exepath[:]),
			OldPath:    gadgets.FromCString(bpfEvent.Oldpath[:]),
			NewPath:    gadgets.FromCString(bpfEvent.Newpath[:]),
		}

		//if t.enricher != nil {
		//	t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		//}

		t.eventCallback(&event)
		t.recordPool.Put(record)
	}
}

// --- Registry changes

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	go t.run()
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.config.MountnsMap = mountnsMap
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		logger.L().Fatal("symlink Tracer.SetEventHandler - invalid event handler", helpers.Interface("handler", handler))
	}
	t.eventCallback = nh
}
