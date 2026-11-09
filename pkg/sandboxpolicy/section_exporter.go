package sandboxpolicy

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
)

type SectionExporterOptions struct {
	Capacity  int
	Receivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]
	// ResolveCgroup finds the binding of a verdict's cgroup (a container, or
	// a pod cgroup with no container fields). Nonblocking; return only
	// identities verified for this cgroup. A missing result leaves it absent.
	ResolveCgroup func(cgroupID uint64) (Binding, bool)
	// SlotPolicies returns the policies of a slot of one section gadget
	// instance (the verdict's Generation and Slot). Nonblocking.
	SlotPolicies func(section string, generation uint64, slot uint32) ([]CompiledPolicy, bool)
}

// SectionExporter is the bounded, best-effort queue of the privilege, network
// and file verdicts. It is separate from the exec VerdictExporter, so a
// section deny burst never drops an exec verdict; both deliver to the same
// receivers, each under its own key. Like VerdictExporter, ReportSection never
// blocks and never changes enforcement. Section events are not enriched.
type SectionExporter struct {
	options                                      SectionExporterOptions
	queue                                        chan SectionEvent
	mu                                           sync.Mutex
	stopped                                      bool
	started                                      atomic.Bool
	enqueued, delivered, dropped, receiverErrors atomic.Uint64
}

func NewSectionExporter(options SectionExporterOptions) (*SectionExporter, error) {
	if options.Capacity <= 0 || options.Capacity > MaxVerdictQueueCapacity {
		return nil, fmt.Errorf("section verdict queue capacity must be between 1 and %d", MaxVerdictQueueCapacity)
	}
	return &SectionExporter{options: options, queue: make(chan SectionEvent, options.Capacity)}, nil
}

// ReportSection adds the binding and the policies, then queues a copy: the
// producer keeps no memory shared with the queue.
func (e *SectionExporter) ReportSection(ctx context.Context, event SectionEvent) error {
	s := event.section()
	if e.options.ResolveCgroup != nil {
		if resolved, ok := e.options.ResolveCgroup(s.Verdict.CgroupID); ok && resolved.CgroupID == s.Verdict.CgroupID {
			s.Binding = resolved
		}
	}
	if e.options.SlotPolicies != nil {
		if policies, ok := e.options.SlotPolicies(s.Verdict.Section, s.Verdict.Generation, s.Verdict.Slot); ok {
			s.Verdict.Attribute(policies)
		}
	}
	copy := event.snapshot()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		e.dropped.Add(1)
		return ErrVerdictExporterStopped
	}
	if err := ctx.Err(); err != nil {
		e.dropped.Add(1)
		return err
	}
	select {
	case e.queue <- copy:
		e.enqueued.Add(1)
		return nil
	default:
		e.dropped.Add(1)
		return ErrVerdictQueueFull
	}
}

// Stats has no enrichment errors: section events are not enriched.
func (e *SectionExporter) Stats() ExporterStats {
	return ExporterStats{Enqueued: e.enqueued.Load(), Delivered: e.delivered.Load(), Dropped: e.dropped.Load(), ReceiverErrors: e.receiverErrors.Load()}
}

// Run delivers queued events until ctx ends. Start exactly one.
func (e *SectionExporter) Run(ctx context.Context) error {
	if !e.started.CompareAndSwap(false, true) {
		return fmt.Errorf("section exporter Run may only be called once")
	}
	defer func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.stopped = true
		for {
			select {
			case <-e.queue:
				e.dropped.Add(1)
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-e.queue:
			e.dispatch(event)
		}
	}
}

func (e *SectionExporter) dispatch(event SectionEvent) {
	var receivers mapset.Set[containerwatcher.GenericEventReceiver]
	if e.options.Receivers != nil {
		receivers, _ = e.options.Receivers.Load(event.GetEventType())
	}
	if receivers == nil || receivers.Cardinality() == 0 {
		e.dropped.Add(1)
		return
	}
	for _, receiver := range receivers.ToSlice() {
		copy := event.snapshot()
		err := guardReceiver(func() error {
			if enriched, ok := receiver.(containerwatcher.EnrichedEventReceiver); ok {
				s := copy.section()
				enriched.ReportEnrichedEvent(&events.EnrichedEvent{Event: copy, Timestamp: s.Verdict.Time, ContainerID: s.Binding.ContainerID, PID: s.Verdict.PID, MountNamespaceID: s.Binding.MountNamespace})
				return nil
			}
			if raw, ok := receiver.(containerwatcher.EventReceiver); ok {
				raw.ReportEvent(copy.GetEventType(), copy)
				return nil
			}
			return fmt.Errorf("unsupported section verdict receiver %T", receiver)
		})
		if err != nil {
			e.receiverErrors.Add(1)
		} else {
			e.delivered.Add(1)
		}
	}
}
