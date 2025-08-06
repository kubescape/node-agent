package ruleadapters

import (
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleadapters/adapters"
	"github.com/kubescape/node-agent/pkg/utils"
)

// EventRuleAdapterFactory creates EventRuleAdapter instances for different event types
type EventRuleAdapterFactory struct {
	adapters map[utils.EventType]EventRuleAdapter
}

// NewEventRuleAdapterFactory creates a new factory with all supported event adapters registered
func NewEventRuleAdapterFactory() *EventRuleAdapterFactory {
	factory := &EventRuleAdapterFactory{
		adapters: make(map[utils.EventType]EventRuleAdapter),
	}
	factory.registerAllAdapters()
	return factory
}

// GetAdapter returns the EventRuleAdapter for the given event type
func (f *EventRuleAdapterFactory) GetAdapter(eventType utils.EventType) (EventRuleAdapter, bool) {
	adapter, exists := f.adapters[eventType]
	return adapter, exists
}

// RegisterAdapter registers an EventRuleAdapter for a specific event type
func (f *EventRuleAdapterFactory) RegisterAdapter(eventType utils.EventType, adapter EventRuleAdapter) {
	f.adapters[eventType] = adapter
}

// registerAllAdapters registers all the built-in event adapters
func (f *EventRuleAdapterFactory) registerAllAdapters() {
	f.RegisterAdapter(utils.ExecveEventType, adapters.NewExecAdapter())
	f.RegisterAdapter(utils.OpenEventType, adapters.NewOpenAdapter())
	f.RegisterAdapter(utils.CapabilitiesEventType, adapters.NewCapabilitiesAdapter())
	f.RegisterAdapter(utils.DnsEventType, adapters.NewDnsAdapter())
	f.RegisterAdapter(utils.NetworkEventType, adapters.NewNetworkAdapter())
	f.RegisterAdapter(utils.SyscallEventType, adapters.NewSyscallAdapter())
	f.RegisterAdapter(utils.SymlinkEventType, adapters.NewSymlinkAdapter())
	f.RegisterAdapter(utils.HardlinkEventType, adapters.NewHardlinkAdapter())
	f.RegisterAdapter(utils.SSHEventType, adapters.NewSSHAdapter())
	f.RegisterAdapter(utils.HTTPEventType, adapters.NewHTTPAdapter())
	f.RegisterAdapter(utils.PtraceEventType, adapters.NewPtraceAdapter())
	f.RegisterAdapter(utils.IoUringEventType, adapters.NewIoUringAdapter())
	f.RegisterAdapter(utils.RandomXEventType, adapters.NewRandomXAdapter())
}
