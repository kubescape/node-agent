package ruleadapters

import (
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleadapters/adapters"
	"github.com/kubescape/node-agent/pkg/utils"
)

type EventRuleAdapterFactory struct {
	adapters map[utils.EventType]EventRuleAdapter
}

func NewEventRuleAdapterFactory() *EventRuleAdapterFactory {
	factory := &EventRuleAdapterFactory{
		adapters: make(map[utils.EventType]EventRuleAdapter),
	}
	factory.registerAllAdapters()
	return factory
}

func (f *EventRuleAdapterFactory) GetAdapter(eventType utils.EventType) (EventRuleAdapter, bool) {
	adapter, exists := f.adapters[eventType]
	return adapter, exists
}

func (f *EventRuleAdapterFactory) RegisterAdapter(eventType utils.EventType, adapter EventRuleAdapter) {
	f.adapters[eventType] = adapter
}

func (f *EventRuleAdapterFactory) registerAllAdapters() {
	f.RegisterAdapter(utils.ExecveEventType, adapters.NewExecAdapter())
	f.RegisterAdapter(utils.OpenEventType, adapters.NewOpenAdapter())
	f.RegisterAdapter(utils.CapabilitiesEventType, adapters.NewCapabilitiesAdapter())
	f.RegisterAdapter(utils.DnsEventType, adapters.NewDnsAdapter())
	f.RegisterAdapter(utils.NetworkEventType, adapters.NewNetworkAdapter())
	f.RegisterAdapter(utils.SyscallEventType, adapters.NewSyscallAdapter())
	f.RegisterAdapter(utils.SymlinkEventType, adapters.NewSymlinkAdapter())
	f.RegisterAdapter(utils.KmodEventType, adapters.NewKmodAdapter())
	f.RegisterAdapter(utils.HardlinkEventType, adapters.NewHardlinkAdapter())
	f.RegisterAdapter(utils.SSHEventType, adapters.NewSSHAdapter())
	f.RegisterAdapter(utils.HTTPEventType, adapters.NewHTTPAdapter())
	f.RegisterAdapter(utils.PtraceEventType, adapters.NewPtraceAdapter())
	f.RegisterAdapter(utils.IoUringEventType, adapters.NewIoUringAdapter())
	f.RegisterAdapter(utils.KubeletTLSEventType, adapters.NewKubeletTLSAdapter())
	f.RegisterAdapter(utils.RandomXEventType, adapters.NewRandomXAdapter())
	f.RegisterAdapter(utils.UnshareEventType, adapters.NewUnshareAdapter())
	f.RegisterAdapter(utils.BpfEventType, adapters.NewBpfAdapter())
}
