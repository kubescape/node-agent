package tracers

import (
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

type captureDNSProfiler struct {
	containerprofilemanager.ContainerProfileManagerMock
	completed bool
	learned   []string
}

func (p *captureDNSProfiler) ReportDNSEvent(_ string, event utils.DNSEvent) {
	if !p.completed && event.GetQr() == utils.DNSPktTypeResponse && event.GetNumAnswers() > 0 && event.GetRcode() == "Success" {
		p.learned = append(p.learned, event.GetDNSName())
	}
}

type delayedDNSQueue struct{ events []utils.K8sEvent }

func (q *delayedDNSQueue) AddEventDirect(_ utils.EventType, event utils.K8sEvent, _ string, _ uint32) {
	q.events = append(q.events, event)
}

func TestDNSCaptureLearnsBeforeQueuedCompletionAndResolverDelay(t *testing.T) {
	for _, addresses := range [][]string{{"192.0.2.1"}, nil} {
		t.Run(fmt.Sprintf("response addresses=%d", len(addresses)), func(t *testing.T) {
			profiler := &captureDNSProfiler{}
			queue := &delayedDNSQueue{}
			factory := &TracerFactory{containerProfileManager: profiler, orderedEventQueue: queue}
			callback := factory.createEventCallback(utils.DnsEventType)
			event := &utils.StructEvent{DNSName: "learned.example.", Qr: utils.DNSPktTypeResponse, NumAnswers: 1, Rcode: "Success", Addresses: addresses}
			callback(event, "container", 1)
			require.Len(t, queue.events, 1)
			// The event is still queued, and a downstream addressless response can
			// additionally block on DNS resolution. Neither can postpone learning.
			require.Equal(t, []string{"learned.example."}, profiler.learned)
			profiler.completed = true
			// Delivery after completion does not need to teach this name again.
			profiler.ReportDNSEvent("container", queue.events[0].(utils.DNSEvent))
			callback(&utils.StructEvent{DNSName: "late.example.", Qr: utils.DNSPktTypeResponse, NumAnswers: 1, Rcode: "Success"}, "container", 1)
			require.Equal(t, []string{"learned.example."}, profiler.learned, "post-completion responses must remain excluded")
		})
	}
}
