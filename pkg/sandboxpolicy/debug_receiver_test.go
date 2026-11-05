package sandboxpolicy

import (
	"strings"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

func TestRegisterDebugReceiverKeepsOtherReceivers(t *testing.T) {
	receivers := maps.NewSafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]()
	other := &dispatchKeyReceiver{received: make(chan utils.EventType, 1)}
	receivers.Set(utils.ExecAuthorizationEventType, mapset.NewSet[containerwatcher.GenericEventReceiver](other))
	RegisterDebugReceiver(receivers)
	for _, key := range AuthorizationEventTypes {
		set, ok := receivers.Load(key)
		if !ok || !set.Contains(DebugReceiver{}) {
			t.Fatalf("no debug receiver under %q", key)
		}
	}
	if set, _ := receivers.Load(utils.ExecAuthorizationEventType); !set.Contains(other) || set.Cardinality() != 2 {
		t.Fatal("registration replaced an existing receiver")
	}
	if _, ok := receivers.Load(utils.ExecveEventType); ok {
		t.Fatal("debug receiver must not observe ordinary exec")
	}
}

func TestDebugReceiverLogsExportedEvents(t *testing.T) {
	v := NewSectionVerdict(SectionFile, 1, 12, 1, 41, 0, false, "ns/a/r", originPtr("custom/a/r"), "cat")
	for _, c := range []struct {
		event utils.K8sEvent
		want  []string
	}{
		{NewExecVerdictEvent(sampleVerdict(), binding()), []string{`"TargetPath":"/bin/target"`, `"ContainerID":"container"`}},
		{NewPrivilegeVerdictEvent(v, binding(), PrivilegeTarget{Syscall: "unshare", Capability: 21}), []string{`"Syscall":"unshare"`, `"WouldDeny":true`}},
		{NewNetworkVerdictEvent(v, binding(), NetworkTarget{Addr: "192.0.2.1", Port: 443}), []string{`"Addr":"192.0.2.1"`, `"Rule":"ns/a/r"`}},
		{NewFileVerdictEvent(v, binding(), FileTarget{Access: "read", Path: "/etc/hostname"}), []string{`"Path":"/etc/hostname"`, `"Origins":["custom/a/r"]`}},
	} {
		line, err := debugLine(c.event)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range c.want {
			if !strings.Contains(line, w) {
				t.Errorf("%T line misses %s: %s", c.event, w, line)
			}
		}
	}
	// Through the exporter: the receiver gets the event under its own key.
	receivers := maps.NewSafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]()
	RegisterDebugReceiver(receivers)
	exporter, err := NewSectionExporter(SectionExporterOptions{Capacity: 1, Receivers: receivers})
	if err != nil {
		t.Fatal(err)
	}
	exporter.dispatch(NewFileVerdictEvent(v, binding(), FileTarget{}))
	if s := exporter.Stats(); s.Delivered != 1 || s.ReceiverErrors != 0 {
		t.Fatalf("stats %+v", s)
	}
}
