package sandboxpolicy

import (
	"encoding/json"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

// AuthorizationEventTypes are the dispatch keys of the exported authorizations.
var AuthorizationEventTypes = []utils.EventType{utils.ExecAuthorizationEventType, utils.PrivilegeAuthorizationEventType,
	utils.NetworkAuthorizationEventType, utils.FileAuthorizationEventType}

// DebugReceiver logs each exported authorization as one JSON line, for local
// tests without an exporter (config sandboxPolicyDebugExport).
type DebugReceiver struct{}

func (DebugReceiver) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	line, err := debugLine(event)
	if err != nil {
		logger.L().Warning("sandbox authorization export", helpers.String("type", string(eventType)), helpers.Error(err))
		return
	}
	logger.L().Info("sandbox authorization export", helpers.String("type", string(eventType)), helpers.String("event", line))
}

// debugLine is the event's decision, binding and target as JSON.
func debugLine(event utils.K8sEvent) (string, error) {
	var payload any = event
	switch e := event.(type) {
	case *ExecVerdictEvent:
		payload = struct{ Verdict, Binding any }{e.Verdict, e.Binding}
	case *PrivilegeVerdictEvent:
		payload = struct{ Verdict, Binding, Target any }{e.Verdict, e.Binding, e.Target}
	case *NetworkVerdictEvent:
		payload = struct{ Verdict, Binding, Target any }{e.Verdict, e.Binding, e.Target}
	case *FileVerdictEvent:
		payload = struct{ Verdict, Binding, Target any }{e.Verdict, e.Binding, e.Target}
	}
	line, err := json.Marshal(payload)
	return string(line), err
}

// RegisterDebugReceiver adds a DebugReceiver under every authorization key,
// next to the receivers already registered.
func RegisterDebugReceiver(receivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]) {
	for _, key := range AuthorizationEventTypes {
		set, ok := receivers.Load(key)
		if !ok {
			set = mapset.NewSet[containerwatcher.GenericEventReceiver]()
			receivers.Set(key, set)
		}
		set.Add(DebugReceiver{})
	}
}
