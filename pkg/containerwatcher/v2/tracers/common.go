package tracers

import (
	"reflect"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	SYS_LINKAT    = 265
	SYS_LINK      = 86
	SYS_SYMLINKAT = 266
	SYS_SYMLINK   = 88
	SYS_OPEN      = 2
	SYS_OPENAT    = 257
	SYS_FORK      = 57
)

func EnrichEvent(thirdPartyEnricher containerwatcher.TaskBasedEnricher, event utils.EnrichEvent, syscalls []uint64, callback containerwatcher.ResultCallback,
	containerID string, processID uint32) {
	if thirdPartyEnricher != nil && !reflect.ValueOf(thirdPartyEnricher).IsNil() {
		thirdPartyEnricher.SubmitEnrichmentTask(event, syscalls, callback, containerID, processID)
	} else {
		callback(event, containerID, processID)
	}

}

func isDroppedEvent(eventType types.EventType, message string) bool {
	return eventType != types.NORMAL &&
		eventType != types.DEBUG &&
		strings.Contains(message, "stop tracing container")
}
