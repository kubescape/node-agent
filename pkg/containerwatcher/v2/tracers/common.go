package tracers

import (
	"reflect"

	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

func EnrichEvent(thirdPartyEnricher containerwatcher.TaskBasedEnricher, event utils.EnrichEvent, syscalls []uint64, callback containerwatcher.ResultCallback,
	containerID string, processID uint32) {
	if thirdPartyEnricher != nil && !reflect.ValueOf(thirdPartyEnricher).IsNil() {
		thirdPartyEnricher.SubmitEnrichmentTask(event, syscalls, callback)
	} else {
		callback(event, containerID, processID)
	}

}
