//go:build !sandbox_shared_qualification

package integration

import (
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

// withVerdictLog is receivers: the product build adds no verdict receiver.
func withVerdictLog(receivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]) *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]] {
	return receivers
}
