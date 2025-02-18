package hostnetworksensor

import (
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/cenkalti/backoff/v4"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	hostPID = 1
)

func (hns *HostNetworkSensor) setProcessTree(event *NetworkScanResult) error {
	err := backoff.Retry(func() error {
		tree, err := hns.processManager.GetProcessTreeForPID(
			event.GetRuntimeProcessDetails().ContainerID,
			int(event.GetRuntimeProcessDetails().ProcessTree.PID),
		)
		if err != nil {
			return err
		}
		event.ProcessDetails.ProcessTree = tree
		return nil
	}, backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(50*time.Millisecond),
		backoff.WithMaxInterval(200*time.Millisecond),
		backoff.WithMaxElapsedTime(500*time.Millisecond),
	))

	if err != nil {
		if tree, err := utils.CreateProcessTree(&event.ProcessDetails.ProcessTree, hostPID); err == nil {
			if tree != nil {
				event.ProcessDetails.ProcessTree = *tree
			} else {
				event.ProcessDetails = apitypes.ProcessTree{
					ProcessTree: apitypes.Process{
						PID: uint32(event.Pid),
					},
				}
			}
		}
	}

	return nil
}
