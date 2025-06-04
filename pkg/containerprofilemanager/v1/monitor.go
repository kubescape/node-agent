package containerprofilemanager

import (
	"github.com/kubescape/node-agent/pkg/utils"
)

func (cpm *ContainerProfileManager) monitorContainer(watchedContainer *utils.WatchedContainerData) {

	for {
		select {
		case <-watchedContainer.UpdateDataTicker.C:
			// Adjust ticker after first tick
			if !watchedContainer.InitialDelayExpired {
				watchedContainer.InitialDelayExpired = true
				watchedContainer.UpdateDataTicker.Reset(utils.AddJitter(cpm.cfg.UpdateDataPeriod, cpm.cfg.MaxJitterPercentage))
			}
			watchedContainer.SetStatus(utils.WatchedContainerStatusReady)
			cpm.saveProfile(ctx, watchedContainer, container.K8s.Namespace, nil)

			// save profile after initialaztion
			if initOps != nil {
				am.saveProfile(ctx, watchedContainer, container.K8s.Namespace, initOps)
				initOps = nil
			}
		case <-ctx.Done():
			// context cancelled, stop monitoring

		}
	}
}
