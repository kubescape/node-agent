package relevancymanager

import (
	"node-agent/pkg/containerwatcher"
	"node-agent/pkg/sbom"
	"time"
)

type supportedServices string

type afterTimerActionsData struct {
	containerID string
	service     supportedServices
}

type watchedContainerData struct {
	snifferTicker  *time.Ticker
	event          containerwatcher.ContainerEvent
	syncChannel    map[string]chan error
	sbomClient     sbom.SBOMClient
	imageID        string
	k8sContainerID string
}
