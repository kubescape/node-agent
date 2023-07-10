package relevancymanager

import (
	"node-agent/pkg/sbom"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/instanceidhandler"
)

type supportedServices string

type afterTimerActionsData struct {
	containerID string
	service     supportedServices
}

type watchedContainerData struct {
	snifferTicker  *time.Ticker
	container      *containercollection.Container
	syncChannel    map[string]chan error
	sbomClient     sbom.SBOMClient
	imageID        string
	instanceID     instanceidhandler.IInstanceID
	k8sContainerID string
}
