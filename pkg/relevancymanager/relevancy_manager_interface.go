package relevancymanager

import (
	"errors"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

var (
	ContainerHasTerminatedError = errors.New("container has terminated")
	IncompleteSBOMError         = errors.New("incomplete SBOM")
)

type RelevancyManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ReportFileAccess(namespace, pod, container, file string)
}
