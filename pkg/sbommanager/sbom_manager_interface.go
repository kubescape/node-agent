package sbommanager

import containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"

type SbomManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
}
