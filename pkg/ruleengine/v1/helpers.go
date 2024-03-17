package ruleengine

import (
	"fmt"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func getExecPathFromEvent(event *tracerexectype.Event) string {
	if len(event.Args) > 0 {
		return event.Args[0]
	}
	return event.Comm
}
func getContainerFromApplicationProfile(ap *v1beta1.ApplicationProfile, containerName string) (v1beta1.ApplicationProfileContainer, error) {
	for i := range ap.Spec.Containers {
		if ap.Spec.Containers[i].Name == containerName {
			return ap.Spec.Containers[i], nil
		}
	}
	for i := range ap.Spec.InitContainers {
		if ap.Spec.InitContainers[i].Name == containerName {
			return ap.Spec.InitContainers[i], nil
		}
	}
	return v1beta1.ApplicationProfileContainer{}, fmt.Errorf("container %s not found in application profile", containerName)
}
