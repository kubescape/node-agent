package containerwatcher

import (
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/stretchr/testify/assert"
)

const (
	TestImageTAG       = "docker-pullable://k8s.gcr.io/etcd"
	TestContainerID    = "e1da74f71370d61564cbc746996e3f534d4c61ce3e7e7627b1f2543999e3cf7a"
	TestContainerName  = "blabla"
	TestK8sContainerID = "any/aaa/contName"
	TestWLID           = "wlid://cluster-name/namespace-any/deployment-aaa"
	TestInstanceIDHash = "fb7c6f65d5ede71f7dd6dc43b63261295ce26a2898d8517c23c6f171cc3865ce"
)

func TestContainerEvent(t *testing.T) {
	instanceid := instanceidhandler.InstanceID{}
	instanceid.SetAPIVersion("apps/v1")
	instanceid.SetNamespace("any")
	instanceid.SetKind("deployment")
	instanceid.SetName("aaa")
	instanceid.SetContainerName("contName")
	cont := &containercollection.Container{
		ID:        TestContainerID,
		Name:      TestContainerName,
		Namespace: "any",
		Podname:   "aaa",
	}
	contEv := CreateNewContainerEvent(cont, "", TestImageTAG, TestK8sContainerID, TestWLID, &instanceid)
	assert.Equal(t, contEv.GetK8SContainerID(), TestK8sContainerID)
	assert.Equal(t, contEv.GetContainerID(), TestContainerID)
	assert.Equal(t, contEv.GetK8SWorkloadID(), TestWLID)
	assert.Equal(t, contEv.GetContainerName(), TestContainerName)
	assert.Equal(t, contEv.GetInstanceID(), &instanceid)
	assert.Equal(t, contEv.GetInstanceIDHash(), TestInstanceIDHash)
	assert.Equal(t, contEv.GetImageTAG(), TestImageTAG)
	assert.Equal(t, contEv.GetNamespace(), "any")
	assert.Equal(t, contEv.GetPodName(), "aaa")
}
