package conthandler

import (
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
)

const (
	TestImageTAG       = "docker-pullable://k8s.gcr.io/etcd"
	TestImageID        = "docker-pullable://k8s.gcr.io/etcd@sha256:13f53ed1d91e2e11aac476ee9a0269fdda6cc4874eba903efd40daf50c55eee5"
	TestContainerID    = "e1da74f71370d61564cbc746996e3f534d4c61ce3e7e7627b1f2543999e3cf7a"
	TestContainerName  = "blabla"
	TestWLID           = "wlid://cluster-name/namespace-any/deployment-aaa"
	TestInstanceID     = "apiVersion-apps/v1/namespace-any/kind-deployment/name-aaa/containerName-contName"
	TestInstanceIDHash = "fb7c6f65d5ede71f7dd6dc43b63261295ce26a2898d8517c23c6f171cc3865ce"
)

func TestContainerEvent(t *testing.T) {
	instanceid := instanceidhandler.InstanceID{}
	instanceid.SetAPIVersion("apps/v1")
	instanceid.SetNamespace("any")
	instanceid.SetKind("deployment")
	instanceid.SetName("aaa")
	instanceid.SetContainerName("contName")
	contEv := CreateNewContainerEvent(TestImageTAG, TestImageID, TestContainerID, TestContainerName, TestWLID, &instanceid, ContainerRunning)
	if contEv.GetContainerEventType() != ContainerRunning {
		t.Fatalf("fail to get container event type")
	}
	if contEv.GetContainerID() != TestContainerID {
		t.Fatalf("fail to get container event container ID")
	}
	if hash, err := contEv.GetImageHash(); err != nil && hash != "13f53ed1d91e2e11aac476ee9a0269fdda6cc4874eba903efd40daf50c55eee5" {
		t.Fatalf("fail to get container event image hash, err %v hash %s", err, hash)
	}
	if contEv.GetImageID() != TestImageID {
		t.Fatalf("fail to get container event image ID")
	}
	if instanceid.GetStringFormatted() != TestInstanceID {
		t.Fatalf("fail to get container event instance ID, get %s expected %s", instanceid.GetStringFormatted(), TestInstanceID)
	}
	if contEv.GetInstanceIDHash() != TestInstanceIDHash {
		t.Fatalf("fail to get container event instance ID hash, get %s, expected %s ", contEv.GetInstanceIDHash(), TestInstanceIDHash)
	}
	if contEv.GetK8SWorkloadID() != TestWLID {
		t.Fatalf("fail to get container event WLID, get %s, expected %s ", contEv.GetK8SWorkloadID(), TestWLID)
	}
	if contEv.GetContainerName() != TestContainerName {
		t.Fatalf("fail to get container event WLID, get %s, expected %s ", contEv.GetContainerName(), TestContainerName)
	}
	if contEv.GetInstanceID() != &instanceid {
		t.Fatalf("fail to get container event WLID, get %s, expected %s ", contEv.GetInstanceID(), instanceid)
	}

	contEvBadImageHash := CreateNewContainerEvent("456", "123", TestContainerID, TestContainerName, TestWLID, &instanceid, ContainerRunning)
	_, err := contEvBadImageHash.GetImageHash()
	if err == nil {
		t.Fatalf("image hash parser should fail")
	}

}
