package conthandler

import (
	"testing"
)

const (
	TestImageID        = "docker-pullable://k8s.gcr.io/etcd@sha256:13f53ed1d91e2e11aac476ee9a0269fdda6cc4874eba903efd40daf50c55eee5"
	TestContainerID    = "e1da74f71370d61564cbc746996e3f534d4c61ce3e7e7627b1f2543999e3cf7a"
	TestPodName        = "blabla"
	TestWLID           = "wlid://cluster-name/namespace-any/deployment-aaa"
	TestInstanceID     = "apiVersion-v1/namespace-any/kind-deployment/name-aaa/resourceVersion-1234/containerName-contName"
	TestInstanceIDHash = "ee9bdd0adec9ce004572faf3492f583aa82042a8b3a9d5c7d9179dc03c531eef"
)

func TestContainerEvent(t *testing.T) {
	contEv := CreateNewContainerEvent(TestImageID, TestContainerID, TestPodName, TestWLID, TestInstanceID, ContainerRunning)
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
	if contEv.GetInstanceID() != TestInstanceID {
		t.Fatalf("fail to get container event instance ID")
	}
	if contEv.GetInstanceIDHash() != TestInstanceIDHash {
		t.Fatalf("fail to get container event instance ID hash")
	}
}
