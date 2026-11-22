package integration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFenceCensusRetainsUnselectedSiblings(t *testing.T) {
	pod, ns, containers := bindingFixtures()
	client := fake.NewSimpleClientset(pod, ns)
	selected, err := SnapshotSelectedBindingsFromContainers(context.Background(), client, containers, "node", func(b sandboxpolicy.Binding) bool { return b.ContainerName == "app" })
	if err != nil || len(selected) != 1 {
		t.Fatalf("legacy selected: %+v %v", selected, err)
	}
	census, err := SnapshotFenceBindingsFromContainers(context.Background(), client, containers, "node")
	if err != nil || len(census.Members) != 3 || len(census.Pending) != 0 {
		t.Fatalf("census %+v: %v", census, err)
	}
	for i, b := range census.Members {
		if b.ContainerID != containers[i].Runtime.ContainerID || b.Kind == "" || b.PodLabels["app"] != "current" {
			t.Fatalf("unclassified member %+v", b)
		}
	}
}

func TestFenceCensusPendingRetainsIndividualIdentity(t *testing.T) {
	for _, test := range []string{"waiting", "exited", "deleted-pod", "missing-pod-uid"} {
		t.Run(test, func(t *testing.T) {
			pod, ns, containers := bindingFixtures()
			extra := *containers[0]
			extra.Runtime.ContainerID = strings.Repeat("d", 64)
			extra.CgroupID = 555
			switch test {
			case "exited":
				pod.Status.ContainerStatuses[0].LastTerminationState.Terminated = &corev1.ContainerStateTerminated{ContainerID: "containerd://" + extra.Runtime.ContainerID}
			case "deleted-pod":
				extra.K8s.PodUID = "deleted"
			case "missing-pod-uid":
				extra.K8s.PodUID = ""
			}
			census, err := SnapshotFenceBindingsFromContainers(context.Background(), fake.NewSimpleClientset(pod, ns), append(containers, &extra), "node")
			var pending *sandboxpolicy.BindingPendingError
			if !errors.As(err, &pending) || pending.Containers != 1 || len(census.Members) != 3 || len(census.Pending) != 1 {
				t.Fatalf("census %+v err %v", census, err)
			}
			hint := census.Pending[0]
			if hint.ContainerID != extra.Runtime.ContainerID || hint.CgroupID != 555 || hint.PodUID != types.UID(extra.K8s.PodUID) || hint.Kind != "" || hint.PodLabels != nil {
				t.Fatalf("incorrect/untrusted hint %+v", hint)
			}
		})
	}
}

func TestFenceCensusRejectsIncompleteSiblings(t *testing.T) {
	for _, test := range []string{"missing-runtime", "nil-runtime", "duplicate-cgroup", "invalid-runtime", "bad-namespace"} {
		t.Run(test, func(t *testing.T) {
			pod, ns, containers := bindingFixtures()
			switch test {
			case "missing-runtime":
				containers = containers[:2]
			case "nil-runtime":
				containers = append(containers, nil)
			case "duplicate-cgroup":
				containers[1].CgroupID = containers[0].CgroupID
			case "invalid-runtime":
				pod.Status.InitContainerStatuses[0].ContainerID = "broken"
			case "bad-namespace":
				ns.Name = "other"
			}
			census, err := SnapshotFenceBindingsFromContainers(context.Background(), fake.NewSimpleClientset(pod, ns), containers, "node")
			if err == nil || len(census.Members) != 0 || len(census.Pending) != 0 {
				t.Fatalf("incomplete census authorized members: %+v %v", census, err)
			}
		})
	}
}

func TestFenceCensusCollectionUnavailable(t *testing.T) {
	if _, err := SnapshotFenceBindings(context.Background(), nil, nil, "node"); err == nil {
		t.Fatal("nil collection accepted")
	}
	var containers []*containercollection.Container
	if _, err := SnapshotFenceBindingsFromContainers(context.Background(), nil, containers, "node"); err == nil {
		t.Fatal("nil client accepted")
	}
}

const fenceTestUID = "12345678-abcd-4321-abcd-123456789012"

func TestFenceCgroupPaths(t *testing.T) {
	systemUID := strings.ReplaceAll(fenceTestUID, "-", "_")
	for _, pod := range []string{
		"/kubepods/pod" + fenceTestUID,
		"/kubepods/burstable/pod" + fenceTestUID,
		"/custom/kubepods/besteffort/pod" + fenceTestUID,
		"/kubepods.slice/kubepods-pod" + systemUID + ".slice",
		"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + systemUID + ".slice",
		"/custom/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + systemUID + ".slice",
	} {
		t.Run(pod, func(t *testing.T) {
			got, child, err := fenceCgroupPaths(fenceTestUID, pod+"/container/subgroup")
			if err != nil || got != pod || child != "container/subgroup" {
				t.Fatalf("got %q %q: %v", got, child, err)
			}
		})
	}
}
func TestFenceCgroupPathsRejectUnverifiedAncestry(t *testing.T) {
	for _, p := range []string{
		"", "/", "kubepods/pod" + fenceTestUID + "/child", "/kubepods/pod" + fenceTestUID,
		"/elsewhere/pod" + fenceTestUID + "/child", "/kubepods/podother/child",
		"/kubepods//pod" + fenceTestUID + "/child", "/kubepods/../kubepods/pod" + fenceTestUID + "/child",
		"/kubepods/pod" + fenceTestUID + "/kubepods/pod" + fenceTestUID + "/child",
		"/kubepods.slice/kubepods-burstable.slice/kubepods-besteffort-pod" + strings.ReplaceAll(fenceTestUID, "-", "_") + ".slice/child",
	} {
		if _, _, err := fenceCgroupPaths(fenceTestUID, p); err == nil {
			t.Errorf("accepted %q", p)
		}
	}
	for _, uid := range []string{"", "../x", "pod-uid", strings.ToUpper(fenceTestUID)} {
		if _, _, err := fenceCgroupPaths(uid, "/kubepods/pod"+uid+"/child"); err == nil {
			t.Errorf("accepted UID %q", uid)
		}
	}
}

func TestOpenFenceCgroupsRejectsOrdinaryFilesystemAndSymlinks(t *testing.T) {
	root := t.TempDir()
	b := sandboxpolicy.Binding{PodUID: types.UID(fenceTestUID), CgroupID: 123, CgroupPath: "/kubepods/pod" + fenceTestUID + "/child"}
	if c, err := OpenFenceCgroups(root, b); err == nil {
		c.Close()
		t.Fatal("ordinary filesystem accepted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if c, err := OpenFenceCgroups(link, b); err == nil {
		c.Close()
		t.Fatal("symlink root accepted")
	}
	for _, badRoot := range []string{"", ".", root + "/../" + filepath.Base(root)} {
		if c, err := OpenFenceCgroups(badRoot, b); err == nil {
			c.Close()
			t.Fatalf("bad root %q accepted", badRoot)
		}
	}
}
