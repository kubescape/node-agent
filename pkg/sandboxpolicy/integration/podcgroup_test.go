package integration

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const testPodUID = types.UID("0f3c2a1b-1111-2222-3333-444455556666")

func TestPodCgroupLayout(t *testing.T) {
	u := "0f3c2a1b_1111_2222_3333_444455556666"
	other := types.UID("9e8d7c6b-aaaa-bbbb-cccc-ddddeeeeffff")
	o := "9e8d7c6b_aaaa_bbbb_cccc_ddddeeeeffff"
	for _, tc := range []struct {
		name, container string
		want            map[corev1.PodQOSClass]string
	}{
		{"systemd besteffort", "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + u + ".slice/cri-containerd-abc.scope", map[corev1.PodQOSClass]string{
			corev1.PodQOSBestEffort: "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + o + ".slice",
			corev1.PodQOSBurstable:  "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + o + ".slice",
			corev1.PodQOSGuaranteed: "/kubepods.slice/kubepods-pod" + o + ".slice",
		}},
		{"systemd guaranteed, kind root", "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod" + u + ".slice/cri-containerd-abc.scope", map[corev1.PodQOSClass]string{
			corev1.PodQOSBurstable:  "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod" + o + ".slice",
			corev1.PodQOSGuaranteed: "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod" + o + ".slice",
		}},
		{"cgroupfs burstable", "/kubepods/burstable/pod" + string(testPodUID) + "/abc", map[corev1.PodQOSClass]string{
			corev1.PodQOSBestEffort: "/kubepods/besteffort/pod" + string(other),
			corev1.PodQOSGuaranteed: "/kubepods/pod" + string(other),
		}},
		{"cgroupfs guaranteed", "/kubepods/pod" + string(testPodUID) + "/abc", map[corev1.PodQOSClass]string{
			corev1.PodQOSBurstable: "/kubepods/burstable/pod" + string(other),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout, ok := learnPodCgroupLayout(tc.container, testPodUID)
			if !ok {
				t.Fatalf("layout not learned from %s", tc.container)
			}
			for qos, want := range tc.want {
				if got := layout.path(other, qos); got != want {
					t.Errorf("%s: got %s, want %s", qos, got, want)
				}
			}
			if got := layout.path(other, ""); got != "" {
				t.Errorf("unknown QoS class must give no path: %s", got)
			}
		})
	}
}

func TestPodCgroupLayoutRefusesOtherPaths(t *testing.T) {
	for _, path := range []string{
		"/system.slice/docker-abc.scope",
		"/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podother.slice/cri-containerd-abc.scope",
		"kubepods/pod" + string(testPodUID),
		"/kubepods/../pod" + string(testPodUID),
		"/pod" + string(testPodUID),
	} {
		if layout, ok := learnPodCgroupLayout(path, testPodUID); ok {
			t.Errorf("%s: unexpected layout %+v", path, layout)
		}
	}
	if _, ok := learnPodCgroupLayout("/kubepods/pod"+string(testPodUID), ""); ok {
		t.Error("a container without a pod UID must not give a layout")
	}
	if got := (podCgroupLayout{root: "/kubepods"}).path("a/b", corev1.PodQOSGuaranteed); got != "" {
		t.Errorf("a UID with a separator must give no path: %s", got)
	}
}
