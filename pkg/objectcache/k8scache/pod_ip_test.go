package k8scache

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func indexedPod(name, uid, ip string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID(uid)}, Status: corev1.PodStatus{PodIP: ip}}
}

func TestPodIPIndexLifecycle(t *testing.T) {
	k := &K8sObjectCacheImpl{}
	ctx := context.Background()
	pod := indexedPod("pod", "first", "10.0.0.1")
	pod.Status.PodIPs = []corev1.PodIP{{IP: "10.0.0.1"}, {IP: "fd00::1"}}
	assert.Nil(t, k.GetPodByIP("10.0.0.1"))
	k.AddHandler(ctx, pod)
	assert.Same(t, pod, k.GetPodByIP("10.0.0.1"))
	assert.Same(t, pod, k.GetPodByIP("fd00::1"))
	assert.Nil(t, k.GetPodByIP(""))
	updated := pod.DeepCopy()
	updated.Status.PodIP = "10.0.0.2"
	updated.Status.PodIPs = nil
	k.ModifyHandler(ctx, updated)
	assert.Nil(t, k.GetPodByIP("10.0.0.1"))
	assert.Nil(t, k.GetPodByIP("fd00::1"))
	assert.Same(t, updated, k.GetPodByIP("10.0.0.2"))
	// Delete payloads may predate the latest status update.
	k.DeleteHandler(ctx, pod)
	assert.Nil(t, k.GetPodByIP("10.0.0.2"))
	assert.Nil(t, k.GetPod("default", "pod"))
}

func TestPodIPIndexReuse(t *testing.T) {
	for _, sameName := range []bool{false, true} {
		t.Run(map[bool]string{false: "different pods", true: "recreated pod"}[sameName], func(t *testing.T) {
			k := &K8sObjectCacheImpl{}
			ctx := context.Background()
			old := indexedPod("old", "first", "10.0.0.1")
			replacement := indexedPod("new", "second", old.Status.PodIP)
			if sameName {
				replacement.Name = old.Name
			}
			k.AddHandler(ctx, old)
			k.AddHandler(ctx, replacement)
			k.DeleteHandler(ctx, old)
			assert.Same(t, replacement, k.GetPodByIP(old.Status.PodIP))
			assert.Same(t, replacement, k.GetPod("default", replacement.Name))
			k.DeleteHandler(ctx, replacement)
			assert.Nil(t, k.GetPodByIP(old.Status.PodIP))
		})
	}
}

func TestPodIPIndexUpdatePreservesReusedIP(t *testing.T) {
	k := &K8sObjectCacheImpl{}
	ctx := context.Background()
	old := indexedPod("old", "first", "10.0.0.1")
	replacement := indexedPod("new", "second", "10.0.0.1")
	k.AddHandler(ctx, old)
	k.AddHandler(ctx, replacement)
	updated := old.DeepCopy()
	updated.Status.PodIP = ""
	updated.Status.PodIPs = []corev1.PodIP{{IP: "fd00::1"}, {IP: ""}}
	k.ModifyHandler(ctx, updated)
	assert.Same(t, replacement, k.GetPodByIP("10.0.0.1"))
	assert.Same(t, updated, k.GetPodByIP("fd00::1"))
	assert.Nil(t, k.GetPodByIP(""))
	k.DeleteHandler(ctx, updated)
	assert.Same(t, replacement, k.GetPodByIP("10.0.0.1"))
	assert.Nil(t, k.GetPodByIP("fd00::1"))
}

func TestPodIPIndexConcurrentAccess(t *testing.T) {
	k := &K8sObjectCacheImpl{}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pod := indexedPod("pod", "uid", "10.0.0.1")
			for j := 0; j < 100; j++ {
				k.AddHandler(context.Background(), pod)
				k.GetPodByIP(pod.Status.PodIP)
				k.ModifyHandler(context.Background(), pod)
				k.DeleteHandler(context.Background(), pod)
			}
		}()
	}
	wg.Wait()
}

func TestPodIPIndexRetainedReassignedIP(t *testing.T) {
	for _, secondary := range []bool{false, true} {
		t.Run(map[bool]string{false: "primary", true: "secondary"}[secondary], func(t *testing.T) {
			k := &K8sObjectCacheImpl{}
			ctx := context.Background()
			ip := "10.0.0.1"
			old := indexedPod("old", "first", ip)
			if secondary {
				ip = "fd00::1"
				old.Status.PodIPs = []corev1.PodIP{{IP: old.Status.PodIP}, {IP: ip}}
			}
			replacement := indexedPod("new", "second", ip)
			k.AddHandler(ctx, old)
			k.AddHandler(ctx, replacement)
			updated := old.DeepCopy()
			updated.Labels = map[string]string{"updated": "true"}
			k.ModifyHandler(ctx, updated)
			assert.Same(t, replacement, k.GetPodByIP(ip))
			k.DeleteHandler(ctx, updated)
			assert.Same(t, replacement, k.GetPodByIP(ip))
		})
	}
}

func TestPodIPIndexNewAssignmentTakesOwnership(t *testing.T) {
	k := &K8sObjectCacheImpl{}
	ctx := context.Background()
	old := indexedPod("old", "first", "10.0.0.1")
	replacement := indexedPod("new", "second", "10.0.0.2")
	k.AddHandler(ctx, old)
	k.AddHandler(ctx, replacement)
	updated := replacement.DeepCopy()
	updated.Status.PodIP = old.Status.PodIP
	k.ModifyHandler(ctx, updated)
	assert.Same(t, updated, k.GetPodByIP(old.Status.PodIP))
	assert.Nil(t, k.GetPodByIP(replacement.Status.PodIP))
	recreated := indexedPod(replacement.Name, "third", old.Status.PodIP)
	k.AddHandler(ctx, recreated)
	assert.Same(t, recreated, k.GetPodByIP(old.Status.PodIP))
}
