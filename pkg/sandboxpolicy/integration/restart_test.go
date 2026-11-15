package integration

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// Shutdown tells an uninstall (the DaemonSet is gone or being deleted: remove
// the pinned sets) from a restart (keep them).
func TestUninstallingFollowsTheDaemonSet(t *testing.T) {
	ctx := context.Background()
	owner := metav1.OwnerReference{Kind: "DaemonSet", Name: "node-agent", UID: "ds-1"}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "node-agent-x", Namespace: "kubescape", OwnerReferences: []metav1.OwnerReference{owner}}}
	ds := func(mut func(*appsv1.DaemonSet)) *appsv1.DaemonSet {
		d := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "node-agent", Namespace: "kubescape", UID: "ds-1"}}
		if mut != nil {
			mut(d)
		}
		return d
	}
	now := metav1.Now()
	for name, tc := range map[string]struct {
		objects []any
		want    bool
		err     bool
	}{
		"restart or rollout":  {objects: []any{pod, ds(nil)}},
		"daemonset deleted":   {objects: []any{pod}, want: true},
		"daemonset deleting":  {objects: []any{pod, ds(func(d *appsv1.DaemonSet) { d.DeletionTimestamp = &now; d.Finalizers = []string{"x"} })}, want: true},
		"recreated daemonset": {objects: []any{pod, ds(func(d *appsv1.DaemonSet) { d.UID = "ds-2" })}, want: true},
		"pod unreadable":      {objects: nil, err: true},
	} {
		client := fake.NewSimpleClientset()
		for _, o := range tc.objects {
			switch v := o.(type) {
			case *corev1.Pod:
				_, _ = client.CoreV1().Pods(v.Namespace).Create(ctx, v, metav1.CreateOptions{})
			case *appsv1.DaemonSet:
				_, _ = client.AppsV1().DaemonSets(v.Namespace).Create(ctx, v, metav1.CreateOptions{})
			}
		}
		got, err := uninstalling(ctx, client, "kubescape", "node-agent-x")
		if got != tc.want || (err != nil) != tc.err {
			t.Errorf("%s: uninstalling=%v err=%v, want %v (error %v)", name, got, err, tc.want, tc.err)
		}
	}
}
