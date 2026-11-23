package integration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
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
		"recreated daemonset": {objects: []any{pod, ds(func(d *appsv1.DaemonSet) { d.UID = "ds-2" })}, want: false},
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
		w, err := ownDaemonSet(ctx, client, "kubescape", "node-agent-x")
		if (err != nil) != tc.err {
			t.Errorf("%s: err=%v, want error %v", name, err, tc.err)
			continue
		}
		if w == nil {
			continue
		}
		if got := w.uninstalling(ctx); got != tc.want {
			t.Errorf("%s: uninstalling=%v, want %v", name, got, tc.want)
		}
	}
}

// The watch decides when the fresh read at shutdown fails (an uninstall
// removed node-agent's RBAC): the DaemonSet it saw deleted means uninstall; a
// DaemonSet recreated under the same name means restart; nothing known keeps
// the pins.
func TestUninstallFromTheWatchWhenTheReadFails(t *testing.T) {
	ctx := t.Context()
	owner := metav1.OwnerReference{Kind: "DaemonSet", Name: "node-agent", UID: "ds-1"}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "node-agent-x", Namespace: "kubescape", OwnerReferences: []metav1.OwnerReference{owner}}}
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "node-agent", Namespace: "kubescape", UID: "ds-1"}}
	client := fake.NewSimpleClientset(pod, ds)
	w, err := watchOwnDaemonSet(ctx, client, "kubescape", "node-agent-x")
	if err != nil || w == nil {
		t.Fatalf("watch: %v %v", w, err)
	}
	defer w.stop()
	if !cache.WaitForCacheSync(ctx.Done(), w.informer.HasSynced) {
		t.Fatal("no sync")
	}
	// Every later read is refused, as after the RBAC is gone.
	client.PrependReactor("get", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "daemonsets"}, "node-agent", errors.New("rbac gone"))
	})
	if w.uninstalling(ctx) {
		t.Fatal("a running DaemonSet is a restart")
	}
	if err := client.AppsV1().DaemonSets("kubescape").Delete(ctx, "node-agent", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return w.uninstalling(ctx) }, "the watched delete must mean uninstall")
	recreated := ds.DeepCopy()
	recreated.UID = "ds-2"
	if _, err := client.AppsV1().DaemonSets("kubescape").Create(ctx, recreated, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !w.uninstalling(ctx) }, "a recreated DaemonSet keeps the pins")
	// No watch and no read: keep the pins.
	unknown := &daemonSetWatch{client: client, namespace: "kubescape", name: "node-agent", uid: "ds-1"}
	if unknown.uninstalling(ctx) {
		t.Fatal("nothing known must keep the pins")
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Review 9, S-c: after an uninstall decision the pins go before the backend
// closes (a SIGKILL at the end of the grace period must not leave them), and
// only once.
func TestUninstallRemovesThePinsBeforeTheBackendCloses(t *testing.T) {
	s, b := testService(t)
	removed := 0
	old := removeRestartPins
	removeRestartPins = func() error { removed++; return nil }
	t.Cleanup(func() { removeRestartPins = old })
	s.uninstallDecided, s.uninstall = true, true
	b.onClose = func() {
		if removed != 1 {
			t.Errorf("the backend closed before the pins were removed (%d)", removed)
		}
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if removed != 1 || b.closes != 1 {
		t.Fatalf("removed %d times, closed %d times", removed, b.closes)
	}
}

// Review 9, S-d: only a section that is off (no image) loses its pinned sets
// at start. A configured section that is unavailable (a failed host check)
// keeps them, and its status says so.
func TestUnavailableSectionKeepsItsPins(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"privilege/set1", "network/set1"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var removed []string
	old := removeSectionPins
	removeSectionPins = func(_ string, sections ...string) error { removed = append(removed, sections...); return nil }
	t.Cleanup(func() { removeSectionPins = old })
	kept := enableRestartSurvivalAt(root, map[string]restartSection{
		sandboxpolicy.SectionPrivilege: {nil, true},  // unavailable
		sandboxpolicy.SectionNetwork:   {nil, false}, // off
		sandboxpolicy.SectionFile:      {nil, true},  // unavailable, nothing pinned
	}, func(err error) { t.Error(err) })
	if !kept[sandboxpolicy.SectionPrivilege] || kept[sandboxpolicy.SectionFile] || len(kept) != 1 {
		t.Fatalf("kept %v", kept)
	}
	if len(removed) != 1 || removed[0] != sandboxpolicy.SectionNetwork {
		t.Fatalf("removed %v, want only the section that is off", removed)
	}
	if err := keptPins(errors.New("BPF LSM off"), true); err == nil || !strings.Contains(err.Error(), "kept and may still enforce") {
		t.Fatalf("status note: %v", err)
	}
}

// Review 10, minor 3: when the refresh loop does not stop within Close's
// context, the pins still go after an uninstall decision.
func TestUninstallRemovesThePinsWhenTheLoopDoesNotStop(t *testing.T) {
	s, _ := testService(t)
	removed := 0
	old := removeRestartPins
	removeRestartPins = func() error { removed++; return nil }
	t.Cleanup(func() { removeRestartPins = old })
	s.uninstallDecided, s.uninstall = true, true
	s.cancel = func() {} // the loop never joins: s.done stays open
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := s.Close(ctx); err == nil {
		t.Fatal("Close must report the context error")
	}
	if removed != 1 {
		t.Fatalf("the pins must be removed: %d", removed)
	}
}
