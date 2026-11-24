package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ktesting "k8s.io/client-go/testing"
)

const testExemptionKey = "sandbox.kubescape.io/exempt"

// fakePods is the informer view of the pods, for a PodSource.
type fakePods struct {
	pods    map[string]PodFacts
	epoch   atomic.Uint64
	lookups atomic.Int64
	// fetched, when set, is what Fetch returns.
	fetched *PodFacts
	fetches atomic.Int64
}

func newFakePods(pods map[string]PodFacts) *fakePods { return &fakePods{pods: pods} }

func (f *fakePods) source() PodSource {
	src := PodSource{
		ExemptionKey: testExemptionKey,
		InputEpoch:   f.epoch.Load,
		Lookup: func(namespace, name string) (PodFacts, bool) {
			f.lookups.Add(1)
			p, ok := f.pods[namespace+"/"+name]
			return p, ok
		},
	}
	if f.fetched != nil {
		src.Fetch = func(context.Context, string, string) (PodFacts, bool) {
			f.fetches.Add(1)
			return *f.fetched, true
		}
	}
	return src
}

// testPod returns the NRI view and the informer view of a pod with one
// regular container "app" and the label app=test.
func testPod(namespace, name string) (NRIPod, PodFacts) {
	uid := types.UID(namespace + "-" + name + "-uid")
	return NRIPod{UID: uid, Namespace: namespace, Name: name, Annotations: map[string]string{configSourceAnnotation: "api"}},
		PodFacts{UID: uid, Labels: map[string]string{"app": "test"}, Containers: []PodContainer{{Name: "app", Kind: "regular"}}, NamespaceLabels: map[string]string{"team": "red"}}
}

func classifyOne(t *testing.T, c *Controller, pod NRIPod, facts PodFacts) PodClassification {
	t.Helper()
	pods := newFakePods(map[string]PodFacts{pod.Namespace + "/" + pod.Name: facts})
	return c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod}, pods.source())
}

func syncedController(t *testing.T, objects ...runtime.Object) *Controller {
	t.Helper()
	c, _, _, _ := setup(t, objects...)
	_ = c.InitialSync(context.Background())
	return c
}

func privPolicy(name, namespace string) *api.SandboxPolicy {
	p := policy(name, namespace)
	p.Spec.Privilege = privilegeSection(api.ActionDeny)
	return p
}

func TestClassifyNilSnapshotIsUnknown(t *testing.T) {
	c, _, _, _ := setup(t, privPolicy("priv", "ns"))
	pod, facts := testPod("ns", "pod")
	got := classifyOne(t, c, pod, facts)
	if got.Class != PodUnknown || !strings.Contains(got.Reason, "snapshot") {
		t.Fatalf("before the first reconcile: %+v", got)
	}
	if plans, ok := c.PodPlans([]Binding{{PodUID: facts.UID, Namespace: "ns", PodName: "pod", ContainerName: "app", Kind: "regular"}}); ok || plans != nil {
		t.Fatalf("PodPlans before the first reconcile: %+v %v", plans, ok)
	}
	var zero PodClassification
	if zero.Class != PodUnknown {
		t.Fatal("the zero classification must be Unknown")
	}
}

// v5.1 addendum item 1: a policy added while bindingError is set is visible
// to ClassifyPod (reconcile returns early, its defer still publishes).
func TestClassifySnapshotPublishedWhileBindingErrorIsSet(t *testing.T) {
	ctx := context.Background()
	c := syncedController(t)
	if err := c.ReportBindingFailure(ctx, errors.New("discovery incomplete")); err == nil {
		t.Fatal("binding failure hidden")
	}
	c.mu.Lock()
	before := c.configSeq
	c.mu.Unlock()
	pod, facts := testPod("ns", "pod")
	if got := classifyOne(t, c, pod, facts); got.Class != PodUnselected {
		t.Fatalf("no policy yet: %+v", got)
	}
	c.AddHandler(ctx, privPolicy("added", "ns"))
	c.mu.Lock()
	bindingErr, after := c.bindingError, c.configSeq
	c.mu.Unlock()
	if bindingErr == nil || after != before+1 {
		t.Fatalf("bindingError %v, configSeq %d -> %d", bindingErr, before, after)
	}
	got := classifyOne(t, c, pod, facts)
	plan, ok := got.Sections[SectionPrivilege]
	if got.Class != PodSelected || !ok || len(plan.Plan.Policies) != 1 || plan.Plan.Policies[0].Identity.Name != "added" || got.Seq.Config != after {
		t.Fatalf("a policy added under bindingError: %+v", got)
	}
}

// A configuration error publishes a snapshot that classifies every pod
// Unknown; the recovery publishes a usable one.
func TestClassifySnapshotPublishedOnConfigError(t *testing.T) {
	ctx := context.Background()
	c, _, _, client := setup(t, privPolicy("priv", "ns"))
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	pod, facts := testPod("ns", "pod")
	if got := classifyOne(t, c, pod, facts); got.Class != PodSelected {
		t.Fatalf("synced: %+v", got)
	}
	failing := true
	client.PrependReactor("list", "clustersandboxpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
		if failing {
			return true, nil, errors.New("disconnected")
		}
		return false, nil, nil
	})
	if err := c.Refresh(ctx, nil); err == nil {
		t.Fatal("hidden listing failure")
	}
	got := classifyOne(t, c, pod, facts)
	if got.Class != PodUnknown || !strings.Contains(got.Reason, "configuration unavailable") {
		t.Fatalf("configuration error: %+v", got)
	}
	if _, ok := c.PodPlans([]Binding{{PodUID: facts.UID, Namespace: "ns", PodName: "pod", ContainerName: "app", Kind: "regular"}}); ok {
		t.Fatal("PodPlans under a configuration error")
	}
	failing = false
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := classifyOne(t, c, pod, facts); got.Class != PodSelected {
		t.Fatalf("recovered: %+v", got)
	}
}

// A CIDR write bumps configSeq at once; the snapshot keeps its own configSeq
// and CIDRs until the next reconcile republishes.
func TestClassifySnapshotClusterCIDRs(t *testing.T) {
	ctx := context.Background()
	c := syncedController(t, privPolicy("priv", "ns"))
	first := c.classify.Load()
	cidrs := ClusterCIDRs{Pods: []string{"10.0.0.0/16"}}
	if !c.SetClusterCIDRs(cidrs) {
		t.Fatal("CIDRs unchanged")
	}
	c.mu.Lock()
	seq := c.configSeq
	c.mu.Unlock()
	if seq != first.configSeq+1 || c.classify.Load() != first {
		t.Fatalf("configSeq %d, snapshot %d replaced early", seq, first.configSeq)
	}
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	next := c.classify.Load()
	if next.configSeq != seq || len(next.clusterCIDRs.Pods) != 1 {
		t.Fatalf("republished snapshot: %d %+v", next.configSeq, next.clusterCIDRs)
	}
	// A reconcile without a write keeps the configSeq.
	if err := c.Reconcile(ctx); err != nil || c.classify.Load().configSeq != seq {
		t.Fatalf("unchanged reconcile: %v", err)
	}
}

func TestClassifyExemption(t *testing.T) {
	c := syncedController(t, privPolicy("priv", "ns"))
	unsynced, _, _, _ := setup(t)
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		container   string
		want        PodClass
		exempt      bool
	}{
		{"none", nil, "", PodSelected, false},
		{"key", map[string]string{testExemptionKey: "true"}, "", PodUnselected, true},
		{"pod form", map[string]string{testExemptionKey + "/pod": "true"}, "", PodUnselected, true},
		{"pod form before the key", map[string]string{testExemptionKey + "/pod": "false", testExemptionKey: "true"}, "", PodSelected, false},
		{"container form at create", map[string]string{testExemptionKey + "/container.app": "true"}, "app", PodUnselected, true},
		{"container form before the pod form", map[string]string{testExemptionKey + "/container.app": "false", testExemptionKey + "/pod": "true"}, "app", PodSelected, false},
		{"container form does not exempt the sandbox", map[string]string{testExemptionKey + "/container.app": "true"}, "", PodSelected, false},
		{"another container's form", map[string]string{testExemptionKey + "/container.other": "true"}, "app", PodSelected, false},
		{"not a boolean", map[string]string{testExemptionKey: "yes please"}, "", PodUnknown, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod, facts := testPod("ns", "pod")
			for k, v := range tc.annotations {
				pod.Annotations[k] = v
			}
			pods := newFakePods(map[string]PodFacts{"ns/pod": facts})
			pods.fetched = &facts
			got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod, Container: tc.container}, pods.source())
			if got.Class != tc.want || got.Exempt != tc.exempt {
				t.Fatalf("got %+v", got)
			}
			if tc.exempt {
				// The exemption never waits for the API (no Fetch; the cache
				// Lookup only flags ExemptButSelected), and it holds before
				// the first snapshot.
				if pods.fetches.Load() != 0 {
					t.Fatal("an exempt pod was fetched")
				}
				if got := unsynced.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod, Container: tc.container}, pods.source()); got.Class != PodUnselected || !got.Exempt {
					t.Fatalf("exempt without a snapshot: %+v", got)
				}
			}
		})
	}
	// No key configured: no exemption.
	pod, facts := testPod("ns", "pod")
	pod.Annotations[testExemptionKey] = "true"
	pods := newFakePods(map[string]PodFacts{"ns/pod": facts})
	src := pods.source()
	src.ExemptionKey = ""
	if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod}, src); got.Class != PodSelected {
		t.Fatalf("no key: %+v", got)
	}
}

func TestClassifyStaticPods(t *testing.T) {
	c := syncedController(t, privPolicy("priv", "kube-system"))
	pod, facts := testPod("kube-system", "etcd-node")
	pod.UID = "static-hash"
	pod.Annotations = map[string]string{configSourceAnnotation: "file"}
	mirror := facts
	mirror.UID = "mirror-uid"
	for _, tc := range []struct {
		name   string
		mirror map[string]string
		want   PodClass
	}{
		{"mirror names the static UID", map[string]string{configMirrorAnnotation: "static-hash"}, PodSelected},
		{"mirror names another UID", map[string]string{configMirrorAnnotation: "other"}, PodUnknown},
		{"no mirror annotation", nil, PodUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := mirror
			m.Annotations = tc.mirror
			if got := classifyOne(t, c, pod, m); got.Class != tc.want {
				t.Fatalf("got %+v", got)
			}
		})
	}
	pods := newFakePods(nil)
	if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod}, pods.source()); got.Class != PodUnknown || !strings.Contains(got.Reason, "mirror") {
		t.Fatalf("no mirror pod: %+v", got)
	}
	// A pod whose UID equals the mirror's would match only as an API pod.
	apiPod := pod
	apiPod.Annotations = map[string]string{configSourceAnnotation: "api"}
	m := mirror
	m.Annotations = map[string]string{configMirrorAnnotation: "static-hash"}
	if got := classifyOne(t, c, apiPod, m); got.Class != PodUnknown {
		t.Fatalf("an API pod is not matched through a mirror annotation: %+v", got)
	}
}

func TestClassifyInformerMiss(t *testing.T) {
	c := syncedController(t, privPolicy("priv", "ns"))
	pod, facts := testPod("ns", "pod")
	pods := newFakePods(nil)
	if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod}, pods.source()); got.Class != PodUnknown || !strings.Contains(got.Reason, "not known") {
		t.Fatalf("informer miss: %+v", got)
	}
	// A pod recreated under the same name: the informer's UID differs.
	stale := facts
	stale.UID = "old"
	if got := classifyOne(t, c, pod, stale); got.Class != PodUnknown {
		t.Fatalf("UID mismatch: %+v", got)
	}
	// The hook (S5's bounded GET) is asked on a miss only.
	pods.fetched = &facts
	if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod}, pods.source()); got.Class != PodSelected || pods.fetches.Load() != 1 {
		t.Fatalf("fetched: %+v after %d fetches", got, pods.fetches.Load())
	}
	pods.pods = map[string]PodFacts{"ns/pod": facts}
	if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod}, pods.source()); got.Class != PodSelected || pods.fetches.Load() != 1 {
		t.Fatalf("informer hit: %+v after %d fetches", got, pods.fetches.Load())
	}
	// A fetched pod with another UID is still a miss.
	pods.pods = nil
	pods.fetched = &stale
	if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod}, pods.source()); got.Class != PodUnknown {
		t.Fatalf("fetched UID mismatch: %+v", got)
	}
	// A source without its required functions is Unknown.
	if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod}, PodSource{}); got.Class != PodUnknown {
		t.Fatalf("empty source: %+v", got)
	}
}

// An errored ClusterSandboxPolicy is in scope for every pod; an errored
// SandboxPolicy only for its own namespace, whatever its selector.
func TestClassifyErroredPolicyInScope(t *testing.T) {
	brokenCluster := clusterPolicy("broken-cluster")
	brokenCluster.Spec.Containers = nil
	brokenCluster.Spec.Selector.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"never": "matches"}}
	c := syncedController(t, brokenCluster)
	for _, ns := range []string{"ns", "other", "kube-system"} {
		pod, facts := testPod(ns, "pod")
		if got := classifyOne(t, c, pod, facts); got.Class != PodUnknown || !strings.Contains(got.Reason, "broken-cluster") {
			t.Fatalf("%s: %+v", ns, got)
		}
	}
	brokenNs := policy("broken", "ns")
	brokenNs.Spec.Containers = nil
	brokenNs.Spec.Selector.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"never": "matches"}}
	c = syncedController(t, brokenNs, privPolicy("priv", "other"))
	pod, facts := testPod("ns", "pod")
	if got := classifyOne(t, c, pod, facts); got.Class != PodUnknown || !strings.Contains(got.Reason, "broken") {
		t.Fatalf("own namespace: %+v", got)
	}
	pod, facts = testPod("other", "pod")
	if got := classifyOne(t, c, pod, facts); got.Class != PodSelected {
		t.Fatalf("other namespace: %+v", got)
	}
	pod, facts = testPod("third", "pod")
	if got := classifyOne(t, c, pod, facts); got.Class != PodUnselected {
		t.Fatalf("unrelated namespace: %+v", got)
	}
}

// A selecting policy with a class or compile error is Unknown; one that
// does not select the pod is not.
func TestClassifyClassAndCompileErrors(t *testing.T) {
	dependent := policy("dependent", "ns")
	dependent.Spec.Exec.Rules[0].Target.PathClass = []string{"broken"}
	dependent.Spec.Selector.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"role": "dependent"}}
	classes := &api.SandboxPolicyClasses{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicyClasses"}, ObjectMeta: metav1.ObjectMeta{Name: "classes", UID: "classes"}, Spec: api.PolicyClasses{PathClasses: map[string][]string{"broken": {"/bin/one"}}}}
	duplicate := classes.DeepCopy()
	duplicate.Name, duplicate.UID = "duplicate", "duplicate"
	missing := policy("missing-class", "ns")
	missing.Spec.Exec.Rules[0].Target.PathClass = []string{"missing"}
	missing.Spec.Selector.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"role": "missing"}}
	c := syncedController(t, dependent, missing, classes, duplicate)
	for role, reason := range map[string]string{"dependent": "class error", "missing": "does not compile"} {
		pod, facts := testPod("ns", role)
		facts.Labels = map[string]string{"role": role}
		if got := classifyOne(t, c, pod, facts); got.Class != PodUnknown || !strings.Contains(got.Reason, reason) {
			t.Fatalf("%s: %+v", role, got)
		}
	}
	pod, facts := testPod("ns", "plain")
	if got := classifyOne(t, c, pod, facts); got.Class != PodUnselected {
		t.Fatalf("not selected by the broken policies: %+v", got)
	}
}

func TestClassifyTooManyPolicies(t *testing.T) {
	var objects []runtime.Object
	for i := 0; i <= MaxPoliciesPerBinding; i++ {
		objects = append(objects, privPolicy(fmt.Sprintf("priv-%d", i), "ns"))
	}
	c := syncedController(t, objects...)
	pod, facts := testPod("ns", "pod")
	if got := classifyOne(t, c, pod, facts); got.Class != PodUnknown || !strings.Contains(got.Reason, "65 policies") {
		t.Fatalf("over the limit: %+v", got)
	}
	c = syncedController(t, objects[:MaxPoliciesPerBinding]...)
	if got := classifyOne(t, c, pod, facts); got.Class != PodSelected || len(got.Sections[SectionPrivilege].Plan.Policies) != MaxPoliciesPerBinding {
		t.Fatalf("at the limit: %+v", got)
	}
}

func TestClassifySelectedAndUnselected(t *testing.T) {
	priv := privPolicy("priv", "ns")
	priv.Spec.Mode = api.ModeAudit
	priv.Spec.Exec = nil
	net := policy("net", "ns")
	net.Spec.PolicySpec = netSpec(api.ActionDeny)
	off := privPolicy("off", "ns")
	off.Spec.Mode = api.ModeOff
	off.Spec.Selector.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"role": "off"}}
	c := syncedController(t, priv, net, off)
	pod, facts := testPod("ns", "pod")
	got := classifyOne(t, c, pod, facts)
	if got.Class != PodSelected || got.Shape != 0 || !got.Strict || got.Exec || len(got.Sections) != 2 {
		t.Fatalf("selected: %+v", got)
	}
	p, n := got.Sections[SectionPrivilege], got.Sections[SectionNetwork]
	if p.Strict || !n.Strict || p.Digest == "" || p.Digest != SectionDigest(p.Plan, SectionPrivilege) || n.Digest != SectionDigest(n.Plan, SectionNetwork) || p.Digest == n.Digest {
		t.Fatalf("sections: %+v %+v", p, n)
	}
	// Each section's plan holds only that section.
	if p.Plan.Policies[0].Network != nil || n.Plan.Policies[0].Privilege != nil || n.Plan.Policies[0].Network == nil {
		t.Fatalf("section contents: %+v %+v", p.Plan.Policies, n.Plan.Policies)
	}
	// The digest is stable, and follows a policy edit.
	if again := classifyOne(t, c, pod, facts); again.Sections[SectionPrivilege].Digest != p.Digest {
		t.Fatal("digest not stable")
	}
	edited := priv.DeepCopy()
	edited.Generation = 2
	edited.Spec.Privilege = privilegeSection(api.ActionAllow)
	c.ModifyHandler(context.Background(), edited)
	if next := classifyOne(t, c, pod, facts); next.Sections[SectionPrivilege].Digest == p.Digest || next.Sections[SectionNetwork].Digest != n.Digest {
		t.Fatalf("digest after an edit: %+v", next)
	}
	// Only an Off policy selects: Unselected, authoritatively.
	pod, facts = testPod("ns", "off")
	facts.Labels = map[string]string{"role": "off"}
	c = syncedController(t, off)
	if got := classifyOne(t, c, pod, facts); got.Class != PodUnselected || got.Reason != "unselected" {
		t.Fatalf("Off only: %+v", got)
	}
	// An exec-only policy selects the pod with no section plan.
	c = syncedController(t, policy("exec", "ns"))
	if got := classifyOne(t, c, pod, facts); got.Class != PodSelected || !got.Exec || !got.Strict || len(got.Sections) != 0 || got.Shape != 0 {
		t.Fatalf("exec only: %+v", got)
	}
}

func TestClassifyShapes(t *testing.T) {
	t.Run("sources", func(t *testing.T) {
		sourced := privPolicy("sourced", "ns")
		sourced.Spec.Sources = []api.PolicySource{{ContainerProfile: api.ContainerProfileReference{Name: "profile"}, Include: []string{"execs"}}}
		c := syncedController(t, sourced, privPolicy("plain", "ns"))
		pod, facts := testPod("ns", "pod")
		got := classifyOne(t, c, pod, facts)
		if got.Class != PodSelected || got.Shape != ShapeSources || len(got.Sections) != 0 || !got.Exec {
			t.Fatalf("sources: %+v", got)
		}
	})
	t.Run("init container under *", func(t *testing.T) {
		net := policy("net", "ns")
		net.Spec.PolicySpec = netSpec(api.ActionDeny)
		net.Spec.Containers = []string{"app", "setup"}
		c := syncedController(t, privPolicy("priv", "ns"), net)
		pod, facts := testPod("ns", "pod")
		facts.Containers = append(facts.Containers, PodContainer{Name: "setup", Kind: "init"})
		got := classifyOne(t, c, pod, facts)
		// "*" selects regular containers only: the init container lacks
		// the privilege policy. The network policy names both.
		if got.Class != PodSelected || got.Shape != ShapeDifferentSets {
			t.Fatalf("init container: %+v", got)
		}
		if _, ok := got.Sections[SectionPrivilege]; ok {
			t.Fatal("a section with different sets has no plan")
		}
		if n, ok := got.Sections[SectionNetwork]; !ok || len(n.Plan.Policies) != 1 {
			t.Fatalf("the uniform section keeps its plan: %+v", got.Sections)
		}
	})
	t.Run("different sets among regular containers", func(t *testing.T) {
		web := privPolicy("web-only", "ns")
		web.Spec.Containers = []string{"web"}
		c := syncedController(t, privPolicy("all", "ns"), web)
		pod, facts := testPod("ns", "pod")
		facts.Containers = append(facts.Containers, PodContainer{Name: "web", Kind: "regular"})
		if got := classifyOne(t, c, pod, facts); got.Shape != ShapeDifferentSets || len(got.Sections) != 0 {
			t.Fatalf("different sets: %+v", got)
		}
	})
	t.Run("container in the pod cgroup", func(t *testing.T) {
		c := syncedController(t, privPolicy("priv", "ns"))
		pod, facts := testPod("ns", "pod")
		pods := newFakePods(map[string]PodFacts{"ns/pod": facts})
		got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod, Container: "app", ContainerInPodCgroup: true}, pods.source())
		if got.Class != PodSelected || got.Shape != ShapeContainerInPodCgroup || len(got.Sections) != 1 {
			t.Fatalf("container in the pod cgroup: %+v", got)
		}
		// An unselected pod has no shape.
		other, otherFacts := testPod("elsewhere", "pod")
		pods = newFakePods(map[string]PodFacts{"elsewhere/pod": otherFacts})
		if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: other, Container: "app", ContainerInPodCgroup: true}, pods.source()); got.Class != PodUnselected || got.Shape != 0 {
			t.Fatalf("unselected: %+v", got)
		}
		// A container the pod spec does not declare is Unknown.
		pods = newFakePods(map[string]PodFacts{"ns/pod": facts})
		if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod, Container: "debug"}, pods.source()); got.Class != PodUnknown {
			t.Fatalf("undeclared container: %+v", got)
		}
	})
	t.Run("no container", func(t *testing.T) {
		c := syncedController(t, privPolicy("priv", "ns"))
		pod, facts := testPod("ns", "pod")
		facts.Containers = nil
		if got := classifyOne(t, c, pod, facts); got.Class != PodUnknown {
			t.Fatalf("no container: %+v", got)
		}
	})
}

// The classification carries the snapshot's configSeq and the input epoch
// of the lookup, retried once when a bump races it.
func TestClassifySeq(t *testing.T) {
	c := syncedController(t, privPolicy("priv", "ns"))
	pod, facts := testPod("ns", "pod")
	pods := newFakePods(map[string]PodFacts{"ns/pod": facts})
	pods.epoch.Store(7)
	src := pods.source()
	got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod}, src)
	if got.Seq != (Seq{Config: c.classify.Load().configSeq, Input: 7}) || pods.lookups.Load() != 1 {
		t.Fatalf("seq %+v after %d lookups", got.Seq, pods.lookups.Load())
	}
	lookup := src.Lookup
	bumped := false
	src.Lookup = func(namespace, name string) (PodFacts, bool) {
		if !bumped {
			bumped = true
			pods.epoch.Add(1)
		}
		return lookup(namespace, name)
	}
	got = c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod}, src)
	if got.Seq.Input != 8 || pods.lookups.Load() != 3 || got.Class != PodSelected {
		t.Fatalf("raced: %+v after %d lookups", got, pods.lookups.Load())
	}
}

// ClassifyPod and PodPlans read the snapshot only: they finish while c.mu is
// held (as Refresh holds it across the API listings).
func TestClassifyNeverWaitsForControllerLock(t *testing.T) {
	c := syncedController(t, privPolicy("priv", "ns"))
	pod, facts := testPod("ns", "pod")
	pods := newFakePods(map[string]PodFacts{"ns/pod": facts})
	c.mu.Lock()
	defer c.mu.Unlock()
	done := make(chan PodClassification, 1)
	go func() {
		got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod}, pods.source())
		_, _ = c.PodPlans([]Binding{{PodUID: facts.UID, Namespace: "ns", PodName: "pod", ContainerName: "app", Kind: "regular"}})
		done <- got
	}()
	select {
	case got := <-done:
		if got.Class != PodSelected {
			t.Fatalf("classified under c.mu: %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ClassifyPod or PodPlans waited for c.mu")
	}
}

// Concurrent classification while reconciles publish snapshots (run with
// -race).
func TestClassifyConcurrentWithReconcile(t *testing.T) {
	ctx := context.Background()
	c := syncedController(t, privPolicy("priv", "ns"))
	pod, facts := testPod("ns", "pod")
	pods := newFakePods(map[string]PodFacts{"ns/pod": facts})
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		var last uint64
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			got := c.ClassifyPod(ctx, ClassifyRequest{Pod: pod}, pods.source())
			if got.Class != PodSelected {
				done <- fmt.Errorf("classified %+v", got)
				return
			}
			if got.Seq.Config < last {
				done <- fmt.Errorf("configSeq went back: %d after %d", got.Seq.Config, last)
				return
			}
			last = got.Seq.Config
		}
	}()
	for i := 0; i < 20; i++ {
		edited := privPolicy("priv", "ns")
		edited.Generation = int64(i + 2)
		c.ModifyHandler(ctx, edited)
		c.SetClusterCIDRs(ClusterCIDRs{Pods: []string{fmt.Sprintf("10.%d.0.0/16", i)}})
		_ = c.Reconcile(ctx)
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Finding 1: ClassifyPod's section digest is the one of the PodPlans plan of
// the same pod, and the SectionBackend's section revision.
func TestClassifySectionDigestMatchesPodPlans(t *testing.T) {
	priv := privPolicy("priv", "ns")
	net := policy("net", "ns")
	net.Spec.PolicySpec = netSpec(api.ActionDeny)
	both := privPolicy("both", "ns")
	both.Spec.Mode = api.ModeAudit
	both.Spec.Network = netSpec(api.ActionAllow).Network
	file := policy("file", "ns")
	file.Spec.File = &api.FileSection{Default: api.ActionDeny}
	c := syncedController(t, priv, net, both, file)
	pod, facts := testPod("ns", "pod")
	got := classifyOne(t, c, pod, facts)
	plans, ok := c.PodPlans([]Binding{{PodUID: facts.UID, Namespace: "ns", PodName: "pod", ContainerName: "app", Kind: "regular", PodLabels: facts.Labels, NamespaceLabels: facts.NamespaceLabels}})
	if !ok || got.Class != PodSelected || len(got.Sections) != 3 {
		t.Fatalf("classified %+v, plans %+v", got, plans)
	}
	backend, err := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	split := func(plan Plan, section string) string {
		out := backend.split(plan)
		for i, sec := range backend.sections {
			if sec.name == section {
				return out.other[i].Revision
			}
		}
		return ""
	}
	for _, sec := range []string{SectionPrivilege, SectionNetwork, SectionFile} {
		want := SectionDigest(plans[facts.UID], sec)
		if want == "" || got.Sections[sec].Digest != want {
			t.Fatalf("%s: classified %q, PodPlans %q", sec, got.Sections[sec].Digest, want)
		}
		if rev := split(plans[facts.UID], sec); rev != want {
			t.Fatalf("%s: section revision %q, SectionDigest %q", sec, rev, want)
		}
	}
	if SectionDigest(Plan{Policies: []CompiledPolicy{{Identity: PolicyIdentity{UID: "x"}}}}, SectionNetwork) != "" || SectionDigest(plans[facts.UID], "exec") != "" {
		t.Fatal("no section policy (or an unknown section) has no digest")
	}
	// A generation bump with an unchanged section keeps that section's
	// digest; a change of the section changes it.
	edited := priv.DeepCopy()
	edited.Generation = 5
	c.ModifyHandler(context.Background(), edited)
	if next := classifyOne(t, c, pod, facts); next.Sections[SectionPrivilege].Digest != got.Sections[SectionPrivilege].Digest {
		t.Fatal("a generation bump changed the digest")
	}
	edited = edited.DeepCopy()
	edited.Generation = 6
	edited.Spec.Privilege = privilegeSection(api.ActionAllow)
	c.ModifyHandler(context.Background(), edited)
	next := classifyOne(t, c, pod, facts)
	if next.Sections[SectionPrivilege].Digest == got.Sections[SectionPrivilege].Digest || next.Sections[SectionNetwork].Digest != got.Sections[SectionNetwork].Digest {
		t.Fatalf("after a privilege edit: %+v", next.Sections)
	}
}

// Finding 2: an exempt pod that a policy selects stays exempt, flagged.
func TestClassifyExemptButSelected(t *testing.T) {
	c := syncedController(t, privPolicy("priv", "ns"))
	pod, facts := testPod("ns", "pod")
	pod.Annotations[testExemptionKey] = "true"
	got := classifyOne(t, c, pod, facts)
	if got.Class != PodUnselected || !got.Exempt || !got.ExemptButSelected || !strings.Contains(got.Reason, "SandboxPolicy ns/priv") {
		t.Fatalf("exempt and selected: %+v", got)
	}
	other, otherFacts := testPod("elsewhere", "pod")
	other.Annotations[testExemptionKey] = "true"
	if got := classifyOne(t, c, other, otherFacts); got.Class != PodUnselected || !got.Exempt || got.ExemptButSelected {
		t.Fatalf("exempt, not selected: %+v", got)
	}
	// Not cached, or no snapshot: exempt, without the flag and without a
	// Fetch.
	pods := newFakePods(nil)
	pods.fetched = &facts
	if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod}, pods.source()); !got.Exempt || got.ExemptButSelected || pods.fetches.Load() != 0 {
		t.Fatalf("exempt, not cached: %+v after %d fetches", got, pods.fetches.Load())
	}
	unsynced, _, _, _ := setup(t, privPolicy("priv", "ns"))
	if got := classifyOne(t, unsynced, pod, facts); !got.Exempt || got.ExemptButSelected {
		t.Fatalf("exempt, no snapshot: %+v", got)
	}
}

// Finding 3: the cap is per container. Two containers with 40 distinct
// policies each (80 for the pod) are classified.
func TestClassifyPolicyCapPerContainer(t *testing.T) {
	var objects []runtime.Object
	for _, container := range []string{"app", "web"} {
		for i := 0; i < 40; i++ {
			p := privPolicy(fmt.Sprintf("%s-%d", container, i), "ns")
			p.Spec.Containers = []string{container}
			objects = append(objects, p)
		}
	}
	c := syncedController(t, objects...)
	pod, facts := testPod("ns", "pod")
	facts.Containers = append(facts.Containers, PodContainer{Name: "web", Kind: "regular"})
	if got := classifyOne(t, c, pod, facts); got.Class != PodSelected || got.Shape != ShapeDifferentSets {
		t.Fatalf("40 per container: %+v", got)
	}
}

// Finding 7(c): a container kind other than regular, init or ephemeral.
func TestClassifyInvalidContainerKind(t *testing.T) {
	c := syncedController(t, privPolicy("priv", "ns"))
	pod, facts := testPod("ns", "pod")
	for _, kind := range []string{"", "Regular", "sidecar"} {
		facts.Containers = []PodContainer{{Name: "app", Kind: kind}}
		if got := classifyOne(t, c, pod, facts); got.Class != PodUnknown || !strings.Contains(got.Reason, "invalid kind") {
			t.Fatalf("kind %q: %+v", kind, got)
		}
	}
}

// Finding 6: concurrent PodPlans calls (run with -race).
func TestPodPlansConcurrentCalls(t *testing.T) {
	c := syncedController(t, privPolicy("priv", "ns"))
	b := Binding{PodUID: "pod", Namespace: "ns", PodName: "pod", ContainerName: "app", Kind: "regular", PodLabels: map[string]string{"app": "test"}}
	done := make(chan bool)
	for i := 0; i < 4; i++ {
		go func() {
			plans, ok := c.PodPlans([]Binding{b})
			done <- ok && len(plans["pod"].Policies) == 1
		}()
	}
	for i := 0; i < 4; i++ {
		if !<-done {
			t.Fatal("concurrent PodPlans")
		}
	}
}

// Finding C: PodPlansAt returns the configSeq of the snapshot it read.
func TestPodPlansAtReturnsSnapshotSeq(t *testing.T) {
	c := syncedController(t, privPolicy("priv", "ns"))
	b := Binding{PodUID: "pod", Namespace: "ns", PodName: "pod", ContainerName: "app", Kind: "regular", PodLabels: map[string]string{"app": "test"}}
	for i := 0; i < 3; i++ {
		snap := c.classify.Load()
		plans, seq, ok := c.PodPlansAt([]Binding{b})
		if !ok || seq != snap.configSeq || seq == 0 || len(plans["pod"].Policies) != 1 {
			t.Fatalf("seq %d, snapshot %d, plans %+v", seq, snap.configSeq, plans)
		}
		// A configSeq bump without a reconcile does not move the plans' seq.
		c.SetClusterCIDRs(ClusterCIDRs{Pods: []string{fmt.Sprintf("10.%d.0.0/16", i)}})
		if _, again, _ := c.PodPlansAt([]Binding{b}); again != snap.configSeq {
			t.Fatalf("unpublished bump leaked: %d, snapshot %d", again, snap.configSeq)
		}
		_ = c.Reconcile(context.Background())
		if next := c.classify.Load().configSeq; next <= seq {
			t.Fatalf("the reconcile did not publish a newer snapshot: %d after %d", next, seq)
		}
	}
	unsynced, _, _, _ := setup(t)
	if _, seq, ok := unsynced.PodPlansAt([]Binding{b}); ok || seq != 0 {
		t.Fatalf("no snapshot: %d %v", seq, ok)
	}
}

// Finding E: a container-form exemption at CreateContainer is flagged only
// for a policy that selects that container.
func TestClassifyExemptButSelectedContainerForm(t *testing.T) {
	web := privPolicy("web-only", "ns")
	web.Spec.Containers = []string{"web"}
	c := syncedController(t, web)
	pod, facts := testPod("ns", "pod")
	facts.Containers = append(facts.Containers, PodContainer{Name: "web", Kind: "regular"})
	pods := newFakePods(map[string]PodFacts{"ns/pod": facts})
	pod.Annotations[testExemptionKey+"/container.app"] = "true"
	if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod, Container: "app"}, pods.source()); !got.Exempt || got.ExemptButSelected {
		t.Fatalf("app is exempt and not selected: %+v", got)
	}
	pod.Annotations[testExemptionKey+"/container.web"] = "true"
	if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod, Container: "web"}, pods.source()); !got.Exempt || !got.ExemptButSelected || !strings.Contains(got.Reason, "ns/web-only") {
		t.Fatalf("web is exempt and selected: %+v", got)
	}
	// A pod-form exemption still checks every container.
	delete(pod.Annotations, testExemptionKey+"/container.app")
	pod.Annotations[testExemptionKey+"/pod"] = "true"
	if got := c.ClassifyPod(context.Background(), ClassifyRequest{Pod: pod, Container: "app"}, pods.source()); !got.Exempt || !got.ExemptButSelected {
		t.Fatalf("pod form: %+v", got)
	}
}
