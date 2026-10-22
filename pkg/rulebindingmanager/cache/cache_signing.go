//go:build experimental_signing

package cache

import (
	"context"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	rbtypes "github.com/kubescape/node-agent/pkg/rulebindingmanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	"github.com/kubescape/node-agent/pkg/rulemanager/prefilter"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/watcher"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

var _ rulebindingmanager.RuleBindingCache = (*RBCache)(nil)
var _ watcher.Adaptor = (*RBCache)(nil)

type pendingNotification struct {
	notifiers []*chan rulebindingmanager.RuleBindingNotify
	events    []rulebindingmanager.RuleBindingNotify
}

type RBCache struct {
	config            config.Config
	nodeName          string
	k8sClient         k8sclient.K8sClientInterface
	allPods           mapset.Set[string]                                    // set of all pods (also pods without rules)
	podToRBNames      maps.SafeMap[string, mapset.Set[string]]              // podID -> []rule binding names
	podToBundle       maps.SafeMap[string, string]                          // podID -> signed bundle the pod opted into (kubescape.io/user-defined-profile)
	rbNameToRB        maps.SafeMap[string, typesv1.RuntimeAlertRuleBinding] // rule binding name -> rule binding
	rbNameToRules     maps.SafeMap[string, []rulemanagertypesv1.Rule]       // rule binding name -> []created rules
	rbNameToPods      maps.SafeMap[string, mapset.Set[string]]              // rule binding name -> podIDs
	ruleCreator       rulecreator.RuleCreator
	watchResources    []watcher.WatchResource
	notifiers         []*chan rulebindingmanager.RuleBindingNotify
	mutex             sync.RWMutex
	rulesForPod       *expirable.LRU[string, []rulemanagertypesv1.Rule]
	notificationQueue chan pendingNotification

	policyMutex sync.RWMutex
	trustPolicy *bundle.TrustPolicy
}

func (c *RBCache) SetTrustPolicy(p *bundle.TrustPolicy) {
	c.policyMutex.Lock()
	defer c.policyMutex.Unlock()
	c.trustPolicy = p
}

func (c *RBCache) trustPolicySnapshot() (*bundle.TrustPolicy, bool) {
	c.policyMutex.RLock()
	defer c.policyMutex.RUnlock()
	if c.trustPolicy == nil || !c.trustPolicy.BindingSigningEnabled() {
		return nil, false
	}
	return c.trustPolicy, true
}

func (c *RBCache) bindingSigningEnabled() bool {
	_, ok := c.trustPolicySnapshot()
	return ok
}

func NewCache(config config.Config, k8sClient k8sclient.K8sClientInterface, ruleCreator rulecreator.RuleCreator) *RBCache {
	c := &RBCache{
		config:            config,
		nodeName:          config.NodeName,
		k8sClient:         k8sClient,
		ruleCreator:       ruleCreator,
		allPods:           mapset.NewSet[string](),
		rbNameToRB:        maps.SafeMap[string, typesv1.RuntimeAlertRuleBinding]{},
		podToRBNames:      maps.SafeMap[string, mapset.Set[string]]{},
		podToBundle:       maps.SafeMap[string, string]{},
		rbNameToPods:      maps.SafeMap[string, mapset.Set[string]]{},
		watchResources:    resourcesToWatch(config.NodeName, config.IgnoreRuleBindings),
		rulesForPod:       expirable.NewLRU[string, []rulemanagertypesv1.Rule](1000, nil, 5*time.Second),
		notificationQueue: make(chan pendingNotification, 10000),
	}
	go c.processNotifications()
	return c
}

func (c *RBCache) processNotifications() {
	for pn := range c.notificationQueue {
		for _, n := range pn.notifiers {
			for _, event := range pn.events {
				select {
				case *n <- event:
				default:
					timer := time.NewTimer(100 * time.Millisecond)
					select {
					case *n <- event:
						timer.Stop()
					case <-timer.C:
						logger.L().Error("RBCache - notifier is slow or blocked, dropping notification", helpers.Interface("event", event))
					}
				}
			}
		}
	}
}

// ----------------- watcher.WatchResources methods -----------------

func (c *RBCache) WatchResources() []watcher.WatchResource {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.watchResources
}

// ------------------ rulebindingmanager.RuleBindingCache methods -----------------------

func (c *RBCache) ListRulesForPod(namespace, name string) []rulemanagertypesv1.Rule {
	podID := utils.CreateK8sPodID(namespace, name)
	bundleName := c.bundleForPod(podID)

	if c.config.IgnoreRuleBindings {
		rules, ok := c.rulesForPod.Get(podID)
		if ok {
			return rules
		}
		// Scope BEFORE caching: the LRU key is the podID, which identifies the
		// pod whose bundle we scoped to, so a post-filter result is correct to
		// memoise.
		rules = scopeRulesToBundle(c.getRules(), bundleName)
		c.rulesForPod.Add(podID, rules)
		return rules
	}

	var rulesSlice []rulemanagertypesv1.Rule

	rulesSlice, ok := c.rulesForPod.Get(podID)
	if ok {
		return rulesSlice
	}

	if !c.podToRBNames.Has(podID) {
		return nil
	}

	//append rules for pod
	rbNames := c.podToRBNames.Get(podID)
	for _, i := range rbNames.ToSlice() {
		if rules, ok := c.rbNameToRules.Load(i); ok {
			rulesSlice = append(rulesSlice, rules...)
		}
	}

	rulesSlice = scopeRulesToBundle(rulesSlice, bundleName)

	c.rulesForPod.Add(podID, rulesSlice)

	return rulesSlice
}

// bundleForPod returns the signed bundle a pod opted into, or "" when the pod
// carries no user-defined-profile label or is not known to the cache. Empty is
// the safe default: only cluster-wide (base-class) rules then apply.
func (c *RBCache) bundleForPod(podID string) string {
	if b, ok := c.podToBundle.Load(podID); ok {
		return b
	}
	return ""
}

// setPodBundle records (or clears) the bundle a pod is bound to. The key is the
// same namespace-qualified pod ID used by podToRBNames and by the rulesForPod
// LRU, so all three agree on pod identity.
func (c *RBCache) setPodBundle(pod *corev1.Pod) {
	podID := uniqueName(pod)
	// Cached rules were scoped to the previous bundle membership.
	if c.rulesForPod != nil {
		c.rulesForPod.Remove(podID)
	}
	if b := pod.GetLabels()[helpersv1.UserDefinedProfileMetadataKey]; b != "" {
		c.podToBundle.Set(podID, b)
		return
	}
	// The label can be removed by an update; a stale entry would keep applying
	// an overlay to a pod that opted out.
	c.podToBundle.Delete(podID)
}

// scopeRulesToBundle resolves the provenance of signed rule fragments for a pod
// bound to the given bundle:
//
//  1. A base (cluster-wide) rule applies to every workload, bundle or not.
//  2. An overlay rule applies ONLY to workloads bound to its bundle — in any
//     namespace — and is dropped for everyone else. Bundle membership is signed,
//     the namespace is not, so the namespace plays no part here.
//  3. For a pod inside the bundle, the overlay REPLACES the base rule carrying
//     the same ID. That override is the point of the feature: the vendor ships
//     one bundle whose ContainerProfile half describes the expected behaviour and
//     whose Rules half retunes the detections that go with it.
//
// When rule signing is DISABLED the rules watcher stamps ClusterWide on every
// rule and no bundle at all, and this function returns the input untouched — no
// filtering, no de-duplication, no reordering. That keeps the no-trust-policy
// deployment bit-for-bit identical to the pre-signing behaviour, including
// duplicate rule IDs contributed by two rule bindings with different prefilter
// parameters.
//
// Ordering is first-seen deterministic: the output preserves the order of the
// input, with an overriding bundle rule taking the position of the cluster-wide
// rule it replaces. It never depends on map iteration order.
func scopeRulesToBundle(rules []rulemanagertypesv1.Rule, bundleName string) []rulemanagertypesv1.Rule {
	if len(rules) == 0 {
		return rules
	}

	// Fast path: no rule belongs to a bundle, so there is nothing to scope and
	// nothing that could override anything. A non-empty Bundle is the only thing
	// that can make this function change its input: AdmitRulesFragment refuses an
	// overlay without one, so an overlay always trips this check.
	provenance := false
	for i := range rules {
		if rules[i].Bundle != "" {
			provenance = true
			break
		}
	}
	if !provenance {
		return rules
	}

	out := make([]rulemanagertypesv1.Rule, 0, len(rules))
	posByID := make(map[string]int, len(rules))

	for _, rule := range rules {
		// A rule that is neither cluster-wide nor bundled carries no provenance
		// at all (e.g. registered directly by a third party). It is NOT an
		// overlay, so it is kept for every pod — the pre-signing behaviour.
		overlay := !rule.ClusterWide && rule.Bundle != ""
		if overlay && (bundleName == "" || rule.Bundle != bundleName) {
			// An overlay never leaks outside the bundle it was signed for.
			continue
		}
		pos, seen := posByID[rule.ID]
		if !seen {
			posByID[rule.ID] = len(out)
			out = append(out, rule)
			continue
		}
		existing := out[pos]
		existingOverlay := !existing.ClusterWide && existing.Bundle != ""
		if overlay && !existingOverlay {
			// The bundle overlay wins over the cluster-wide rule.
			out[pos] = rule
		}
		// Otherwise keep the first-seen rule (two cluster-wide rules with the
		// same ID, or an already-applied bundle override).
	}

	return out
}

func (c *RBCache) AddNotifier(n *chan rulebindingmanager.RuleBindingNotify) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.notifiers = append(c.notifiers, n)
}

// ------------------ watcher.Watcher methods -----------------------

func (c *RBCache) AddHandler(ctx context.Context, obj runtime.Object) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var rbs []rulebindingmanager.RuleBindingNotify

	if pod, ok := obj.(*corev1.Pod); ok {
		// The pod's bundle is tracked in EVERY mode: ListRulesForPod scopes
		// overlays by it whether or not rule bindings are consulted.
		c.setPodBundle(pod)
		// When rule bindings are ignored, pod->binding bookkeeping is never read
		// (ListRulesForPod resolves rules directly from the rule creator), so skip it.
		if c.config.IgnoreRuleBindings {
			return
		}
		rbs = c.addPod(ctx, pod)
	} else if un, ok := obj.(*unstructured.Unstructured); ok {
		if un.GetKind() != "" && un.GetKind() != rbtypes.RuntimeRuleBindingAlertKind {
			return
		}
		ruleBinding, err := unstructuredToRuleBinding(un)
		if err != nil {
			logger.L().Warning("RBCache - failed to convert unstructured to rule binding", helpers.Error(err))
			return
		}
		rbs = c.addRuleBinding(ruleBinding)
	}

	if len(c.notifiers) > 0 && len(rbs) > 0 {
		notifiers := make([]*chan rulebindingmanager.RuleBindingNotify, len(c.notifiers))
		copy(notifiers, c.notifiers)
		select {
		case c.notificationQueue <- pendingNotification{notifiers: notifiers, events: rbs}:
		default:
			logger.L().Error("RBCache - notification queue full, dropping notifications", helpers.Int("size", len(c.notificationQueue)))
		}
	}
}

func (c *RBCache) ModifyHandler(ctx context.Context, obj runtime.Object) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var rbs []rulebindingmanager.RuleBindingNotify

	if pod, ok := obj.(*corev1.Pod); ok {
		// A pod update can add, change or remove the user-defined-profile label,
		// so the bundle is re-read on every modify, in every mode.
		c.setPodBundle(pod)
		// When rule bindings are ignored, pod->binding bookkeeping is never read
		// (ListRulesForPod resolves rules directly from the rule creator), so skip it.
		if c.config.IgnoreRuleBindings {
			return
		}
		rbs = c.addPod(ctx, pod)
	} else if un, ok := obj.(*unstructured.Unstructured); ok {
		if un.GetKind() != "" && un.GetKind() != rbtypes.RuntimeRuleBindingAlertKind {
			return
		}
		ruleBinding, err := unstructuredToRuleBinding(un)
		if err != nil {
			logger.L().Warning("RBCache - failed to convert unstructured to rule binding", helpers.Error(err))
			return
		}
		rbs = c.modifiedRuleBinding(ruleBinding)
	}

	if len(c.notifiers) > 0 && len(rbs) > 0 {
		notifiers := make([]*chan rulebindingmanager.RuleBindingNotify, len(c.notifiers))
		copy(notifiers, c.notifiers)
		select {
		case c.notificationQueue <- pendingNotification{notifiers: notifiers, events: rbs}:
		default:
			logger.L().Error("RBCache - notification queue full, dropping notifications", helpers.Int("size", len(c.notificationQueue)))
		}
	}
}

func (c *RBCache) DeleteHandler(_ context.Context, obj runtime.Object) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var rbs []rulebindingmanager.RuleBindingNotify

	if pod, ok := obj.(*corev1.Pod); ok {
		// Drop the bundle binding in every mode, so a recycled pod ID cannot
		// inherit the previous pod's overlay.
		c.podToBundle.Delete(uniqueName(pod))
		if c.rulesForPod != nil {
			c.rulesForPod.Remove(uniqueName(pod))
		}
		// When rule bindings are ignored, pod->binding bookkeeping is never populated, so skip it.
		if c.config.IgnoreRuleBindings {
			return
		}
		c.deletePod(uniqueName(pod))
	} else if un, ok := obj.(*unstructured.Unstructured); ok {
		rbs = c.deleteRuleBinding(uniqueName(un))
	}

	if len(c.notifiers) > 0 && len(rbs) > 0 {
		notifiers := make([]*chan rulebindingmanager.RuleBindingNotify, len(c.notifiers))
		copy(notifiers, c.notifiers)
		select {
		case c.notificationQueue <- pendingNotification{notifiers: notifiers, events: rbs}:
		default:
			logger.L().Error("RBCache - notification queue full, dropping notifications", helpers.Int("size", len(c.notificationQueue)))
		}
	}
}

func (c *RBCache) RefreshRuleBindingsRules() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// When rule bindings are ignored, ListRulesForPod resolves rules directly from
	// the rule creator (CreateAllRules), so there are no per-binding rules to rebuild.
	// We still notify downstream consumers so they react to the underlying rule change
	// (e.g. RuleManager recompiling the profile projection spec).
	if !c.config.IgnoreRuleBindings {
		for _, rbName := range c.rbNameToRB.Keys() {
			rb := c.rbNameToRB.Get(rbName)
			c.rbNameToRules.Set(rbName, c.createRules(rb.Spec.Rules))
		}
		logger.L().Info("RBCache - refreshed rule bindings rules", helpers.Int("ruleBindings", len(c.rbNameToRB.Keys())))
	}

	// The per-pod memo answers from the ruleset that was live when it was
	// filled, so leaving it in place holds every pod on the previous ruleset
	// until the entry expires: permissive while a rules outage is in progress,
	// and blind to the rules that end it. Both directions are a detection gap
	// bounded only by the memo's lifetime, so a rules change drops it.
	c.rulesForPod.Purge()

	if len(c.notifiers) > 0 {
		notifiers := make([]*chan rulebindingmanager.RuleBindingNotify, len(c.notifiers))
		copy(notifiers, c.notifiers)
		select {
		case c.notificationQueue <- pendingNotification{notifiers: notifiers, events: []rulebindingmanager.RuleBindingNotify{{}}}:
		default:
			logger.L().Error("RBCache - notification queue full, dropping refresh notification")
		}
	}
}

// ----------------- RuleBinding manager methods -----------------

// AddRuleBinding adds a rule binding to the cache
func (c *RBCache) addRuleBinding(ruleBinding *typesv1.RuntimeAlertRuleBinding) []rulebindingmanager.RuleBindingNotify {
	var rbs []rulebindingmanager.RuleBindingNotify
	rbName := uniqueName(ruleBinding)
	logger.L().Info("RBCache - ruleBinding added/modified", helpers.String("name", rbName))

	if policy, signingEnabled := c.trustPolicySnapshot(); signingEnabled {
		verified, admitErr := bundle.AdmitBinding(ruleBinding, *policy)
		if admitErr != nil {
			logger.L().Warning("rule binding rejected",
				helpers.String("name", ruleBinding.GetName()),
				helpers.String("namespace", ruleBinding.GetNamespace()),
				helpers.Error(admitErr))
			return rbs
		}
		// Keep the watch object's identity, but enforce only authenticated
		// selectors and rules. Never mutate an informer-owned object.
		admitted := *ruleBinding
		admitted.Spec = verified.Spec
		ruleBinding = &admitted
	}

	// convert selectors to string
	nsSelector, err := metav1.LabelSelectorAsSelector(&ruleBinding.Spec.NamespaceSelector)
	// check if the selectors are valid
	if err != nil {
		logger.L().Warning("RBCache - failed to parse ns selector", helpers.String("ruleBiding", rbName), helpers.Interface("NamespaceSelector", ruleBinding.Spec.NamespaceSelector), helpers.Error(err))
		return rbs
	}
	podSelector, err := metav1.LabelSelectorAsSelector(&ruleBinding.Spec.PodSelector)
	// check if the selectors are valid
	if err != nil {
		logger.L().Warning("RBCache - failed to parse pod selector", helpers.String("ruleBiding", rbName), helpers.Interface("PodSelector", ruleBinding.Spec.PodSelector), helpers.Error(err))
		return rbs
	}

	nsSelectorStr := nsSelector.String()
	podSelectorStr := podSelector.String()

	// add the rule binding to the cache
	c.rbNameToRB.Set(rbName, *ruleBinding)
	c.rbNameToPods.Set(rbName, mapset.NewSet[string]())
	c.rbNameToRules.Set(rbName, c.createRules(ruleBinding.Spec.Rules))

	var namespaces *corev1.NamespaceList
	// if ruleBinding.GetNamespace() == "" {
	namespaces, err = c.k8sClient.GetKubernetesClient().CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{LabelSelector: nsSelectorStr})
	if err != nil {
		logger.L().Warning("RBCache - failed to list namespaces", helpers.String("ruleBiding", rbName), helpers.String("nsSelector", nsSelectorStr), helpers.Error(err))
		return rbs
	}
	// } else {
	// 	namespaces = &corev1.NamespaceList{Items: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: ruleBinding.GetNamespace()}}}}
	// }

	// get related pods
	for _, ns := range namespaces.Items {
		lp := metav1.ListOptions{
			LabelSelector: podSelectorStr,
			FieldSelector: "spec.nodeName=" + c.nodeName,
		}
		pods, err := c.k8sClient.GetKubernetesClient().CoreV1().Pods(ns.GetName()).List(context.Background(), lp)
		if err != nil {
			logger.L().Warning("RBCache - failed to list pods", helpers.String("ruleBiding", rbName), helpers.String("podSelector", podSelectorStr), helpers.Error(err))
			return rbs
		}

		for _, pod := range pods.Items {
			podName := uniqueName(&pod)
			// These pod objects come straight from the apiserver, so they are as
			// authoritative about the bundle opt-in as a watch event.
			c.setPodBundle(&pod)
			if rbNames, ok := c.podToRBNames.Load(podName); !ok {
				c.podToRBNames.Set(podName, mapset.NewSet[string](rbName))
			} else {
				rbNames.Add(rbName)
			}

			c.rbNameToPods.Get(rbName).Add(podName)

			if len(c.notifiers) == 0 {
				continue
			}
			n := rulebindingmanager.NewRuleBindingNotifierImpl(rulebindingmanager.Added, pod)
			rbs = append(rbs, n)

			logger.L().Debug("RBCache - ruleBinding attached to pod", helpers.String("ruleBinding", rbName), helpers.String("pod", podName))
		}
	}
	return rbs
}
func (c *RBCache) deleteRuleBinding(uniqueName string) []rulebindingmanager.RuleBindingNotify {
	logger.L().Info("RBCache - ruleBinding deleted", helpers.String("name", uniqueName))
	var rbs []rulebindingmanager.RuleBindingNotify

	// remove the rule binding from the pods
	for _, podName := range c.podToRBNames.Keys() {
		c.podToRBNames.Get(podName).Remove(uniqueName)

		if c.podToRBNames.Get(podName).Cardinality() != 0 {
			// if this pod is still bound to other rule bindings, continue
			continue
		}
		c.podToRBNames.Delete(podName)

		if len(c.notifiers) == 0 {
			continue
		}
		namespace, name := uniqueNameToName(podName)
		n, err := rulebindingmanager.RuleBindingNotifierImplWithK8s(c.k8sClient, rulebindingmanager.Removed, namespace, name)
		if err != nil {
			logger.L().Warning("RBCache - failed to create notifier", helpers.String("namespace", namespace), helpers.String("name", name), helpers.Error(err))
			continue
		}

		rbs = append(rbs, n)
	}

	// remove the rule binding from the cache
	c.rbNameToRB.Delete(uniqueName)
	c.rbNameToRules.Delete(uniqueName)
	c.rbNameToPods.Delete(uniqueName)

	return rbs
}

func (c *RBCache) modifiedRuleBinding(ruleBinding *typesv1.RuntimeAlertRuleBinding) []rulebindingmanager.RuleBindingNotify {
	rbsD := c.deleteRuleBinding(uniqueName(ruleBinding))
	rbsA := c.addRuleBinding(ruleBinding)

	return diff(rbsD, rbsA)
}

// ----------------- Pod manager methods -----------------

// addPod binds a pod to the rule bindings selecting it. The pod's BUNDLE opt-in
// is recorded by the calling handler (setPodBundle) before this runs, because it
// must be tracked even when rule bindings are ignored and addPod is skipped.
func (c *RBCache) addPod(ctx context.Context, pod *corev1.Pod) []rulebindingmanager.RuleBindingNotify {
	var rbs []rulebindingmanager.RuleBindingNotify
	podName := uniqueName(pod)

	// add the pods to list of all pods only after the pod is processed
	defer c.allPods.Add(podName)

	// if pod is already in the cache, ignore
	if c.podToRBNames.Has(podName) {
		return rbs
	}

	for _, rb := range c.rbNameToRB.Values() {
		// if rb.GetNamespace() != "" && rb.GetNamespace() != pod.GetNamespace() {
		// 	// rule binding is not in the same namespace as the pod
		// 	continue
		// }
		rbName := uniqueName(&rb)

		// check pod selectors
		podSelector, err := metav1.LabelSelectorAsSelector(&rb.Spec.PodSelector)
		if err != nil {
			logger.L().Warning("RBCache - failed to parse pod selector", helpers.String("ruleBiding", uniqueName(&rb)), helpers.Error(err))
			continue
		}
		if !podSelector.Matches(labels.Set(pod.GetLabels())) {
			// pod selectors doesnt match
			continue
		}

		// check namespace selectors
		nsSelector, err := metav1.LabelSelectorAsSelector(&rb.Spec.NamespaceSelector)
		if err != nil {
			logger.L().Warning("RBCache - failed to parse ns selector", helpers.String("ruleBiding", uniqueName(&rb)), helpers.Error(err))
			continue
		}
		nsSelectorStr := nsSelector.String()
		if len(nsSelectorStr) != 0 {
			// get related namespaces
			namespaces, err := c.k8sClient.GetKubernetesClient().CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: nsSelectorStr})
			if err != nil {
				logger.L().Warning("RBCache - failed to list namespaces", helpers.String("ruleBiding", uniqueName(&rb)), helpers.String("nsSelector", nsSelectorStr), helpers.Error(err))
				continue
			}
			if !namespaceListHasName(namespaces, pod.GetNamespace()) {
				// namespace selectors dont match
				continue
			}
		}

		// selectors match, add the rule binding to the pod
		if rbNames, ok := c.podToRBNames.Load(podName); !ok {
			c.podToRBNames.Set(podName, mapset.NewSet[string](rbName))
		} else {
			rbNames.Add(rbName)
		}

		if pods, ok := c.rbNameToPods.Load(rbName); !ok {
			c.rbNameToPods.Set(rbName, mapset.NewSet[string](podName))
		} else {
			pods.Add(podName)
		}
		logger.L().Debug("RBCache - adding pod to roleBinding", helpers.String("pod", podName), helpers.String("ruleBinding", rbName))

		n := rulebindingmanager.NewRuleBindingNotifierImpl(rulebindingmanager.Added, *pod)
		rbs = append(rbs, n)
	}
	return rbs
}

func (c *RBCache) deletePod(uniqueName string) {
	c.allPods.Remove(uniqueName)
	c.podToBundle.Delete(uniqueName)

	// selectors match, add the rule binding to the pod
	if rbNames, ok := c.podToRBNames.Load(uniqueName); ok {
		rbNames.Each(func(name string) bool {
			if pods, ok := c.rbNameToPods.Load(name); ok {
				pods.Remove(uniqueName)
			}
			return false
		})
	}
	c.podToRBNames.Delete(uniqueName)
}

func (c *RBCache) createRules(rulesForPod []typesv1.RuntimeAlertRuleBindingRule) []rulemanagertypesv1.Rule {
	var rules []rulemanagertypesv1.Rule
	// Get the rules that are bound to the container
	for _, ruleParams := range rulesForPod {
		rules = append(rules, c.createRule(&ruleParams)...)
	}
	return rules
}

// createRule expands one rule-binding entry into the rules it contributes.
//
// A by-ID or by-name entry contributes EVERY variant of that rule: the
// cluster-wide one plus each signed bundle overlay carrying the same ID/name.
// Selecting between them is not this function's job — it has no pod and
// therefore no bundle. ListRulesForPod does it later via scopeRulesToBundle,
// which drops the overlays belonging to other bundles and lets the matching
// overlay override the cluster-wide rule. Resolving to a single rule here (as
// the by-ID/by-name path used to) would make that override unreachable for the
// common binding that names its rules explicitly.
//
// Every contributed variant receives the binding's prefilter parameters, exactly
// as before: the binding tunes the detection, the fragment defines it.
func (c *RBCache) createRule(r *typesv1.RuntimeAlertRuleBindingRule) []rulemanagertypesv1.Rule {
	if r.RuleID != "" {
		rules := c.ruleCreator.CreateRulesByID(r.RuleID)
		if len(rules) == 0 {
			// No rule with that ID. Keep the historical shape (one zero-valued
			// rule) so consumers counting bound rules — e.g.
			// HasApplicableRuleBindings — behave exactly as before for bindings
			// that name a rule the agent does not know.
			rules = []rulemanagertypesv1.Rule{c.ruleCreator.CreateRuleByID(r.RuleID)}
		}
		for i := range rules {
			rules[i].Prefilter = prefilter.ParseWithDefaults(rules[i].State, r.Parameters)
		}
		return rules
	}
	if r.RuleName != "" {
		rules := c.ruleCreator.CreateRulesByName(r.RuleName)
		if len(rules) == 0 {
			rules = []rulemanagertypesv1.Rule{c.ruleCreator.CreateRuleByName(r.RuleName)}
		}
		for i := range rules {
			rules[i].Prefilter = prefilter.ParseWithDefaults(rules[i].State, r.Parameters)
		}
		return rules
	}
	if len(r.RuleTags) > 0 {
		rules := c.ruleCreator.CreateRulesByTags(r.RuleTags)
		for i := range rules {
			rules[i].Prefilter = prefilter.ParseWithDefaults(rules[i].State, r.Parameters)
		}
		return rules
	}

	return []rulemanagertypesv1.Rule{}
}

// Expose the rule creator to be able to create rules from third party.
func (c *RBCache) GetRuleCreator() rulecreator.RuleCreator {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.ruleCreator
}

func diff(a, b []rulebindingmanager.RuleBindingNotify) []rulebindingmanager.RuleBindingNotify {
	m := make(map[string]rulebindingmanager.RuleBindingNotify)
	diff := make([]rulebindingmanager.RuleBindingNotify, 0)

	for i := range a {
		m[uniqueName(&a[i].Pod)] = a[i]
	}

	for i := range b {
		n := uniqueName(&b[i].Pod)
		if _, found := m[n]; !found {
			diff = append(diff, b[i])
		} else {
			delete(m, n)
		}
	}

	for i := range m {
		diff = append(diff, m[i])
	}

	return diff
}

func (c *RBCache) getRules() []rulemanagertypesv1.Rule {
	return c.ruleCreator.CreateAllRules()
}
