package cache

import (
	"context"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"
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

type RBCache struct {
	nodeName       string
	k8sClient      k8sclient.K8sClientInterface
	allPods        mapset.Set[string]                                    // set of all pods (also pods without rules)
	podToRBNames   maps.SafeMap[string, mapset.Set[string]]              // podID -> []rule binding names
	rbNameToRB     maps.SafeMap[string, typesv1.RuntimeAlertRuleBinding] // rule binding name -> rule binding
	rbNameToRules  maps.SafeMap[string, []ruleengine.RuleEvaluator]      // rule binding name -> []created rules
	rbNameToPods   maps.SafeMap[string, mapset.Set[string]]              // rule binding name -> podIDs
	ruleCreator    ruleengine.RuleCreator
	watchResources []watcher.WatchResource
	notifiers      []*chan rulebindingmanager.RuleBindingNotify
}

func NewCache(nodeName string, k8sClient k8sclient.K8sClientInterface) *RBCache {
	return &RBCache{
		nodeName:       nodeName,
		k8sClient:      k8sClient,
		ruleCreator:    ruleenginev1.NewRuleCreator(),
		allPods:        mapset.NewSet[string](),
		rbNameToRB:     maps.SafeMap[string, typesv1.RuntimeAlertRuleBinding]{},
		podToRBNames:   maps.SafeMap[string, mapset.Set[string]]{},
		rbNameToPods:   maps.SafeMap[string, mapset.Set[string]]{},
		watchResources: resourcesToWatch(nodeName),
	}
}

// ----------------- watcher.WatchResources methods -----------------

func (c *RBCache) WatchResources() []watcher.WatchResource {
	return c.watchResources
}

// ------------------ rulebindingmanager.RuleBindingCache methods -----------------------

func (c *RBCache) ListRulesForPod(namespace, name string) []ruleengine.RuleEvaluator {
	var rulesSlice []ruleengine.RuleEvaluator

	podID := utils.CreateK8sPodID(namespace, name)
	if !c.podToRBNames.Has(podID) {
		return rulesSlice
	}

	//append rules for pod
	rbNames := c.podToRBNames.Get(podID)
	for _, i := range rbNames.ToSlice() {
		if c.rbNameToRules.Has(i) {
			rulesSlice = append(rulesSlice, c.rbNameToRules.Get(i)...)
		}
	}

	return rulesSlice
}

func (c *RBCache) AddNotifier(n *chan rulebindingmanager.RuleBindingNotify) {
	c.notifiers = append(c.notifiers, n)
}

// ------------------ watcher.Watcher methods -----------------------

func (c *RBCache) AddHandler(ctx context.Context, obj runtime.Object) {
	var rbs []rulebindingmanager.RuleBindingNotify

	if pod, ok := obj.(*corev1.Pod); ok {
		rbs = c.addPod(ctx, pod)
	} else if un, ok := obj.(*unstructured.Unstructured); ok {
		ruleBinding, err := unstructuredToRuleBinding(un)
		if err != nil {
			logger.L().Error("failed to convert unstructured to rule binding", helpers.Error(err))
			return
		}
		rbs = c.addRuleBinding(ruleBinding)
	}
	// notify
	for n := range c.notifiers {
		for i := range rbs {
			*c.notifiers[n] <- rbs[i]
		}
	}
}

func (c *RBCache) ModifyHandler(ctx context.Context, obj runtime.Object) {
	var rbs []rulebindingmanager.RuleBindingNotify

	if pod, ok := obj.(*corev1.Pod); ok {
		rbs = c.addPod(ctx, pod)
	} else if un, ok := obj.(*unstructured.Unstructured); ok {
		ruleBinding, err := unstructuredToRuleBinding(un)
		if err != nil {
			logger.L().Error("failed to convert unstructured to rule binding", helpers.Error(err))
			return
		}
		rbs = c.modifiedRuleBinding(ruleBinding)
	}
	// notify
	for n := range c.notifiers {
		for i := range rbs {
			*c.notifiers[n] <- rbs[i]
		}
	}
}

func (c *RBCache) DeleteHandler(_ context.Context, obj runtime.Object) {
	var rbs []rulebindingmanager.RuleBindingNotify

	if pod, ok := obj.(*corev1.Pod); ok {
		c.deletePod(uniqueName(pod))
	} else if un, ok := obj.(*unstructured.Unstructured); ok {
		rbs = c.deleteRuleBinding(uniqueName(un))
	}

	// notify
	for n := range c.notifiers {
		for i := range rbs {
			*c.notifiers[n] <- rbs[i]
		}
	}
}

// ----------------- RuleBinding manager methods -----------------

// AddRuleBinding adds a rule binding to the cache
func (c *RBCache) addRuleBinding(ruleBinding *typesv1.RuntimeAlertRuleBinding) []rulebindingmanager.RuleBindingNotify {
	var rbs []rulebindingmanager.RuleBindingNotify
	rbName := uniqueName(ruleBinding)
	logger.L().Info("RuleBinding added/modified", helpers.String("name", rbName))

	// convert selectors to string
	nsSelector, err := metav1.LabelSelectorAsSelector(&ruleBinding.Spec.NamespaceSelector)
	// check if the selectors are valid
	if err != nil {
		logger.L().Error("failed to parse ns selector", helpers.String("ruleBiding", rbName), helpers.Interface("NamespaceSelector", ruleBinding.Spec.NamespaceSelector), helpers.Error(err))
		return rbs
	}
	podSelector, err := metav1.LabelSelectorAsSelector(&ruleBinding.Spec.PodSelector)
	// check if the selectors are valid
	if err != nil {
		logger.L().Error("failed to parse pod selector", helpers.String("ruleBiding", rbName), helpers.Interface("PodSelector", ruleBinding.Spec.PodSelector), helpers.Error(err))
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
		logger.L().Error("failed to list namespaces", helpers.String("ruleBiding", rbName), helpers.String("nsSelector", nsSelectorStr), helpers.Error(err))
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
			logger.L().Error("failed to list pods", helpers.String("ruleBiding", rbName), helpers.String("podSelector", podSelectorStr), helpers.Error(err))
			return rbs
		}

		for _, pod := range pods.Items {
			podName := uniqueName(&pod)
			if !c.podToRBNames.Has(podName) {
				c.podToRBNames.Set(podName, mapset.NewSet[string]())
			}

			c.podToRBNames.Get(podName).Add(rbName)
			c.rbNameToPods.Get(rbName).Add(podName)

			if len(c.notifiers) == 0 {
				continue
			}
			n := rulebindingmanager.NewRuleBindingNotifierImpl(rulebindingmanager.Added, pod)
			rbs = append(rbs, n)

			logger.L().Debug("ruleBinding attached to pod", helpers.String("ruleBinding", rbName), helpers.String("pod", podName))
		}
	}
	return rbs
}
func (c *RBCache) deleteRuleBinding(uniqueName string) []rulebindingmanager.RuleBindingNotify {
	logger.L().Info("RuleBinding deleted", helpers.String("name", uniqueName))
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
			logger.L().Warning("failed to create notifier", helpers.String("namespace", namespace), helpers.String("name", name), helpers.Error(err))
			continue
		}

		rbs = append(rbs, n)
	}

	// remove the rule binding from the cache
	c.rbNameToRB.Delete(uniqueName)
	c.rbNameToRules.Delete(uniqueName)
	c.rbNameToPods.Delete(uniqueName)

	logger.L().Info("DeleteRuleBinding", helpers.String("name", uniqueName))
	return rbs
}

func (c *RBCache) modifiedRuleBinding(ruleBinding *typesv1.RuntimeAlertRuleBinding) []rulebindingmanager.RuleBindingNotify {
	rbsD := c.deleteRuleBinding(uniqueName(ruleBinding))
	rbsA := c.addRuleBinding(ruleBinding)

	return diff(rbsD, rbsA)
}

// ----------------- Pod manager methods -----------------

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
		podSelector, _ := metav1.LabelSelectorAsSelector(&rb.Spec.PodSelector)
		if !podSelector.Matches(labels.Set(pod.GetLabels())) {
			// pod selectors doesnt match
			continue
		}

		// check namespace selectors
		nsSelector, _ := metav1.LabelSelectorAsSelector(&rb.Spec.NamespaceSelector)
		nsSelectorStr := nsSelector.String()
		if len(nsSelectorStr) != 0 {
			// get related namespaces
			namespaces, err := c.k8sClient.GetKubernetesClient().CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: nsSelectorStr})
			if err != nil {
				logger.L().Error("failed to list namespaces", helpers.String("ruleBiding", uniqueName(&rb)), helpers.String("nsSelector", nsSelectorStr), helpers.Error(err))
				continue
			}
			if !strings.Contains(namespaces.String(), pod.GetNamespace()) {
				// namespace selectors dont match
				continue
			}
		}

		// selectors match, add the rule binding to the pod
		if !c.podToRBNames.Has(podName) {
			c.podToRBNames.Set(podName, mapset.NewSet[string](rbName))
		} else {
			c.podToRBNames.Get(podName).Add(rbName)
		}

		if !c.rbNameToPods.Has(rbName) {
			c.rbNameToPods.Set(rbName, mapset.NewSet[string](podName))
		} else {
			c.rbNameToPods.Get(rbName).Add(podName)
		}
		logger.L().Debug("adding pod to roleBinding", helpers.String("pod", podName), helpers.String("ruleBinding", rbName))

		n := rulebindingmanager.NewRuleBindingNotifierImpl(rulebindingmanager.Added, *pod)
		rbs = append(rbs, n)
	}
	return rbs
}

func (c *RBCache) deletePod(uniqueName string) {
	c.allPods.Remove(uniqueName)

	// selectors match, add the rule binding to the pod
	var rbNames []string
	if c.podToRBNames.Has(uniqueName) {
		rbNames = c.podToRBNames.Get(uniqueName).ToSlice()
	}

	for i := range rbNames {
		if c.rbNameToPods.Has(rbNames[i]) {
			c.rbNameToPods.Get(rbNames[i]).Remove(uniqueName)
		}
	}
	c.podToRBNames.Delete(uniqueName)
}

func (c *RBCache) createRules(rulesForPod []typesv1.RuntimeAlertRuleBindingRule) []ruleengine.RuleEvaluator {
	var rules []ruleengine.RuleEvaluator
	// Get the rules that are bound to the container
	for _, ruleParams := range rulesForPod {
		rules = append(rules, c.createRule(&ruleParams)...)
	}
	return rules
}
func (c *RBCache) createRule(r *typesv1.RuntimeAlertRuleBindingRule) []ruleengine.RuleEvaluator {

	if r.RuleID != "" {
		if ruleDesc := c.ruleCreator.CreateRuleByID(r.RuleID); ruleDesc != nil {
			if r.Parameters != nil {
				ruleDesc.SetParameters(r.Parameters)
			}
			return []ruleengine.RuleEvaluator{ruleDesc}
		}
	}
	if r.RuleName != "" {
		if ruleDesc := c.ruleCreator.CreateRuleByName(r.RuleName); ruleDesc != nil {
			if r.Parameters != nil {
				ruleDesc.SetParameters(r.Parameters)
			}
			return []ruleengine.RuleEvaluator{ruleDesc}
		}
	}
	if len(r.RuleTags) > 0 {
		if ruleTagsDescs := c.ruleCreator.CreateRulesByTags(r.RuleTags); ruleTagsDescs != nil {
			for _, ruleDesc := range ruleTagsDescs {
				if r.Parameters != nil {
					ruleDesc.SetParameters(r.Parameters)
				}
			}
			return ruleTagsDescs
		}
	}
	return []ruleengine.RuleEvaluator{}
}

// Expose the rule creator to be able to create rules from third party.
func (c *RBCache) GetRuleCreator() ruleengine.RuleCreator {
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
