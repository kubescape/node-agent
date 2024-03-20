package rulebindingmanager

import (
	"context"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/rulebindingmanager/types/v1"
	"node-agent/pkg/ruleengine"
	ruleenginev1 "node-agent/pkg/ruleengine/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type RBCache struct {
	nodeName         string
	k8sClient        k8sclient.K8sClientInterface
	globalRBNames    mapset.Set[string]                                  // rules without selectors
	podToRBNames     maps.SafeMap[string, mapset.Set[string]]            // pod name -> []rule binding names
	rbNameToRB       maps.SafeMap[string, types.RuntimeAlertRuleBinding] // rule binding name -> rule binding
	rbNameToRules    maps.SafeMap[string, []ruleengine.RuleEvaluator]    // rule binding name -> []created rules
	rbNameToPodNames maps.SafeMap[string, mapset.Set[string]]            // rule binding name -> []pod names
	ruleCreator      ruleengine.RuleCreator
}

func NewCache(nodeName string, k8sClient k8sclient.K8sClientInterface) *RBCache {
	return &RBCache{
		nodeName:         nodeName,
		k8sClient:        k8sClient,
		ruleCreator:      ruleenginev1.NewRuleCreator(),
		globalRBNames:    mapset.NewSet[string](),
		podToRBNames:     maps.SafeMap[string, mapset.Set[string]]{},
		rbNameToPodNames: maps.SafeMap[string, mapset.Set[string]]{},
	}
}

func (c *RBCache) AddRuleBinding(ruleBinding *types.RuntimeAlertRuleBinding) {
	rbName := ruleBinding.GetName()
	logger.L().Info("AddRuleBinding", helpers.String("name", rbName))

	// convert selectors to string
	nsSelector, err := metav1.LabelSelectorAsSelector(&ruleBinding.Spec.NamespaceSelector)
	// check if the selectors are valid
	if err != nil {
		logger.L().Error("failed to parse ns selector", helpers.String("ruleBiding", rbName), helpers.Interface("NamespaceSelector", ruleBinding.Spec.NamespaceSelector), helpers.Error(err))
		return
	}
	podSelector, err := metav1.LabelSelectorAsSelector(&ruleBinding.Spec.PodSelector)
	// check if the selectors are valid
	if err != nil {
		logger.L().Error("failed to parse pod selector", helpers.String("ruleBiding", rbName), helpers.Interface("PodSelector", ruleBinding.Spec.PodSelector), helpers.Error(err))
		return
	}

	nsSelectorStr := nsSelector.String()
	podSelectorStr := podSelector.String()

	// add the rule binding to the cache
	c.rbNameToRB.Set(rbName, *ruleBinding)
	c.rbNameToPodNames.Set(rbName, mapset.NewSet[string]())
	c.rbNameToRules.Set(rbName, []ruleengine.RuleEvaluator{})

	// if the rule binding is global, add it to the global rules
	if len(nsSelectorStr) == 0 && len(podSelectorStr) == 0 {
		c.globalRBNames.Add(ruleBinding.GetName())
		logger.L().Debug("AddRuleBinding", helpers.String("ruleBinding", rbName), helpers.String("global", "true"))
		return
	}

	// get related namespaces
	namespaces, err := c.k8sClient.GetKubernetesClient().CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{LabelSelector: nsSelectorStr})
	if err != nil {
		logger.L().Error("failed to list namespaces", helpers.String("ruleBiding", rbName), helpers.String("nsSelector", nsSelectorStr), helpers.Error(err))
		return
	}

	// get related pods
	for _, ns := range namespaces.Items {
		lp := metav1.ListOptions{
			LabelSelector: podSelectorStr,
			FieldSelector: "spec.nodeName=" + c.nodeName,
		}
		pods, err := c.k8sClient.GetKubernetesClient().CoreV1().Pods(ns.GetName()).List(context.Background(), lp)
		if err != nil {
			logger.L().Error("failed to list pods", helpers.String("ruleBiding", rbName), helpers.String("podSelector", podSelectorStr), helpers.Error(err))
			return
		}

		for _, pod := range pods.Items {
			podName := pod.GetName()
			if !c.podToRBNames.Has(podName) {
				c.podToRBNames.Set(podName, mapset.NewSet[string]())
			}

			c.podToRBNames.Get(podName).Add(rbName)
			c.rbNameToPodNames.Get(rbName).Add(podName)
			c.rbNameToRules.Set(rbName, c.createRules(ruleBinding.Spec.Rules))

			logger.L().Debug("AddRuleBinding", helpers.String("ruleBinding", rbName), helpers.String("pod", podName))
		}
	}
}
func (c *RBCache) DeleteRuleBinding(ruleBinding *types.RuntimeAlertRuleBinding) {
	rbName := ruleBinding.GetName()
	logger.L().Info("DeleteRuleBinding", helpers.String("name", rbName))

	// remove the rule binding from the pods
	for _, podName := range c.podToRBNames.Keys() {
		c.podToRBNames.Get(podName).Remove(rbName)
	}

	// remove the rule binding from the cache
	c.rbNameToRB.Delete(rbName)
	c.rbNameToRules.Delete(rbName)
	c.rbNameToPodNames.Delete(rbName)
	c.globalRBNames.Remove(rbName)
}

func (c *RBCache) ListRuleBindings() []types.RuntimeAlertRuleBinding {
	return c.rbNameToRB.Values()
}

func (c *RBCache) ListRulesForPod(namespace, podName string) ([]ruleengine.RuleEvaluator, error) {
	ruleBindingsForPod := c.ListRuleBindings()
	// // TODO: change to support parameters of rule + custom priority
	// ruleBindingsForPod, err := c.listRuleBindingsForPod(namespace, podName)
	// if err != nil {
	// 	return nil, err
	// }

	var rulesSlice []types.RuntimeAlertRuleBindingRule
	for _, ruleBinding := range ruleBindingsForPod {
		rulesSlice = append(rulesSlice, ruleBinding.Spec.Rules...)
	}

	createdRules := c.createRules(rulesSlice)

	return createdRules, nil
}

func (c *RBCache) createRules(rulesForPod []types.RuntimeAlertRuleBindingRule) []ruleengine.RuleEvaluator {
	rules := []ruleengine.RuleEvaluator{}
	// Get the rules that are bound to the container
	for _, ruleParams := range rulesForPod {
		rules = append(rules, c.createRule(&ruleParams)...)
	}
	return rules
}
func (c *RBCache) createRule(r *types.RuntimeAlertRuleBindingRule) []ruleengine.RuleEvaluator {

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

// func (c *Cache) listRuleBindingsForPod(namespace, podName string) ([]types.RuntimeAlertRuleBinding, error) {
// 	allBindings := c.ListRuleBindings()
// 	var ruleBindingsForPod []types.RuntimeAlertRuleBinding

// 	for _, ruleBinding := range allBindings {
// 		// check the namespace selector fits the pod namespace
// 		nsLabelSelector := ruleBinding.Spec.NamespaceSelector
// 		if len(nsLabelSelector.MatchLabels) != 0 || len(nsLabelSelector.MatchExpressions) != 0 {
// 			selectorString := metav1.FormatLabelSelector(&nsLabelSelector)
// 			nss, err := c.coreV1Client.Namespaces().List(context.Background(), metav1.ListOptions{LabelSelector: selectorString, Limit: 1})
// 			if err != nil {
// 				return nil, fmt.Errorf("failed to get namespaces for selector %s: %v", selectorString, err)
// 			}
// 			if len(nss.Items) == 0 {
// 				continue
// 			}
// 			// check namespace
// 		} else if ns, ok := nsLabelSelector.MatchLabels["kubernetes.io/metadata.name"]; ok && ns != namespace {
// 			// namespace selector doesn't match the pod namespace
// 			continue
// 		}

// 		selectorString := metav1.FormatLabelSelector(&ruleBinding.Spec.PodSelector)
// 		if selectorString == "<none>" {
// 			// This rule binding applies to all pods in the namespace
// 			ruleBindingsForPod = append(ruleBindingsForPod, ruleBinding)
// 			continue
// 		} else if selectorString == "<error>" {
// 			return nil, fmt.Errorf("failed to parse pod selector in ruleBinding.spec %s", selectorString)
// 		}
// 		pods, err := ruleInformer.coreV1Client.Pods(namespace).List(context.Background(),
// 			metav1.ListOptions{
// 				LabelSelector: selectorString,
// 				FieldSelector: "spec.nodeName=" + c.nodeName,
// 			},
// 		)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to get pods for selector %s: %v", selectorString, err)
// 		}
// 		if len(pods.Items) == 0 {
// 			continue
// 		}
// 		for _, pod := range pods.Items {
// 			if pod.Name == podName {
// 				ruleBindingsForPod = append(ruleBindingsForPod, ruleBinding)
// 				break
// 			}
// 		}
// 	}

// 	return ruleBindingsForPod, nil
// }

// func (c *Cache) OnRuleBindingChanged(ruleBinding types.RuntimeAlertRuleBinding) {
// 	log.Printf("OnRuleBindingChanged: %s\n", ruleBinding.Name)
// 	// list all namespaces which match the rule binding selectors
// 	selectorString := metav1.FormatLabelSelector(&ruleBinding.Spec.NamespaceSelector)
// 	if selectorString == "<none>" {
// 		selectorString = ""
// 	} else if selectorString == "<error>" {
// 		log.Errorf("Failed to parse namespace selector for rule binding %s\n", ruleBinding.Name)
// 		return
// 	}
// 	nsList, err := engine.k8sClientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{
// 		LabelSelector: selectorString,
// 	})
// 	if err != nil {
// 		log.Errorf("Failed to list namespaces: %v\n", err)
// 		return
// 	}
// 	podsMap := make(map[string]struct{})
// 	podSelectorString := metav1.FormatLabelSelector(&ruleBinding.Spec.PodSelector)
// 	if podSelectorString == "<none>" {
// 		podSelectorString = ""
// 	} else if podSelectorString == "<error>" {
// 		log.Errorf("Failed to parse pod selector for rule binding %s\n", ruleBinding.Name)
// 		return
// 	}
// 	for _, ns := range nsList.Items {
// 		// list all pods in the namespace which match the rule binding selectors
// 		podList, err := engine.k8sClientset.CoreV1().Pods(ns.Name).List(context.TODO(), metav1.ListOptions{
// 			LabelSelector: podSelectorString,
// 			FieldSelector: "spec.nodeName=" + engine.nodeName,
// 		})
// 		if err != nil {
// 			log.Errorf("Failed to list pods in namespace %s: %v\n", ns.Name, err)
// 			continue
// 		}
// 		for _, pod := range podList.Items {
// 			podsMap[fullPodName(ns.Name, pod.Name)] = struct{}{}
// 		}
// 	}

// 	for _, det := range getcontainerIdToDetailsCacheCopy() {
// 		if _, ok := podsMap[fullPodName(det.Namespace, det.PodName)]; ok {
// 			go engine.associateRulesWithContainerInCache(det, true)
// 		}
// 	}
// }

// func (engine *Engine) OnContainerActivityEvent(event *tracing.ContainerActivityEvent) {
// 	if event.Activity == tracing.ContainerActivityEventStart || event.Activity == tracing.ContainerActivityEventAttached {

// 		attached := event.Activity == tracing.ContainerActivityEventAttached

// 		ownerRef, err := getHighestOwnerOfPod(engine.k8sClientset, event.PodName, event.Namespace)
// 		if err != nil {
// 			log.Errorf("Failed to get highest owner of pod %s/%s: %v\n", event.Namespace, event.PodName, err)
// 			return
// 		}

// 		// Load application profile if it exists
// 		err = engine.applicationProfileCache.LoadApplicationProfile(event.Namespace, "Pod", event.PodName, ownerRef.Kind, ownerRef.Name, event.ContainerName, event.ContainerID, attached)
// 		if err != nil {
// 			// Ask cache to load the application profile when/if it becomes available
// 			err = engine.applicationProfileCache.AnticipateApplicationProfile(event.Namespace, "Pod", event.PodName, ownerRef.Kind, ownerRef.Name, event.ContainerName, event.ContainerID, attached)
// 			if err != nil {
// 				log.Errorf("Failed to anticipate application profile for container %s/%s/%s/%s: %v\n", event.Namespace, ownerRef.Kind, ownerRef.Name, event.ContainerName, err)
// 			}
// 		}

// 		podSpec, err := engine.fetchPodSpec(event.PodName, event.Namespace)
// 		if err != nil {
// 			log.Errorf("Failed to get pod spec for pod %s/%s: %v\n", event.Namespace, event.PodName, err)
// 			return
// 		}

// 		contEntry := containerEntry{
// 			ContainerID:   event.ContainerID,
// 			ContainerName: event.ContainerName,
// 			PodName:       event.PodName,
// 			Namespace:     event.Namespace,
// 			OwnerKind:     ownerRef.Kind,
// 			OwnerName:     ownerRef.Name,
// 			NsMntId:       event.NsMntId,
// 			AttachedLate:  event.Activity == tracing.ContainerActivityEventAttached,
// 			PodSpec:       podSpec,
// 		}

// 		err = engine.associateRulesWithContainerInCache(contEntry, false)
// 		if err != nil {
// 			log.Errorf("Failed to add container details to cache: %v\n", err)
// 		}

// 		appliedContainerEntry, ok := getContainerDetails(event.ContainerID)
// 		if !ok {
// 			log.Errorf("Failed to get container details from cache\n")
// 			return
// 		}

// 		// Start tracing the container
// 		neededEvents := map[tracing.EventType]bool{}
// 		for _, rule := range appliedContainerEntry.BoundRules {
// 			for _, needEvent := range rule.Requirements().EventTypes {
// 				neededEvents[needEvent] = true
// 			}
// 		}
// 		for neededEvent := range neededEvents {
// 			if engine.tracer != nil {
// 				_ = engine.tracer.StartTraceContainer(event.NsMntId, event.Pid, neededEvent)
// 			}
// 		}

// 	} else if event.Activity == tracing.ContainerActivityEventStop {
// 		go func() {
// 			containerIdToDetailsCacheLock.RLock()
// 			eventsInUse := GetRequiredEventsFromRules(containerIdToDetailsCache[event.ContainerID].BoundRules)
// 			containerIdToDetailsCacheLock.RUnlock()

// 			// Stop tracing the container
// 			for _, eventInUse := range eventsInUse {
// 				if engine.tracer != nil {
// 					_ = engine.tracer.StopTraceContainer(event.NsMntId, event.Pid, eventInUse)
// 				}
// 			}

// 			// Remove the container from the cache
// 			deleteContainerDetails(event.ContainerID)

// 			// Remove the container from the cache
// 			containerIdToDetailsCacheLock.Lock()
// 			delete(containerIdToDetailsCache, event.ContainerID)
// 			containerIdToDetailsCacheLock.Unlock()
// 		}()
// 	}
// }

// func GetRequiredEventsFromRules(rules []rule.Rule) []tracing.EventType {
// 	neededEvents := map[tracing.EventType]bool{}
// 	for _, rule := range rules {
// 		for _, needEvent := range rule.Requirements().EventTypes {
// 			neededEvents[needEvent] = true
// 		}
// 	}
// 	var ret []tracing.EventType
// 	for neededEvent := range neededEvents {
// 		ret = append(ret, neededEvent)
// 	}
// 	return ret
// }

// func (engine *Engine) associateRulesWithContainerInCache(contEntry containerEntry, exists bool) error {
// 	// Get the rules that are bound to the container
// 	ruleParamsSlc, err := engine.getRulesForPodFunc(contEntry.PodName, contEntry.Namespace)
// 	if err != nil {
// 		return fmt.Errorf("failed to get rules for pod %s/%s: %v", contEntry.Namespace, contEntry.PodName, err)
// 	}

// 	ruleDescs := make([]rule.Rule, 0, len(ruleParamsSlc))
// 	for _, ruleParams := range ruleParamsSlc {
// 		if ruleParams.RuleName != "" {
// 			ruleDesc := rule.CreateRuleByName(ruleParams.RuleName)
// 			if ruleDesc != nil {
// 				if ruleParams.Parameters != nil {
// 					ruleDesc.SetParameters(ruleParams.Parameters)
// 				}
// 				ruleDescs = append(ruleDescs, ruleDesc)
// 			}
// 			continue
// 		}
// 		if ruleParams.RuleID != "" {
// 			ruleDesc := rule.CreateRuleByID(ruleParams.RuleID)
// 			if ruleDesc != nil {
// 				if ruleParams.Parameters != nil {
// 					ruleDesc.SetParameters(ruleParams.Parameters)
// 				}
// 				ruleDescs = append(ruleDescs, ruleDesc)
// 			}
// 			continue
// 		}
// 		if len(ruleParams.RuleTags) > 0 {
// 			ruleTagsDescs := rule.CreateRulesByTags(ruleParams.RuleTags)
// 			if ruleDescs != nil {
// 				for _, ruleDesc := range ruleTagsDescs {
// 					if ruleParams.Parameters != nil {
// 						ruleDesc.SetParameters(ruleParams.Parameters)
// 					}
// 				}
// 				ruleDescs = append(ruleDescs, ruleTagsDescs...)
// 			}
// 			continue
// 		}
// 		log.Printf("No rule name, id or tags specified for rule binding \n")
// 	}

// 	contEntry.BoundRules = ruleDescs
// 	// Add the container to the cache
// 	setContainerDetails(contEntry.ContainerID, contEntry, exists)
// 	return nil
// }

// func (engine *Engine) GetRulesForEvent(event *tracing.GeneralEvent) []rule.Rule {
// 	eventContainerId := event.ContainerID
// 	if eventContainerId == "" {
// 		return []rule.Rule{}
// 	}
// 	// Get the container details from the cache
// 	containerDetails, ok := getContainerDetails(eventContainerId)
// 	if !ok {
// 		return []rule.Rule{}
// 	}
// 	return containerDetails.BoundRules
// }
