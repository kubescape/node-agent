package cache

import (
	"node-agent/pkg/rulebindingmanager/types/v1"
	"node-agent/pkg/ruleengine"

	"github.com/goradd/maps"
)

type Cache struct {
	// k8sAPI *k8sinterface.KubernetesApi
	// PodToRules        maps.SafeMap[string, []types.RuntimeAlertRuleBindingRule] // podName -> rules (names)
	// GlobalRules       []types.RuntimeAlertRuleBindingRule                       // all rules that are not bound to a specific pod
	// RuleBindingToPods maps.SafeMap[string, mapset.Set[string]]                  // rule binding name -> pod names
	RuleBindings maps.SafeMap[string, types.RuntimeAlertRuleBinding] // rule binding name -> rule binding
	ruleCreator  ruleengine.RuleCreator
}

func NewCache() *Cache {
	return &Cache{
		// RuleBindingToPods: maps.SafeMap[string, mapset.Set[string]]{},
	}
}

func (c *Cache) AddRuleBinding(ruleBinding types.RuntimeAlertRuleBinding) {
	c.RuleBindings.Set(ruleBinding.GetName(), ruleBinding)
}
func (c *Cache) RemoveRuleBinding(ruleBinding types.RuntimeAlertRuleBinding) {
	c.RuleBindings.Delete(ruleBinding.GetName())
}

func (c *Cache) ListRuleBindings() []types.RuntimeAlertRuleBinding {
	return c.RuleBindings.Values()
}

func (c *Cache) ListRulesForPod(namespace, podName string) ([]ruleengine.RuleEvaluator, error) {
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

func (c *Cache) createRules(rulesForPod []types.RuntimeAlertRuleBindingRule) []ruleengine.RuleEvaluator {
	rules := []ruleengine.RuleEvaluator{}
	// Get the rules that are bound to the container
	for _, ruleParams := range rulesForPod {
		rules = append(rules, c.createRule(&ruleParams)...)
	}
	return rules
}
func (c *Cache) createRule(r *types.RuntimeAlertRuleBindingRule) []ruleengine.RuleEvaluator {

	if r.RuleName != "" {
		ruleDesc := c.ruleCreator.CreateRuleByName(r.RuleName)
		if ruleDesc != nil {
			if r.Parameters != nil {
				ruleDesc.SetParameters(r.Parameters)
			}
		}
		return []ruleengine.RuleEvaluator{ruleDesc}
	}
	if r.RuleID != "" {
		ruleDesc := c.ruleCreator.CreateRuleByID(r.RuleID)
		if ruleDesc != nil {
			if r.Parameters != nil {
				ruleDesc.SetParameters(r.Parameters)
			}
		}
		return []ruleengine.RuleEvaluator{ruleDesc}
	}
	if len(r.RuleTags) > 0 {
		ruleTagsDescs := c.ruleCreator.CreateRulesByTags(r.RuleTags)
		if r != nil {
			for _, ruleDesc := range ruleTagsDescs {
				if r.Parameters != nil {
					ruleDesc.SetParameters(r.Parameters)
				}
			}
		}
		return ruleTagsDescs
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
