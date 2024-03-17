package rulebindingmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"node-agent/pkg/rulebindingmanager/types/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
)

const RuntimeRuleBindingAlertPlural = "runtimerulealertbindings"

const (
	RuleBinderGroup string = "kubescape.io"

	// ApplicationProfileVersion is the version of ApplicationProfile
	// TODO: we should prbably set to v1alpha1
	RuleBinderVersion string = "v1"

	// ApplicationProfileApiVersion is the api version of ApplicationProfile
	RuleBinderApiVersion string = RuleBinderGroup + "/" + RuleBinderVersion
)

var RuleBindingAlertGvr schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    RuleBinderGroup,
	Version:  RuleBinderVersion,
	Resource: RuntimeRuleBindingAlertPlural,
}

type dynClient interface {
	Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface
}
type RuleBindingChangedHandler func(ruleBinding types.RuntimeAlertRuleBinding)

type RuleBindingK8sInformer struct {
	dynamicClient       dynClient
	coreV1Client        v1.CoreV1Interface
	informerStopChannel chan struct{}
	nodeName            string
	storeNamespace      string

	// functions to call upon a change in a rule binding
	callBacks []RuleBindingChangedHandler
}

func NewRuleBindingK8sInformer(dynamicClient dynClient, coreV1Client v1.CoreV1Interface, nodeName, storeNamespace string) (*RuleBindingK8sInformer, error) {

	stopCh := make(chan struct{})
	if storeNamespace == "" {
		storeNamespace = metav1.NamespaceNone
	}

	ruleInformer := RuleBindingK8sInformer{
		dynamicClient:       dynamicClient,
		informerStopChannel: stopCh,
		nodeName:            nodeName,
		coreV1Client:        coreV1Client,
		storeNamespace:      storeNamespace,
	}

	// TODO: should not start in intialiaztion time, should be started by the caller
	ruleInformer.StartController()

	return &ruleInformer, nil
}

func (ruleInformer *RuleBindingK8sInformer) getAllRuleBindings() ([]types.RuntimeAlertRuleBinding, error) {
	ruleBindingList, err := ruleInformer.dynamicClient.Resource(RuleBindingAlertGvr).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	ruleBindingListBytes, err := ruleBindingList.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var ruleBindingListObj *types.RuntimeAlertRuleBindingList

	if err := json.Unmarshal(ruleBindingListBytes, &ruleBindingListObj); err != nil {
		return nil, err
	}

	return ruleBindingListObj.Items, nil
}

func (ruleInformer *RuleBindingK8sInformer) getRuleBindingsForPod(podName, namespace string) ([]types.RuntimeAlertRuleBinding, error) {
	allBindings, err := ruleInformer.getAllRuleBindings()
	if err != nil {
		return nil, err
	}

	var ruleBindingsForPod []types.RuntimeAlertRuleBinding
	for _, ruleBinding := range allBindings {
		// check the namespace selector fits the pod namespace
		nsLabelSelector := ruleBinding.Spec.NamespaceSelector
		if nsLabelSelector.MatchLabels == nil {
			nsLabelSelector.MatchLabels = make(map[string]string)
		} else if ns, ok := nsLabelSelector.MatchLabels["kubernetes.io/metadata.name"]; ok && ns != namespace {
			// namespace selector doesn't match the pod namespace
			continue
		}
		// according to https://kubernetes.io/docs/concepts/services-networking/network-policies/#targeting-a-namespace-by-its-name this should do the job
		nsLabelSelector.MatchLabels["kubernetes.io/metadata.name"] = namespace
		selectorString := metav1.FormatLabelSelector(&nsLabelSelector)

		// TODO: WHY??? why do we list the namespaces?
		nss, err := ruleInformer.coreV1Client.Namespaces().List(context.Background(), metav1.ListOptions{LabelSelector: selectorString, Limit: 1})
		if err != nil {
			return nil, fmt.Errorf("failed to get namespaces for selector %s: %v", selectorString, err)
		}
		if len(nss.Items) == 0 {
			continue
		}
		selectorString = metav1.FormatLabelSelector(&ruleBinding.Spec.PodSelector)
		if selectorString == "<none>" {
			// This rule binding applies to all pods in the namespace
			ruleBindingsForPod = append(ruleBindingsForPod, ruleBinding)
			continue
		} else if selectorString == "<error>" {
			return nil, fmt.Errorf("failed to parse pod selector in ruleBinding.spec %s", selectorString)
		}
		pods, err := ruleInformer.coreV1Client.Pods(namespace).List(context.Background(),
			metav1.ListOptions{
				LabelSelector: selectorString,
				FieldSelector: "spec.nodeName=" + ruleInformer.nodeName,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get pods for selector %s: %v", selectorString, err)
		}
		if len(pods.Items) == 0 {
			continue
		}
		for _, pod := range pods.Items {
			if pod.Name == podName {
				ruleBindingsForPod = append(ruleBindingsForPod, ruleBinding)
				break
			}
		}
	}

	return ruleBindingsForPod, nil
}

func (ruleInformer *RuleBindingK8sInformer) GetRulesForPod(podName, namespace string) ([]types.RuntimeAlertRuleBindingRule, error) {
	// TODO: change to support parameters of rule + custom priority
	ruleBindingsForPod, err := ruleInformer.getRuleBindingsForPod(podName, namespace)
	if err != nil {
		return nil, err
	}

	var rulesSlice []types.RuntimeAlertRuleBindingRule
	ruleMap := make(map[string]types.RuntimeAlertRuleBindingRule)
	for _, ruleBinding := range ruleBindingsForPod {
		for _, rule := range ruleBinding.Spec.Rules {
			// remove duplications based on RuleID
			// Fixes issue in GH: https://github.com/armosec/kubecop/issues/30
			ruleMap[rule.RuleID] = rule
		}
	}

	for _, rule := range ruleMap {
		rulesSlice = append(rulesSlice, rule)
	}

	return rulesSlice, nil
}

func (ruleInformer *RuleBindingK8sInformer) Destroy() {
	close(ruleInformer.informerStopChannel)
}

func (ruleInformer *RuleBindingK8sInformer) ruleBindingAddedHandler(obj interface{}) {
	bindObj, err := getRuntimeAlertRuleBindingFromObj(obj)
	if err != nil {
		fmt.Println("Error getting rule binding from obj: ", err)
		return
	}
	fmt.Println("Rule binding added: ", bindObj)
	for _, callBack := range ruleInformer.callBacks {
		callBack(*bindObj)
	}
}

func (ruleInformer *RuleBindingK8sInformer) ruleBindingUpdatedHandler(oldObj, newObj interface{}) {
	// naive implementation. just call the other handlers
	ruleInformer.ruleBindingDeletedHandler(oldObj)
	ruleInformer.ruleBindingAddedHandler(newObj)
}

func (ruleInformer *RuleBindingK8sInformer) ruleBindingDeletedHandler(obj interface{}) {
	bindObj, err := getRuntimeAlertRuleBindingFromObj(obj)
	if err != nil {
		fmt.Println("Error getting rule binding from obj: ", err)
		return
	}
	fmt.Println("Rule binding deleted: ", bindObj)
	for _, callBack := range ruleInformer.callBacks {
		callBack(*bindObj)
	}
}

func getRuntimeAlertRuleBindingFromObj(obj interface{}) (*types.RuntimeAlertRuleBinding, error) {
	typedObj := obj.(*unstructured.Unstructured)
	bytes, err := typedObj.MarshalJSON()
	if err != nil {
		return &types.RuntimeAlertRuleBinding{}, err
	}

	var runtimeAlertRuleBindingObj *types.RuntimeAlertRuleBinding
	err = json.Unmarshal(bytes, &runtimeAlertRuleBindingObj)
	if err != nil {
		return runtimeAlertRuleBindingObj, err
	}
	return runtimeAlertRuleBindingObj, nil
}

func (ruleInformer *RuleBindingK8sInformer) StartController() {

	// Initialize factory and informer
	informer := dynamicinformer.NewFilteredDynamicSharedInformerFactory(ruleInformer.dynamicClient, 0, ruleInformer.storeNamespace, nil).ForResource(RuleBindingAlertGvr).Informer()

	// Add event handlers to informer
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ruleInformer.ruleBindingAddedHandler,
		UpdateFunc: ruleInformer.ruleBindingUpdatedHandler,
		DeleteFunc: ruleInformer.ruleBindingDeletedHandler,
	})

	// Run the informer
	go informer.Run(ruleInformer.informerStopChannel)
}

func (ruleInformer *RuleBindingK8sInformer) SetRuleBindingChangedHandlers(handlers []RuleBindingChangedHandler) {
	ruleInformer.callBacks = handlers
}
