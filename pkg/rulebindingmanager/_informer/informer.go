package rbinformer

import (
	"encoding/json"
	"node-agent/pkg/k8sclient"
	bindingcache "node-agent/pkg/rulebindingmanager/cache"
	"node-agent/pkg/rulebindingmanager/types/v1"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamicinformer"
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

type RuleBindingChangedHandler func(ruleBinding types.RuntimeAlertRuleBinding)

type RuleBindingK8sInformer struct {
	k8sClient           k8sclient.K8sClientInterface
	informerStopChannel chan struct{}
	storeNamespace      string
	bindingCache        *bindingcache.RBCache
}

func NewRuleBindingK8sInformer(k8sClient k8sclient.K8sClientInterface, bindingCache *bindingcache.RBCache, storeNamespace string) (*RuleBindingK8sInformer, error) {

	stopCh := make(chan struct{})
	if storeNamespace == "" {
		storeNamespace = metav1.NamespaceNone
	}

	ruleInformer := RuleBindingK8sInformer{
		k8sClient:           k8sClient,
		informerStopChannel: stopCh,
		storeNamespace:      storeNamespace,
		bindingCache:        bindingCache,
	}

	return &ruleInformer, nil
}

func (ruleInformer *RuleBindingK8sInformer) StartInformer() {

	// Initialize factory and informer
	informer := dynamicinformer.NewFilteredDynamicSharedInformerFactory(ruleInformer.k8sClient.GetDynamicClient(), 0, ruleInformer.storeNamespace, nil).ForResource(RuleBindingAlertGvr).Informer()

	// Add event handlers to informer
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ruleInformer.ruleBindingAddedHandler,
		UpdateFunc: ruleInformer.ruleBindingUpdatedHandler,
		DeleteFunc: ruleInformer.ruleBindingDeletedHandler,
	})

	// Run the informer
	go informer.Run(ruleInformer.informerStopChannel)
}

func (ruleInformer *RuleBindingK8sInformer) Destroy() {
	close(ruleInformer.informerStopChannel)
}

func (ruleInformer *RuleBindingK8sInformer) ruleBindingAddedHandler(obj interface{}) {
	bindObj, err := getRuntimeAlertRuleBindingFromObj(obj)
	if err != nil {
		logger.L().Error("add: to parse rule binding", helpers.Error(err))
		return
	}
	ruleInformer.bindingCache.AddRuleBinding(bindObj)
}

func (ruleInformer *RuleBindingK8sInformer) ruleBindingUpdatedHandler(oldObj, newObj interface{}) {
	// naive implementation. just call the other handlers
	ruleInformer.ruleBindingDeletedHandler(oldObj)
	ruleInformer.ruleBindingAddedHandler(newObj)
}

func (ruleInformer *RuleBindingK8sInformer) ruleBindingDeletedHandler(obj interface{}) {
	bindObj, err := getRuntimeAlertRuleBindingFromObj(obj)
	if err != nil {
		logger.L().Error("delete: failed to parse rule binding", helpers.Error(err))
		return
	}
	ruleInformer.bindingCache.DeleteRuleBinding(bindObj)
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
