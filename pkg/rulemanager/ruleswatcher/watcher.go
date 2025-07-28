package ruleswatcher

import (
	"context"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/watcher"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
)

var _ RulesWatcher = (*RulesWatcherImpl)(nil)

type RulesWatcherImpl struct {
	ruleCreator    rulecreator.RuleCreator
	k8sClient      k8sclient.K8sClientInterface
	callback       RulesWatcherCallback
	watchResources []watcher.WatchResource
}

func NewRulesWatcher(k8sClient k8sclient.K8sClientInterface, ruleCreator rulecreator.RuleCreator, callback RulesWatcherCallback) *RulesWatcherImpl {
	return &RulesWatcherImpl{
		ruleCreator: ruleCreator,
		k8sClient:   k8sClient,
		callback:    callback,
		watchResources: []watcher.WatchResource{
			watcher.NewWatchResource(typesv1.RuleGvr, metav1.ListOptions{}),
		},
	}
}

func (w *RulesWatcherImpl) WatchResources() []watcher.WatchResource {
	return w.watchResources
}

func (w *RulesWatcherImpl) AddHandler(ctx context.Context, obj runtime.Object) {
	logger.L().Debug("RulesWatcher - rule added, syncing all rules")
	w.syncAllRulesAndNotify(ctx)
}

func (w *RulesWatcherImpl) ModifyHandler(ctx context.Context, obj runtime.Object) {
	logger.L().Debug("RulesWatcher - rule modified, syncing all rules")
	w.syncAllRulesAndNotify(ctx)
}

func (w *RulesWatcherImpl) DeleteHandler(ctx context.Context, obj runtime.Object) {
	logger.L().Debug("RulesWatcher - rule deleted, syncing all rules")
	w.syncAllRulesAndNotify(ctx)
}

func (w *RulesWatcherImpl) syncAllRulesAndNotify(ctx context.Context) {
	if err := w.syncAllRulesFromCluster(ctx); err != nil {
		logger.L().Warning("RulesWatcher - failed to sync all rules from cluster", helpers.Error(err))
		return
	}

	if w.callback != nil {
		w.callback()
		logger.L().Debug("RulesWatcher - notified callback with updated rules")
	}
}

func (w *RulesWatcherImpl) syncAllRulesFromCluster(ctx context.Context) error {
	logger.L().Debug("RulesWatcher - syncing all rules from cluster")

	unstructuredList, err := w.k8sClient.GetDynamicClient().Resource(typesv1.RuleGvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	var enabledRules []typesv1.Rule
	for _, item := range unstructuredList.Items {
		rule, err := unstructuredToRule(&item)
		if err != nil {
			logger.L().Warning("RulesWatcher - failed to convert rule during sync", helpers.Error(err))
			continue
		}

		if rule.Spec.Enabled {
			enabledRules = append(enabledRules, *rule)
		}
	}

	w.ruleCreator.SyncRules(enabledRules)

	logger.L().Info("RulesWatcher - synced rules from cluster", helpers.Int("enabledRules", len(enabledRules)), helpers.Int("totalRules", len(unstructuredList.Items)))
	return nil
}

func (w *RulesWatcherImpl) InitialSync(ctx context.Context) error {
	logger.L().Info("RulesWatcher - performing initial sync")
	return w.syncAllRulesFromCluster(ctx)
}

func unstructuredToRule(obj *unstructured.Unstructured) (*typesv1.Rule, error) {
	rule := &typesv1.Rule{}
	if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, rule); err != nil {
		return nil, err
	}
	return rule, nil
}
