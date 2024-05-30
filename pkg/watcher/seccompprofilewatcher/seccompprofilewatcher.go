package seccompprofilewatcher

import (
	"context"
	"fmt"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/seccompmanager"
	"node-agent/pkg/watcher"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type SeccompProfileWatcherImpl struct {
	k8sClient            k8sclient.K8sClientInterface
	seccompManager       seccompmanager.SeccompManagerClient
	groupVersionResource schema.GroupVersionResource
}

var _ watcher.Adaptor = (*SeccompProfileWatcherImpl)(nil)

func NewSeccompProfileWatcher(k8sClient k8sclient.K8sClientInterface, seccompManager seccompmanager.SeccompManagerClient) *SeccompProfileWatcherImpl {
	return &SeccompProfileWatcherImpl{
		k8sClient:      k8sClient,
		seccompManager: seccompManager,
		groupVersionResource: schema.GroupVersionResource{
			Group:    "spdx.softwarecomposition.kubescape.io",
			Version:  "v1beta1",
			Resource: "seccompprofiles",
		},
	}

}

// ------------------ watcher.WatchResources methods -----------------------

func (sp *SeccompProfileWatcherImpl) WatchResources() []watcher.WatchResource {
	// add seccomp profile
	apl := watcher.NewWatchResource(sp.groupVersionResource, metav1.ListOptions{})
	return []watcher.WatchResource{apl}
}

// ------------------ watcher.Watcher methods -----------------------

func (sp *SeccompProfileWatcherImpl) AddHandler(ctx context.Context, obj *unstructured.Unstructured) {
	if obj.GetKind() == "SeccompProfile" {
		fullObj, err := sp.getFullSeccompProfile(obj)
		if err != nil {
			logger.L().Ctx(ctx).Error("SeccompProfileWatcherImpl - failed to get full seccomp profile", helpers.Error(err))
			return
		}
		if err := sp.seccompManager.AddSeccompProfile(fullObj); err != nil {
			logger.L().Ctx(ctx).Error("SeccompProfileWatcherImpl - failed to add seccomp profile", helpers.Error(err))
		}
	}
}

func (sp *SeccompProfileWatcherImpl) ModifyHandler(ctx context.Context, obj *unstructured.Unstructured) {
	if obj.GetKind() == "SeccompProfile" {
		fullObj, err := sp.getFullSeccompProfile(obj)
		if err != nil {
			logger.L().Ctx(ctx).Error("SeccompProfileWatcherImpl - failed to get full seccomp profile", helpers.Error(err))
			return
		}
		if err := sp.seccompManager.AddSeccompProfile(fullObj); err != nil {
			logger.L().Ctx(ctx).Error("SeccompProfileWatcherImpl - failed to modify seccomp profile", helpers.Error(err))
		}
	}
}

func (sp *SeccompProfileWatcherImpl) DeleteHandler(ctx context.Context, obj *unstructured.Unstructured) {
	if obj.GetKind() == "SeccompProfile" {
		if err := sp.seccompManager.DeleteSeccompProfile(obj); err != nil {
			logger.L().Ctx(ctx).Error("SeccompProfileWatcherImpl - failed to delete seccomp profile", helpers.Error(err))
		}
	}
}

func (sp *SeccompProfileWatcherImpl) getFullSeccompProfile(obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	fullObj, err := sp.k8sClient.GetDynamicClient().Resource(sp.groupVersionResource).Namespace(obj.GetNamespace()).Get(context.Background(), obj.GetName(), metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get full seccomp profile: %w", err)
	}
	return fullObj, nil
}
