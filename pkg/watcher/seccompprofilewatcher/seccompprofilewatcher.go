package seccompprofilewatcher

import (
	"context"
	"fmt"

	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/watcher"
	v1beta1api "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type SeccompProfileWatcherImpl struct {
	storageClient        v1beta1.SpdxV1beta1Interface
	seccompManager       seccompmanager.SeccompManagerClient
	groupVersionResource schema.GroupVersionResource
}

var _ watcher.Adaptor = (*SeccompProfileWatcherImpl)(nil)

func NewSeccompProfileWatcher(storageClient v1beta1.SpdxV1beta1Interface, seccompManager seccompmanager.SeccompManagerClient) *SeccompProfileWatcherImpl {
	return &SeccompProfileWatcherImpl{
		storageClient:  storageClient,
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

func (sp *SeccompProfileWatcherImpl) AddHandler(ctx context.Context, obj runtime.Object) {
	if _, ok := obj.(*v1beta1api.SeccompProfile); ok {
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

func (sp *SeccompProfileWatcherImpl) ModifyHandler(ctx context.Context, obj runtime.Object) {
	if _, ok := obj.(*v1beta1api.SeccompProfile); ok {
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

func (sp *SeccompProfileWatcherImpl) DeleteHandler(ctx context.Context, obj runtime.Object) {
	if _, ok := obj.(*v1beta1api.SeccompProfile); ok {
		if err := sp.seccompManager.DeleteSeccompProfile(obj.(*v1beta1api.SeccompProfile)); err != nil {
			logger.L().Ctx(ctx).Error("SeccompProfileWatcherImpl - failed to delete seccomp profile", helpers.Error(err))
		}
	}
}

func (sp *SeccompProfileWatcherImpl) getFullSeccompProfile(obj runtime.Object) (*v1beta1api.SeccompProfile, error) {
	meta := obj.(metav1.Object)
	fullObj, err := sp.storageClient.SeccompProfiles(meta.GetNamespace()).Get(context.Background(), meta.GetName(), metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get full seccomp profile: %w", err)
	}
	return fullObj, nil
}
