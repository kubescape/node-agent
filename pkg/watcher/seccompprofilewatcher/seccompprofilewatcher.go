package seccompprofilewatcher

import (
	"context"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/watcher"
	v1beta1api "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
	backend              string
}

var _ watcher.Adaptor = (*SeccompProfileWatcherImpl)(nil)

// NewSeccompProfileWatcher creates a new SeccompProfileWatcher with storage backend (default)
func NewSeccompProfileWatcher(storageClient v1beta1.SpdxV1beta1Interface, seccompManager seccompmanager.SeccompManagerClient) *SeccompProfileWatcherImpl {
	return NewSeccompProfileWatcherWithBackend(storageClient, seccompManager, config.SeccompBackendStorage)
}

// NewSeccompProfileWatcherWithBackend creates a new SeccompProfileWatcher with specified backend
func NewSeccompProfileWatcherWithBackend(storageClient v1beta1.SpdxV1beta1Interface, seccompManager seccompmanager.SeccompManagerClient, backend string) *SeccompProfileWatcherImpl {
	var gvr schema.GroupVersionResource
	if backend == config.SeccompBackendCRD {
		gvr = schema.GroupVersionResource{
			Group:    "kubescape.io",
			Version:  "v1beta1",
			Resource: "seccompprofiles",
		}
	} else {
		gvr = schema.GroupVersionResource{
			Group:    "spdx.softwarecomposition.kubescape.io",
			Version:  "v1beta1",
			Resource: "seccompprofiles",
		}
	}
	return &SeccompProfileWatcherImpl{
		storageClient:        storageClient,
		seccompManager:       seccompManager,
		groupVersionResource: gvr,
		backend:              backend,
	}
}

// ------------------ watcher.WatchResources methods -----------------------

func (sp *SeccompProfileWatcherImpl) WatchResources() []watcher.WatchResource {
	// add seccomp profile
	apl := watcher.NewWatchResource(sp.groupVersionResource, metav1.ListOptions{})
	return []watcher.WatchResource{apl}
}

// ------------------ watcher.Watcher methods -----------------------

// convertToSeccompProfile converts an object to SeccompProfile, handling both typed and unstructured objects
func (sp *SeccompProfileWatcherImpl) convertToSeccompProfile(obj runtime.Object) (*v1beta1api.SeccompProfile, bool) {
	// Try direct type assertion first (storage mode)
	if fullObj, ok := obj.(*v1beta1api.SeccompProfile); ok {
		return fullObj, true
	}

	// Handle unstructured objects (CRD mode)
	if u, ok := obj.(*unstructured.Unstructured); ok {
		seccompProfile := &v1beta1api.SeccompProfile{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, seccompProfile); err != nil {
			logger.L().Warning("SeccompProfileWatcher - failed to convert unstructured to SeccompProfile",
				helpers.Error(err),
				helpers.String("name", u.GetName()),
				helpers.String("namespace", u.GetNamespace()),
				helpers.String("backend", sp.backend))
			return nil, false
		}
		return seccompProfile, true
	}

	return nil, false
}

func (sp *SeccompProfileWatcherImpl) AddHandler(ctx context.Context, obj runtime.Object) {
	if fullObj, ok := sp.convertToSeccompProfile(obj); ok {
		if err := sp.seccompManager.AddSeccompProfile(fullObj); err != nil {
			logger.L().Ctx(ctx).Warning("SeccompProfileWatcherImpl - failed to add seccomp profile",
				helpers.Error(err),
				helpers.String("name", fullObj.GetName()),
				helpers.String("namespace", fullObj.GetNamespace()),
				helpers.String("backend", sp.backend))
		}
	}
}

func (sp *SeccompProfileWatcherImpl) ModifyHandler(ctx context.Context, obj runtime.Object) {
	if fullObj, ok := sp.convertToSeccompProfile(obj); ok {
		if err := sp.seccompManager.AddSeccompProfile(fullObj); err != nil {
			logger.L().Ctx(ctx).Warning("SeccompProfileWatcherImpl - failed to modify seccomp profile",
				helpers.Error(err),
				helpers.String("name", fullObj.GetName()),
				helpers.String("namespace", fullObj.GetNamespace()),
				helpers.String("backend", sp.backend))
		}
	}
}

func (sp *SeccompProfileWatcherImpl) DeleteHandler(ctx context.Context, obj runtime.Object) {
	if fullObj, ok := sp.convertToSeccompProfile(obj); ok {
		if err := sp.seccompManager.DeleteSeccompProfile(fullObj); err != nil {
			logger.L().Ctx(ctx).Warning("SeccompProfileWatcherImpl - failed to delete seccomp profile",
				helpers.Error(err),
				helpers.String("name", fullObj.GetName()),
				helpers.String("namespace", fullObj.GetNamespace()),
				helpers.String("backend", sp.backend))
		}
	}
}
