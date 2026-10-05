package k8scache

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/watcher"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/goradd/maps"
	corev1 "k8s.io/api/core/v1"
)

var _ objectcache.K8sObjectCache = (*K8sObjectCacheImpl)(nil)
var _ watcher.Adaptor = (*K8sObjectCacheImpl)(nil)

type K8sObjectCacheImpl struct {
	nodeName                string
	k8sClient               k8sclient.K8sClientInterface
	pods                    maps.SafeMap[string, *corev1.Pod]
	podMu                   sync.RWMutex
	podsByIP                map[string]*corev1.Pod
	apiServerIpAddress      string
	containerIDToSharedData maps.SafeMap[string, *objectcache.WatchedContainerData]
}

func NewK8sObjectCache(nodeName string, k8sClient k8sclient.K8sClientInterface) (*K8sObjectCacheImpl, error) {
	k := &K8sObjectCacheImpl{
		k8sClient:               k8sClient,
		nodeName:                nodeName,
		pods:                    maps.SafeMap[string, *corev1.Pod]{},
		containerIDToSharedData: maps.SafeMap[string, *objectcache.WatchedContainerData]{},
	}

	if err := k.setApiServerIpAddress(); err != nil {
		return k, err
	}

	return k, nil
}

// GetPodSpec returns the pod spec for the given namespace and pod name, if not found returns nil
func (k *K8sObjectCacheImpl) GetPodSpec(namespace, podName string) *corev1.PodSpec {
	p := podKey(namespace, podName)
	if pod, ok := k.pods.Load(p); ok {
		return &pod.Spec
	}

	return nil
}

// GetPodStatus returns the pod status for the given namespace and pod name, if not found returns nil
func (k *K8sObjectCacheImpl) GetPodStatus(namespace, podName string) *corev1.PodStatus {
	p := podKey(namespace, podName)
	if pod, ok := k.pods.Load(p); ok {
		return &pod.Status
	}

	return nil
}

// GetPod returns the pod for the given namespace and pod name, if not found returns nil
func (k *K8sObjectCacheImpl) GetPod(namespace, podName string) *corev1.Pod {
	p := podKey(namespace, podName)
	if pod, ok := k.pods.Load(p); ok {
		return pod
	}

	return nil
}

// GetPodByIP returns a cached pod by its primary or secondary IP in constant time.
func (k *K8sObjectCacheImpl) GetPodByIP(ip string) *corev1.Pod {
	k.podMu.RLock()
	defer k.podMu.RUnlock()
	return k.podsByIP[ip]
}

func (k *K8sObjectCacheImpl) GetApiServerIpAddress() string {
	return k.apiServerIpAddress
}

func (k *K8sObjectCacheImpl) GetPods() []*corev1.Pod {
	return k.pods.Values()
}

func (k *K8sObjectCacheImpl) SetSharedContainerData(containerID string, data *objectcache.WatchedContainerData) {
	k.containerIDToSharedData.Set(containerID, data)
}

func (k *K8sObjectCacheImpl) GetSharedContainerData(containerID string) *objectcache.WatchedContainerData {
	if data, ok := k.containerIDToSharedData.Load(containerID); ok {
		return data
	}

	return nil
}

func (k *K8sObjectCacheImpl) DeleteSharedContainerData(containerID string) {
	k.containerIDToSharedData.Delete(containerID)
}

func (k *K8sObjectCacheImpl) AddHandler(_ context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		k.storePod(pod)
	}
}

func (k *K8sObjectCacheImpl) ModifyHandler(_ context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		k.storePod(pod)
	}
}

func (k *K8sObjectCacheImpl) DeleteHandler(_ context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		k.podMu.Lock()
		defer k.podMu.Unlock()
		key := podKey(pod.GetNamespace(), pod.GetName())
		current, ok := k.pods.Load(key)
		if !ok || current.UID != pod.UID {
			return
		}
		k.removePodIPs(current)
		k.pods.Delete(key)
	}
}

func (k *K8sObjectCacheImpl) storePod(pod *corev1.Pod) {
	k.podMu.Lock()
	defer k.podMu.Unlock()
	key := podKey(pod.GetNamespace(), pod.GetName())
	previous, ok := k.pods.Load(key)
	if ok {
		k.removePodIPs(previous)
	}
	k.pods.Set(key, pod)
	if k.podsByIP == nil {
		k.podsByIP = make(map[string]*corev1.Pod)
	}
	indexIP := func(ip string) {
		if ip == "" {
			return
		}
		// A status update retaining an old IP must not reclaim it after reuse.
		// New pods and newly assigned IPs can replace the previous owner.
		if k.podsByIP[ip] != nil && previous != nil && previous.UID == pod.UID {
			if previous.Status.PodIP == ip {
				return
			}
			for _, oldIP := range previous.Status.PodIPs {
				if oldIP.IP == ip {
					return
				}
			}
		}
		k.podsByIP[ip] = pod
	}
	indexIP(pod.Status.PodIP)
	for _, ip := range pod.Status.PodIPs {
		indexIP(ip.IP)
	}
}

// removePodIPs requires podMu and preserves IPs already assigned to another pod.
func (k *K8sObjectCacheImpl) removePodIPs(pod *corev1.Pod) {
	if k.podsByIP[pod.Status.PodIP] == pod {
		delete(k.podsByIP, pod.Status.PodIP)
	}
	for _, ip := range pod.Status.PodIPs {
		if k.podsByIP[ip.IP] == pod {
			delete(k.podsByIP, ip.IP)
		}
	}
}

func (k *K8sObjectCacheImpl) WatchResources() []watcher.WatchResource {
	// add pod
	p := watcher.NewWatchResource(schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	},
		metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + k.nodeName,
		},
	)

	return []watcher.WatchResource{p}
}

func (k *K8sObjectCacheImpl) setApiServerIpAddress() error {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		return fmt.Errorf("KUBERNETES_SERVICE_HOST environment variable not set")
	}
	k.apiServerIpAddress = host
	return nil
}

func podKey(namespace, podName string) string {
	return namespace + "/" + podName
}
