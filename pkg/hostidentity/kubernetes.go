package hostidentity

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	corev1 "k8s.io/api/core/v1"
)

// KubernetesHostCoordinator resolves identity once, retrying until cancellation.
// Its published value contains no raw machine-id and cannot be mutated by callers.
type KubernetesHostCoordinator struct {
	ready    chan struct{}
	mu       sync.RWMutex
	identity armotypes.KubernetesHostIdentity
	resolved bool
}

func NewKubernetesHostCoordinator(ctx context.Context, getClusterUID func(context.Context) (string, error), clusterName, nodeName string, getNode func(context.Context) (*corev1.Node, error)) *KubernetesHostCoordinator {
	c := &KubernetesHostCoordinator{ready: make(chan struct{})}
	go c.resolve(ctx, getClusterUID, clusterName, nodeName, getNode, os.ReadFile, time.Second)
	return c
}

func (c *KubernetesHostCoordinator) Ready() <-chan struct{} { return c.ready }

func (c *KubernetesHostCoordinator) Identity() (armotypes.KubernetesHostIdentity, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.identity, c.resolved
}

func (c *KubernetesHostCoordinator) resolve(ctx context.Context, getClusterUID func(context.Context) (string, error), clusterName, nodeName string, getNode func(context.Context) (*corev1.Node, error), readFile func(string) ([]byte, error), initialDelay time.Duration) {
	delay := initialDelay
	lastReason := ""
	for ctx.Err() == nil {
		reason := "cluster-uid-unavailable"
		clusterUID, err := getClusterUID(ctx)
		if err == nil && clusterUID == "" {
			err = fmt.Errorf("kubernetes cluster UID is unavailable")
		}
		var node *corev1.Node
		if err == nil {
			reason = "node-unavailable"
			node, err = getNode(ctx)
		}
		if err == nil {
			var identity armotypes.KubernetesHostIdentity
			identity, err = resolveKubernetesHostIdentity(clusterUID, clusterName, nodeName, node, readFile)
			if err != nil {
				reason = err.Error()
			} // Resolver errors contain only fixed diagnostics.
			if err == nil && ctx.Err() == nil {
				c.mu.Lock()
				c.identity, c.resolved = identity, true
				c.mu.Unlock()
				logger.L().Info("Kubernetes host identity resolved", helpers.String("key", identity.Key))
				close(c.ready)
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
		if reason != lastReason {
			logger.L().Warning("Kubernetes host identity pending", helpers.String("reason", reason))
			lastReason = reason
		}
		timer := time.NewTimer(min(time.Duration(float64(delay)*(0.8+rand.Float64()*0.4)), 30*time.Second))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(delay*2, 30*time.Second)
	}
}

func resolveKubernetesHostIdentity(clusterUID, clusterName, nodeName string, node *corev1.Node, readFile func(string) ([]byte, error)) (armotypes.KubernetesHostIdentity, error) {
	var identity armotypes.KubernetesHostIdentity
	if node == nil || node.Name != nodeName {
		return identity, fmt.Errorf("kubernetes host Node is missing or inconsistent")
	}
	machineID, err := armotypes.NormalizeKubernetesHostMachineID(node.Status.NodeInfo.MachineID)
	if err != nil {
		return identity, fmt.Errorf("kubernetes host Node machine identity is unavailable")
	}
	hostRoot := filepath.Clean(machineIDHostRoot())
	if !filepath.IsAbs(hostRoot) || hostRoot == "/" {
		return identity, fmt.Errorf("kubernetes host machine identity requires a host-mounted root")
	}
	mounted, err := readFile(filepath.Join(hostRoot, "etc/machine-id"))
	if err == nil {
		normalized, normalizeErr := armotypes.NormalizeKubernetesHostMachineID(string(mounted))
		if normalizeErr != nil || normalized != machineID {
			return identity, fmt.Errorf("kubernetes host mounted machine identity does not match Node")
		}
	} else if !os.IsNotExist(err) {
		return identity, fmt.Errorf("kubernetes host mounted machine identity is unreadable")
	}
	fingerprint, err := armotypes.KubernetesHostMachineFingerprint(machineID)
	if err != nil {
		return identity, err
	}
	key, err := armotypes.KubernetesHostKey(clusterUID, string(node.UID), fingerprint)
	if err != nil {
		return identity, err
	}
	identity = armotypes.KubernetesHostIdentity{Version: armotypes.KubernetesHostIdentityVersion, ClusterUID: clusterUID, ClusterName: clusterName, NodeUID: string(node.UID), NodeName: node.Name, MachineFingerprint: fingerprint, Key: key, ProviderID: node.Spec.ProviderID}
	return identity, identity.Validate()
}
