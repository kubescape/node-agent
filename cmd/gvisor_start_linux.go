//go:build linux

package main

import (
	"context"
	"errors"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/gvisor"
	gvcri "github.com/kubescape/node-agent/pkg/gvisor/cri"
	"github.com/kubescape/node-agent/pkg/otelsetup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
)

// startGVisorCollection is independent of the host PID/mount-namespace inventory.
// In particular it does not inject a sandbox start into an exec/profile path.
func startGVisorCollection(ctx context.Context, cfg config.Config, runtimeEndpoint string, core coreclient.CoreV1Interface, logsReady bool) (func(), error) {
	if !cfg.GVisorStart.Enabled {
		return func() {}, nil
	}
	if err := cfg.GVisorStart.Validate(); err != nil {
		return nil, err
	}
	if !logsReady {
		return nil, errors.New("gVisor observations require an initialized OTLP log exporter")
	}
	if cfg.GVisorStart.RuntimeEndpoint != "" {
		runtimeEndpoint = cfg.GVisorStart.RuntimeEndpoint
	}
	inventory, err := gvcri.New(runtimeEndpoint, cfg.GVisorStart.RuntimeHandler)
	if err != nil {
		return nil, err
	}
	checkCtx, cancelCheck := context.WithTimeout(ctx, 2*time.Second)
	err = inventory.Check(checkCtx)
	cancelCheck()
	if err != nil {
		inventory.Close()
		return nil, err
	}
	sourceCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	lookup := func(ctx context.Context, id string) (gvisor.Identity, error) {
		identity, err := inventory.Resolve(ctx, id)
		if err != nil {
			return gvisor.Identity{}, err
		}
		pod, err := core.Pods(identity.Namespace).Get(ctx, identity.PodName, metav1.GetOptions{})
		if err != nil || !gVisorPodMatches(identity, pod, cfg) {
			return gvisor.Identity{}, errors.New("gVisor Pod identity is unresolved or excluded")
		}
		return identity, nil
	}
	go func() {
		defer close(done)
		if err := gvisor.RunIntegration(sourceCtx, cfg.GVisorStart, cfg.NodeName, lookup, otelsetup.EmitRuntimeStart); err != nil {
			// Never log CRI bodies or Sentry bytes. A source failure is degraded
			// telemetry, not evidence that no sandbox started.
			logger.L().Warning("gVisor start source stopped; runtime visibility is degraded")
		}
	}()
	return func() {
		cancel()
		<-done
		_ = inventory.Close()
	}, nil
}

func gVisorPodMatches(identity gvisor.Identity, pod *corev1.Pod, cfg config.Config) bool {
	if pod == nil || pod.Namespace != identity.Namespace || pod.Name != identity.PodName ||
		string(pod.UID) != identity.PodUID || pod.Spec.NodeName != cfg.NodeName || pod.DeletionTimestamp != nil ||
		cfg.IgnoreContainer(pod.Namespace, pod.Name, pod.Labels) {
		return false
	}
	for _, c := range pod.Spec.Containers {
		if c.Name == identity.ContainerName {
			return true
		}
	}
	for _, c := range pod.Spec.InitContainers {
		if c.Name == identity.ContainerName {
			return true
		}
	}
	for _, c := range pod.Spec.EphemeralContainers {
		if c.Name == identity.ContainerName {
			return true
		}
	}
	return false
}
