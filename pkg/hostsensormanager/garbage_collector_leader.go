package hostsensormanager

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coordination "k8s.io/client-go/kubernetes/typed/coordination/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const hostDataGCLease = "kubescape-hostdata-gc"

type garbageCollector struct {
	client    *CRDClient
	leases    coordination.LeasesGetter
	namespace string
	identity  string
	interval  time.Duration
}

func newGarbageCollector(config Config, client *CRDClient) (*garbageCollector, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	// Acquisition uses a long-lived election context; bound each Lease request
	// as well as GC requests. Renewal still honors its shorter deadline.
	restConfig.Timeout = gcRequestTimeout
	leases, err := coordination.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}
	return &garbageCollector{client: client, leases: leases, namespace: config.Namespace,
		identity: config.NodeName + "_" + uuid.NewString(), interval: config.Interval}, nil
}

func (g *garbageCollector) run(ctx context.Context) {
	for ctx.Err() == nil {
		g.runElection(ctx)
		// Back off between terms; ordinary acquisition retries are handled by client-go.
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (g *garbageCollector) runElection(ctx context.Context) {
	epochCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	leading := make(chan context.Context)
	done := make(chan struct{})
	// Own the worker before Run: client-go invokes OnStartedLeading asynchronously,
	// and Run can return before that callback starts. Joining this worker handles
	// both that race and leadership loss during an API request.
	go func() {
		defer close(done)
		select {
		case leaderCtx := <-leading:
			g.collectLoop(leaderCtx)
		case <-epochCtx.Done():
		}
	}()
	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock: &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{Name: hostDataGCLease, Namespace: g.namespace},
			Client:    g.leases, LockConfig: resourcelock.ResourceLockConfig{Identity: g.identity},
		},
		LeaseDuration: 15 * time.Second, RenewDeadline: 10 * time.Second, RetryPeriod: 2 * time.Second,
		ReleaseOnCancel: false, Name: hostDataGCLease,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leaderCtx context.Context) {
				select {
				case leading <- leaderCtx:
				case <-epochCtx.Done():
				}
			},
			OnStoppedLeading: func() {},
		},
	})
	if err != nil {
		logger.L().Warning("cannot start host-data cleanup election", helpers.Error(err))
	} else {
		elector.Run(epochCtx)
	}
	cancel()
	<-done
}

func (g *garbageCollector) collectLoop(ctx context.Context) {
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if err := g.client.collectHostData(ctx); err != nil && ctx.Err() == nil {
			logGCError("nodes", "", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
