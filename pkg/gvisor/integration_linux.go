//go:build linux

package gvisor

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// Collector owns process-local health counters across listener retries. One
// instance supports one Run call; Stats may be called concurrently.
type Collector struct {
	// StopLookup and EmitStop are required when StopObservations is enabled.
	// StopLookup must accept a container that has just exited and a Pod that
	// is being deleted; the start lookup rejects both.
	StopLookup InventoryLookup
	EmitStop   func(context.Context, StopObservation)

	receiver         Receiver
	recheckRejected  atomic.Uint64
	exportSubmitted  atomic.Uint64
	listenerFailures atomic.Uint64
	stopRejected     atomic.Uint64
	stopSubmitted    atomic.Uint64
	running          atomic.Bool
	retryDelay       time.Duration // test seam; production begins at one second
}

// Health distinguishes local admission, dispatch and export submission. Counts
// are not atomic as a group and never attest to remote OTLP delivery.
type Health struct {
	Receiver         Stats  `json:"receiver"`
	Running          bool   `json:"running"`
	RecheckRejected  uint64 `json:"recheck_rejected"`
	ExportSubmitted  uint64 `json:"export_submitted"`
	ListenerFailures uint64 `json:"listener_failures"`
	// StopExportSubmitted + StopRecheckRejected == Receiver.StopCallbacksCompleted.
	StopRecheckRejected uint64 `json:"stop_recheck_rejected"`
	StopExportSubmitted uint64 `json:"stop_export_submitted"`
}

func (c *Collector) Stats() Health {
	return Health{Receiver: c.receiver.Stats(), Running: c.running.Load(),
		RecheckRejected: c.recheckRejected.Load(), ExportSubmitted: c.exportSubmitted.Load(),
		ListenerFailures: c.listenerFailures.Load(), StopRecheckRejected: c.stopRejected.Load(),
		StopExportSubmitted: c.stopSubmitted.Load()}
}

// RunIntegration is a convenience entrypoint for callers that do not need health.
func RunIntegration(ctx context.Context, cfg IntegrationConfig, node string, lookup InventoryLookup, emit func(context.Context, Observation)) error {
	return new(Collector).Run(ctx, cfg, node, lookup, emit)
}

// Run joins identity before queueing and immediately before emission. Lookup
// must honor its two-second deadline. Emit must be nonblocking (OTEL batch).
// Listener failures retry at 1, 2, 4, 8, 16, then 30 seconds, without replacing
// existing paths or acquiring trace sessions. Clients must reconnect themselves.
func (c *Collector) Run(ctx context.Context, cfg IntegrationConfig, node string, lookup InventoryLookup, emit func(context.Context, Observation)) error {
	if !cfg.Enabled {
		return nil
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if node == "" || lookup == nil || emit == nil {
		return errors.New("gVisor integration requires node, inventory and event export")
	}
	if cfg.StopObservations && (c.StopLookup == nil || c.EmitStop == nil) {
		return errors.New("gVisor stop observations require a terminal inventory lookup and export")
	}
	resolveWith := func(lookup InventoryLookup, ctx context.Context, id string) (Identity, bool) {
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		identity, err := lookup(callCtx, id)
		return identity, err == nil && identity.ContainerID == id &&
			identity.SandboxID != "" && identity.Namespace != "" && identity.PodName != "" &&
			identity.PodUID != "" && identity.ContainerName != "" && identity.RuntimeHandler != ""
	}
	resolve := func(ctx context.Context, id string) (Identity, bool) { return resolveWith(lookup, ctx, id) }
	c.receiver.SocketPath = cfg.SocketPath
	c.receiver.Resolve = func(id string) bool { _, ok := resolve(ctx, id); return ok }
	c.receiver.OnStart = func(ctx context.Context, start Start) {
		identity, ok := resolve(ctx, start.ContainerID)
		if !ok || ctx.Err() != nil {
			c.recheckRejected.Add(1)
			return
		}
		emit(ctx, Observation{Start: start, Identity: identity, Node: node})
		c.exportSubmitted.Add(1)
	}
	if cfg.StopObservations {
		c.receiver.OnStop = func(ctx context.Context, stop Stop) {
			// The start was verified on this connection; re-check that the ID
			// is still this node's gVisor workload container before export.
			identity, ok := resolveWith(c.StopLookup, ctx, stop.ContainerID)
			if !ok || ctx.Err() != nil {
				c.stopRejected.Add(1)
				return
			}
			c.EmitStop(ctx, StopObservation{Stop: stop, Identity: identity, Node: node})
			c.stopSubmitted.Add(1)
		}
	}
	c.running.Store(true)
	defer c.running.Store(false)
	delay := c.retryDelay
	if delay <= 0 {
		delay = time.Second
	}
	for ctx.Err() == nil {
		err := c.receiver.Run(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			return nil
		}
		c.listenerFailures.Add(1)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		delay = min(2*delay, 30*time.Second)
	}
	return nil
}
