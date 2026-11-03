//go:build linux

package gvisor

import (
	"context"
	"errors"
	"time"
)

// RunIntegration joins identity both before queuing and immediately before
// emission. A short-lived container that disappears between those joins is
// deliberately not attributed using a stale cache. Lookup must honor ctx.
// Emit must not block on network or file I/O; the OTEL batch processor is the
// intended consumer. Callers own the runtime client's lifetime.
func RunIntegration(ctx context.Context, cfg IntegrationConfig, node string, lookup InventoryLookup, emit func(context.Context, Observation)) error {
	if !cfg.Enabled {
		return nil
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if node == "" || lookup == nil || emit == nil {
		return errors.New("gVisor integration requires node, inventory and event export")
	}
	resolve := func(ctx context.Context, id string) (Identity, bool) {
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		identity, err := lookup(callCtx, id)
		return identity, err == nil && identity.ContainerID == id &&
			identity.SandboxID != "" && identity.Namespace != "" && identity.PodName != "" &&
			identity.PodUID != "" && identity.ContainerName != "" && identity.RuntimeHandler != ""
	}
	receiver := Receiver{
		SocketPath: cfg.SocketPath,
		Resolve: func(id string) bool {
			_, ok := resolve(ctx, id)
			return ok
		},
		OnStart: func(ctx context.Context, start Start) {
			if identity, ok := resolve(ctx, start.ContainerID); ok && ctx.Err() == nil {
				emit(ctx, Observation{Start: start, Identity: identity, Node: node})
			}
		},
	}
	return receiver.Run(ctx)
}
