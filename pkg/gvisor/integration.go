package gvisor

import (
	"context"
	"errors"
	"path/filepath"
)

// IntegrationConfig enables a separate experimental observation source. Empty
// configuration performs no I/O. RuntimeEndpoint defaults to the node's CRI
// socket at the call site; RuntimeHandler defaults to runsc.
type IntegrationConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	SocketPath      string `mapstructure:"socketPath"`
	RuntimeEndpoint string `mapstructure:"runtimeEndpoint"`
	RuntimeHandler  string `mapstructure:"runtimeHandler"`
}

func (c IntegrationConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if !filepath.IsAbs(c.SocketPath) {
		return errors.New("gVisor start collection requires an absolute socketPath")
	}
	if c.RuntimeEndpoint != "" && !filepath.IsAbs(c.RuntimeEndpoint) {
		return errors.New("gVisor runtimeEndpoint must be an absolute local CRI socket path")
	}
	return nil
}

// Identity contains only allowlisted local-runtime inventory fields. It does
// not authenticate the trace sender or identify an actor/session.
type Identity struct {
	ContainerID    string
	SandboxID      string
	RuntimeHandler string
	Namespace      string
	PodName        string
	PodUID         string
	ContainerName  string
}

// Observation is distinct from an exec event, profile entry or security alert.
// Container/start precedes application execution. ObservedAt is receiver time.
type Observation struct {
	Start
	Identity Identity
	Node     string
}

type InventoryLookup func(context.Context, string) (Identity, error)
