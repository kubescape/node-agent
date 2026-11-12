// Package cri resolves trace claims through a private, deadline-bound local
// CRI connection, independently of node-agent's host namespace enrichment.
package cri

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"

	"github.com/kubescape/node-agent/pkg/gvisor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

var containerID = regexp.MustCompile(`^[a-f0-9]{64}$`)

var errUnresolved = errors.New("gVisor identity not verified by local CRI inventory")

type Inventory struct {
	client  runtimeapi.RuntimeServiceClient
	conn    *grpc.ClientConn
	handler string
}

// New connects only to a local Unix socket. No TCP endpoint or runsc control
// root is accessed. The operator must configure handler to select runsc.
func New(endpoint, handler string) (*Inventory, error) {
	if !filepath.IsAbs(endpoint) {
		return nil, errors.New("gVisor inventory requires an absolute CRI socket path")
	}
	if handler == "" {
		handler = "runsc"
	}
	conn, err := grpc.NewClient("unix://"+endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1<<20)))
	if err != nil {
		return nil, errors.New("cannot initialize gVisor CRI inventory")
	}
	return &Inventory{client: runtimeapi.NewRuntimeServiceClient(conn), conn: conn, handler: handler}, nil
}

func (i *Inventory) Close() error { return i.conn.Close() }

func (i *Inventory) Check(ctx context.Context) error {
	status, err := i.client.Status(ctx, &runtimeapi.StatusRequest{})
	if err == nil && status != nil {
		for _, condition := range status.GetStatus().GetConditions() {
			if condition.GetType() == "RuntimeReady" && condition.GetStatus() {
				return nil
			}
		}
	}
	return errors.New("gVisor local CRI inventory is unavailable")
}

// Resolve verifies a start claim: the container must be CREATED or RUNNING in
// a READY sandbox.
func (i *Inventory) Resolve(ctx context.Context, id string) (gvisor.Identity, error) {
	return i.resolve(ctx, id, false)
}

// ResolveTerminal verifies a stop. The Sentry reports a termination a few
// milliseconds before CRI does, so the container may be RUNNING or already
// EXITED, and its sandbox may be NOTREADY when the whole Pod is stopping.
// Every other check is the same as for a start.
func (i *Inventory) ResolveTerminal(ctx context.Context, id string) (gvisor.Identity, error) {
	return i.resolve(ctx, id, true)
}

func (i *Inventory) resolve(ctx context.Context, id string, terminal bool) (gvisor.Identity, error) {
	if !containerID.MatchString(id) {
		return gvisor.Identity{}, errUnresolved
	}
	// CRI may interpret an ID filter as a prefix. Never accept that behavior
	// as verification: require exactly one complete matching inventory ID.
	listed, err := i.client.ListContainers(ctx, &runtimeapi.ListContainersRequest{Filter: &runtimeapi.ContainerFilter{Id: id}})
	if err != nil || listed == nil || len(listed.Containers) != 1 {
		return gvisor.Identity{}, errUnresolved
	}
	c := listed.Containers[0]
	live := c != nil && (c.State == runtimeapi.ContainerState_CONTAINER_CREATED || c.State == runtimeapi.ContainerState_CONTAINER_RUNNING)
	exited := c != nil && terminal && c.State == runtimeapi.ContainerState_CONTAINER_EXITED
	if c == nil || c.Id != id || !containerID.MatchString(c.PodSandboxId) || c.Metadata.GetName() == "" || !(live || exited) {
		return gvisor.Identity{}, errUnresolved
	}
	response, err := i.client.PodSandboxStatus(ctx, &runtimeapi.PodSandboxStatusRequest{PodSandboxId: c.PodSandboxId})
	if err != nil || response == nil {
		return gvisor.Identity{}, errUnresolved
	}
	s := response.Status
	sandboxOK := s != nil && (s.State == runtimeapi.PodSandboxState_SANDBOX_READY ||
		(terminal && s.State == runtimeapi.PodSandboxState_SANDBOX_NOTREADY))
	if !sandboxOK || s.RuntimeHandler != i.handler || s.Id != c.PodSandboxId ||
		s.Metadata.GetNamespace() == "" || s.Metadata.GetName() == "" || s.Metadata.GetUid() == "" {
		return gvisor.Identity{}, errUnresolved
	}
	return gvisor.Identity{ContainerID: c.Id, SandboxID: s.Id, RuntimeHandler: s.RuntimeHandler,
		ContainerName: c.Metadata.Name, Namespace: s.Metadata.Namespace, PodName: s.Metadata.Name, PodUID: s.Metadata.Uid}, nil
}
